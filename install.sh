#!/usr/bin/env bash
# =============================================================================
# Traffic Dashboard — one-key installer
#
#   Dashboard host (usually an exit node):
#     curl -fsSL https://raw.githubusercontent.com/alexchen7/traffic-dashboard/main/install.sh | bash -s -- dashboard
#
#   Metered node (relay or exit) — only needed if you can't use add-server:
#     curl -fsSL https://raw.githubusercontent.com/alexchen7/traffic-dashboard/main/install.sh | bash -s -- node
#
#   Register a node from the dashboard host (pushes meter over SSH — the node
#   itself never needs to reach GitHub, useful when a node can't reach GitHub directly):
#     bash /opt/traffic-dash/install.sh add-server
#
#   Remove everything:
#     bash install.sh uninstall
#
# Supported: Debian/Ubuntu with systemd, python3 and nftables. No pip deps.
# =============================================================================
set -euo pipefail

REPO_BASE="${TD_REPO_BASE:-https://raw.githubusercontent.com/alexchen7/traffic-dashboard/main}"
METER_DIR=/opt/traffic-meter
DASH_DIR=/opt/traffic-dash

C_G='\033[0;32m'; C_Y='\033[1;33m'; C_R='\033[0;31m'; C_B='\033[1;34m'; C_N='\033[0m'
say()  { echo -e "${C_B}[traffic-dash]${C_N} $*"; }
ok()   { echo -e "${C_G}[ok]${C_N} $*"; }
warn() { echo -e "${C_Y}[warn]${C_N} $*"; }
die()  { echo -e "${C_R}[error]${C_N} $*" >&2; exit 1; }

need_root() { [ "$(id -u)" = 0 ] || die "run as root"; }

ask() { # ask "prompt" "default" -> REPLY  (works under `curl | bash`)
  local prompt="$1" def="${2:-}"
  if [ -e /dev/tty ]; then
    read -rp "$(echo -e "${C_B}?${C_N} ${prompt}${def:+ [$def]}: ")" REPLY < /dev/tty || true
  else
    REPLY=""
  fi
  REPLY="${REPLY:-$def}"
}

fetch() { # fetch <relpath> <dest>
  say "fetching $1"
  curl -fsSL "${REPO_BASE}/$1" -o "$2" || return 1
}

check_deps() {
  local apt_updated=0
  command -v apt-get >/dev/null || warn "apt-get not found — this installer targets Debian/Ubuntu; assuming deps are present"
  command -v python3 >/dev/null || {
    warn "python3 not found — installing"
    apt-get update -qq && apt_updated=1 && apt-get install -y -qq python3 || die "install python3 manually"
  }
  command -v nft >/dev/null || {
    warn "nftables not found — installing"
    { [ "$apt_updated" = 1 ] || apt-get update -qq; } && apt-get install -y -qq nftables || die "install nftables manually"
  }
  command -v curl >/dev/null || apt-get install -y -qq curl || true
}

detect_source() {
  if nft list table ip nft_forward >/dev/null 2>&1; then echo nft
  elif [ -f /etc/x-ui/x-ui.db ]; then echo xui
  else echo none; fi
}

# --------------------------------------------------------------------------
# node: install the per-server meter (nft counters + boot service)
# --------------------------------------------------------------------------
install_meter_local() { # $1 = source
  local src="$1"
  mkdir -p "$METER_DIR"
  if [ -f "$(dirname "$0")/meter/meter.py" ]; then
    cp "$(dirname "$0")/meter/meter.py" "$METER_DIR/meter.py"
  else
    fetch "meter/meter.py" "$METER_DIR/meter.py"
  fi
  cat > /etc/systemd/system/traffic-meter.service <<EOF
[Unit]
Description=Recreate traffic_meter nft counters at boot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 ${METER_DIR}/meter.py ensure --source ${src}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now traffic-meter.service >/dev/null 2>&1 || true
  python3 "$METER_DIR/meter.py" report --source "$src" >/dev/null || die "meter self-test failed"
  ok "meter installed (port source: ${src})"
}

cmd_node() {
  need_root; check_deps
  local src="${SOURCE:-auto}"
  [ "$src" = auto ] && src="$(detect_source)"
  say "installing meter with port source: $src"
  install_meter_local "$src"
  echo
  ok "node ready. Next, on your DASHBOARD host run:"
  echo "    bash ${DASH_DIR}/install.sh add-server"
  echo "and point it at this machine ($(hostname), $(hostname -I 2>/dev/null | awk '{print $1}'))."
}

# --------------------------------------------------------------------------
# dashboard: meter + collector/web app + nginx TLS (optional)
# --------------------------------------------------------------------------
cmd_dashboard() {
  need_root; check_deps
  local src; src="$(detect_source)"
  say "installing local meter (source: $src)"
  install_meter_local "$src"

  say "installing dashboard to $DASH_DIR"
  mkdir -p "$DASH_DIR/static"
  fetch "dashboard/app.py"            "$DASH_DIR/app.py"
  fetch "dashboard/static/index.html" "$DASH_DIR/static/index.html"
  fetch "dashboard/static/login.html" "$DASH_DIR/static/login.html"
  fetch "dashboard/static/chart.umd.js" "$DASH_DIR/static/chart.umd.js"
  fetch "install.sh"                  "$DASH_DIR/install.sh" || cp "$0" "$DASH_DIR/install.sh" 2>/dev/null || true
  chmod +x "$DASH_DIR/install.sh" 2>/dev/null || true

  # ssh key for the collector
  if [ ! -f /root/.ssh/id_ed25519 ]; then
    ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519 -q
    ok "generated SSH key for the collector"
  fi

  # config
  local http_port="${HTTP_PORT:-15080}"
  if [ ! -f "$DASH_DIR/config.json" ]; then
    local pw hash secret kind
    pw="$(python3 -c 'import secrets,string;print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(16)))')"
    hash="$(printf %s "$pw" | python3 -c 'import hashlib,sys;print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
    secret="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
    kind=exit; [ "$src" = nft ] && kind=relay
    python3 - "$hash" "$secret" "$http_port" "$src" "$kind" <<'PYEOF'
import json, socket, sys
hash_, secret, port, src, kind = sys.argv[1:6]
cfg = {
  "password_hash": hash_, "secret": secret,
  "listen_host": "127.0.0.1", "listen_port": int(port),
  "servers": [{"id": "local", "name": f"{socket.gethostname()} (dashboard)",
               "kind": kind, "conn": {"mode": "local"}, "source": src}],
}
json.dump(cfg, open("/opt/traffic-dash/config.json", "w"), indent=1)
PYEOF
    chmod 600 "$DASH_DIR/config.json"
    DASH_PW="$pw"
    ok "config created"
  else
    warn "existing config.json kept"
    DASH_PW="(unchanged)"
  fi

  # systemd
  cat > /etc/systemd/system/traffic-dash.service <<EOF
[Unit]
Description=Traffic dashboard (collector + web)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${DASH_DIR}
ExecStart=/usr/bin/python3 ${DASH_DIR}/app.py
Restart=always
RestartSec=5
MemoryMax=120M

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now traffic-dash.service
  sleep 3
  systemctl is-active --quiet traffic-dash || die "traffic-dash failed to start (journalctl -u traffic-dash)"
  ok "dashboard service running on 127.0.0.1:${http_port}"

  # nginx TLS front (optional)
  local tls_port="${TLS_PORT:-15443}" url
  if [ "${NO_NGINX:-0}" = 1 ]; then
    python3 - "$DASH_DIR/config.json" <<'PYEOF'
import json, sys
p = sys.argv[1]
c = json.load(open(p))
c["listen_host"] = "0.0.0.0"
c["secure_cookies"] = False  # plain HTTP: Secure cookies would break login
json.dump(c, open(p, "w"), indent=1)
PYEOF
    systemctl restart traffic-dash
    warn "nginx skipped — dashboard is on PLAIN HTTP port ${http_port} (all interfaces)."
    url="http://<this-server>:${http_port}"
  else
    command -v nginx >/dev/null || { say "installing nginx"; apt-get install -y -qq nginx; }
    local cert="${CERT_FILE:-}" key="${KEY_FILE:-}" domain="${DOMAIN:-_}"
    if [ -z "$cert" ]; then
      ask "Path to TLS fullchain.pem (empty = generate self-signed)" ""
      cert="$REPLY"
    fi
    if [ -n "$cert" ]; then
      [ -z "$key" ] && { ask "Path to TLS privkey.pem" "$(dirname "$cert")/privkey.pem"; key="$REPLY"; }
      [ -f "$cert" ] && [ -f "$key" ] || die "cert/key not found"
    else
      mkdir -p /etc/traffic-dash
      openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=traffic-dash" \
        -keyout /etc/traffic-dash/selfsigned.key -out /etc/traffic-dash/selfsigned.crt 2>/dev/null
      cert=/etc/traffic-dash/selfsigned.crt; key=/etc/traffic-dash/selfsigned.key
      warn "self-signed certificate generated (browser will warn)"
    fi
    cat > /etc/nginx/conf.d/traffic-dash.conf <<EOF
server {
    listen ${tls_port} ssl;
    server_name ${domain};
    ssl_certificate     ${cert};
    ssl_certificate_key ${key};
    ssl_protocols TLSv1.2 TLSv1.3;
    location / {
        proxy_pass http://127.0.0.1:${http_port};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 60s;
    }
}
EOF
    nginx -t >/dev/null || die "nginx config test failed"
    systemctl enable --now nginx >/dev/null 2>&1 || true
    systemctl reload nginx
    ok "nginx TLS on port ${tls_port}"
    url="https://<this-server>:${tls_port}"
  fi

  echo
  echo -e "${C_G}=============================================================${C_N}"
  echo -e "  Dashboard:  ${url}"
  echo -e "  Password:   ${C_Y}${DASH_PW}${C_N}   (change it in Settings)"
  echo -e "  Add nodes:  bash ${DASH_DIR}/install.sh add-server"
  echo -e "${C_G}=============================================================${C_N}"
}

# --------------------------------------------------------------------------
# add-server: register a node in config.json and push meter over SSH
# --------------------------------------------------------------------------
cmd_add_server() {
  need_root
  [ -f "$DASH_DIR/config.json" ] || die "no dashboard here — run 'install.sh dashboard' first"
  [ -e /dev/tty ] || die "add-server is interactive; run it from a terminal"

  ask "Server id (short, e.g. relay2)" ""; local id="$REPLY"
  [[ "$id" =~ ^[a-z0-9_]+$ ]] || die "id must be lowercase letters/digits/underscore"
  ask "Display name" "$id"; local name="$REPLY"
  ask "Kind (relay/exit/client)" "client"; local kind="$REPLY"
  ask "SSH host (address THIS machine can reach — private IP for relays, optimized-route IP for hard-to-reach clients)" ""; local host="$REPLY"
  [ -n "$host" ] || die "host required"
  ask "SSH port" "22"; local port="$REPLY"
  ask "Public IP for country flag (the node's REAL public IP, not an optimized-route address)" "$host"; local pubip="$REPLY"
  ask "Port source on that server (nft/xui/none/auto)" "auto"; local src="$REPLY"

  local SSH=(ssh -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -p "$port" "root@${host}")

  say "checking SSH key auth to root@${host}:${port}"
  if ! "${SSH[@]}" -o BatchMode=yes true 2>/dev/null; then
    warn "key auth not working yet — you'll be asked for the node's root password (twice)"
    # ensure pubkey auth enabled remotely + install key
    ssh-copy-id -p "$port" "root@${host}" < /dev/tty || die "ssh-copy-id failed"
    if ! "${SSH[@]}" -o BatchMode=yes true 2>/dev/null; then
      warn "key still refused; enabling PubkeyAuthentication (and relaxing AuthenticationMethods if it forces password-only)"
      "${SSH[@]}" "sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config; sed -ri 's/^[[:space:]]*AuthenticationMethods[[:space:]]+.*/AuthenticationMethods publickey password/' /etc/ssh/sshd_config; sshd -t && (systemctl reload sshd 2>/dev/null || systemctl reload ssh)" < /dev/tty
      "${SSH[@]}" -o BatchMode=yes true 2>/dev/null || die "key auth still failing"
    fi
  fi
  ok "key auth working"

  if [ "$src" = auto ]; then
    src="$("${SSH[@]}" "if nft list table ip nft_forward >/dev/null 2>&1; then echo nft; elif [ -f /etc/x-ui/x-ui.db ]; then echo xui; else echo none; fi")"
    say "detected port source: $src"
  fi

  say "pushing meter to the node (no GitHub access needed on the node)"
  "${SSH[@]}" "mkdir -p $METER_DIR"
  scp -P "$port" -q "$METER_DIR/meter.py" "root@${host}:$METER_DIR/meter.py"
  "${SSH[@]}" "cat > /etc/systemd/system/traffic-meter.service <<EOF
[Unit]
Description=Recreate traffic_meter nft counters at boot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 ${METER_DIR}/meter.py ensure --source ${src}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now traffic-meter.service >/dev/null 2>&1 || true"
  "${SSH[@]}" "python3 $METER_DIR/meter.py report --source $src" >/dev/null || die "remote meter self-test failed"
  ok "meter running on ${host}"

  python3 - "$id" "$name" "$kind" "$host" "$port" "$src" "$pubip" <<'PYEOF'
import json, sys
id_, name, kind, host, port, src, pubip = sys.argv[1:8]
p = "/opt/traffic-dash/config.json"
cfg = json.load(open(p))
cfg["servers"] = [s for s in cfg["servers"] if s["id"] != id_]
entry = {"id": id_, "name": name, "kind": kind,
         "conn": {"mode": "ssh", "host": host, "port": int(port)},
         "source": src}
if pubip:
    entry["public_ip"] = pubip
cfg["servers"].append(entry)
json.dump(cfg, open(p, "w"), indent=1)
print("config updated:", [s["id"] for s in cfg["servers"]])
PYEOF
  systemctl restart traffic-dash
  ok "'${name}' added — it will appear on the dashboard within ~30 seconds"
}

# --------------------------------------------------------------------------
cmd_uninstall() {
  need_root
  systemctl disable --now traffic-dash 2>/dev/null || true
  systemctl disable --now traffic-meter 2>/dev/null || true
  rm -f /etc/systemd/system/traffic-dash.service /etc/systemd/system/traffic-meter.service
  rm -f /etc/nginx/conf.d/traffic-dash.conf 2>/dev/null && { nginx -t >/dev/null 2>&1 && systemctl reload nginx || true; }
  systemctl daemon-reload
  nft delete table ip traffic_meter 2>/dev/null || true
  ask "Delete data and config in ${DASH_DIR} and ${METER_DIR}? (yes/no)" "no"
  if [ "$REPLY" = yes ]; then rm -rf "$DASH_DIR" "$METER_DIR"; ok "removed data"; else warn "kept $DASH_DIR and $METER_DIR"; fi
  ok "uninstalled"
}

# --------------------------------------------------------------------------
usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

CMD="${1:-}"; shift || true
SOURCE=auto; HTTP_PORT=15080; TLS_PORT=15443; NO_NGINX=0; DOMAIN=""; CERT_FILE=""; KEY_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --source)    SOURCE="$2"; shift 2;;
    --base)      REPO_BASE="$2"; shift 2;;
    --http-port) HTTP_PORT="$2"; shift 2;;
    --tls-port)  TLS_PORT="$2"; shift 2;;
    --no-nginx)  NO_NGINX=1; shift;;
    --domain)    DOMAIN="$2"; shift 2;;
    --cert)      CERT_FILE="$2"; shift 2;;
    --key)       KEY_FILE="$2"; shift 2;;
    *) die "unknown option: $1";;
  esac
done

case "$CMD" in
  node)       cmd_node;;
  dashboard)  cmd_dashboard;;
  add-server) cmd_add_server;;
  uninstall)  cmd_uninstall;;
  *)          usage;;
esac
