#!/usr/bin/env python3
"""traffic_meter v2: non-disruptive per-port nftables byte counters.

Port sources:
  --source nft   ports from `ip nft_forward` prerouting dnat rules (relay servers)
  --source xui   ports from 3x-ui SQLite db enabled inbounds (exit nodes)
  --source none  host totals only
Manual adjustment: --include p1,p2  --exclude p3,p4
Monitored set = (auto-discovered UNION include) MINUS exclude.

Creates a SEPARATE nft table `ip traffic_meter` (accept-policy chains, never
touches other tables, no service restarts):
  meter_pre  (prerouting,  -150): bytes addressed to port  -> in_<p>
  meter_post (postrouting,  200): bytes leaving with sport -> out_<p>

Per-source-IP tracking (v3): per-PORT dynamic sets with per-element counters —
si_<p> (inbound saddr) and so_<p> (outbound daddr) — so each source IP's bytes
are attributed to the specific port it used. The set update is folded into the
same rule as the port byte counter. Elements expire after 26h idle so the sets
stay bounded. `report` emits ips as {port: {ip: {in,out}}}. If the local nft is
too old for stateful set counters the sets simply don't exist and "ips" is
omitted — everything else keeps working.

Usage: meter.py [ensure|report] [--source S] [--include CSV] [--exclude CSV]
"""
import json, os, re, subprocess, sys, time

TABLE = "traffic_meter"
XUI_DB = "/etc/x-ui/x-ui.db"


def sh(cmd, check=True):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"cmd failed: {cmd}\n{p.stderr}")
    return p


def nft_json(cmd, check=True):
    p = sh(f"nft -j {cmd}", check=check)
    if p.returncode != 0:
        return None
    return json.loads(p.stdout)


def ports_from_nft_forward():
    ports, names = set(), {}
    j = nft_json("list chain ip nft_forward prerouting", check=False)
    if not j:
        return ports, names
    for item in j.get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        exprs = rule.get("expr", [])
        if not any("dnat" in e for e in exprs):
            continue
        for e in exprs:
            m = e.get("match")
            if not m:
                continue
            if m.get("left", {}).get("payload", {}).get("field") == "dport" and isinstance(m.get("right"), int):
                ports.add(m["right"])
    return ports, names


def ports_from_xui():
    ports, names = set(), {}
    import os, sqlite3
    if not os.path.exists(XUI_DB):
        return ports, names
    try:
        c = sqlite3.connect(f"file:{XUI_DB}?mode=ro", uri=True, timeout=5)
        for port, remark, enable in c.execute("SELECT port, remark, enable FROM inbounds"):
            if enable:
                ports.add(int(port))
                if remark:
                    names[int(port)] = str(remark)
        c.close()
    except Exception as e:
        print(f"xui read failed: {e}", file=sys.stderr)
    return ports, names


def discover(source, include, exclude):
    if source == "xui":
        auto, names = ports_from_xui()
    elif source == "nft":
        auto, names = ports_from_nft_forward()
    else:
        auto, names = set(), {}
    ports = (auto | set(include)) - set(exclude)
    return sorted(ports), names


def table_exists():
    return sh(f"nft list table ip {TABLE}", check=False).returncode == 0


def existing_counters():
    if not table_exists():
        return set()
    j = nft_json(f"list counters table ip {TABLE}")
    return {i["counter"]["name"] for i in j.get("nftables", []) if "counter" in i}


def chain_ports(chain):
    ports = set()
    p = sh(f"nft -j list chain ip {TABLE} {chain}", check=False)
    if p.returncode != 0:
        return ports
    for item in json.loads(p.stdout).get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        for e in rule.get("expr", []):
            m = e.get("match")
            if m and isinstance(m.get("right"), int):
                ports.add(m["right"])
    return ports


def chain_mentions(chain, needle):
    p = sh(f"nft list chain ip {TABLE} {chain}", check=False)
    return p.returncode == 0 and needle in (p.stdout or "")


def list_sets():
    out = set()
    j = nft_json(f"list sets table ip {TABLE}", check=False)
    if not j:
        return out
    for item in j.get("nftables", []):
        s = item.get("set")
        if s and s.get("name"):
            out.add(s["name"])
    return out


def ensure(source, include, exclude):
    ports, names = discover(source, include, exclude)
    want = set(ports)
    if not table_exists():
        sh(f"nft add table ip {TABLE}")
    sh(f"nft add chain ip {TABLE} meter_pre '{{ type filter hook prerouting priority -150 ; policy accept ; }}'", check=False)
    sh(f"nft add chain ip {TABLE} meter_post '{{ type filter hook postrouting priority 200 ; policy accept ; }}'", check=False)
    # Per-PORT source-IP dynamic sets: si_<p> (inbound saddr), so_<p> (outbound
    # daddr). One pair per monitored port so traffic can be attributed to a
    # specific port. Needs nft with stateful set counters; if unsupported the
    # adds fail silently (check=False) and per-IP reporting is simply omitted.
    have_sets = list_sets()
    for legacy in ("src_in", "src_out"):        # drop older meter's global sets
        if legacy in have_sets:
            sh(f"nft delete set ip {TABLE} {legacy}", check=False)
    for p in ports:
        for pre in ("si", "so"):
            if f"{pre}_{p}" not in have_sets:
                sh(f"nft add set ip {TABLE} {pre}_{p} '{{ type ipv4_addr ; flags dynamic,timeout ; timeout 26h ; size 65535 ; counter ; }}'", check=False)
    for sname in have_sets:                      # drop sets for unmonitored ports
        m = re.match(r"(?:si|so)_(\d+)$", sname)
        if m and int(m.group(1)) not in want:
            sh(f"nft delete set ip {TABLE} {sname}", check=False)
    # Did the per-port sets actually get created? Old nft (<0.9.4-ish) can't do
    # dynamic sets with counters, so the adds above no-op. Without this check the
    # rules below would reference non-existent @si_ sets and the whole batch would
    # fail, taking port/host metering down too. When unsupported we fall back to
    # plain port counters and just omit per-source-IP data.
    sets_now = list_sets()
    ipsets_ok = bool(ports) and all(f"si_{p}" in sets_now and f"so_{p}" in sets_now for p in ports)
    have = existing_counters()
    batch = [f"add counter ip {TABLE} {d}_{p}" for p in ports for d in ("in", "out")
             if f"{d}_{p}" not in have]
    if batch:
        sh("nft -f - <<'EOF'\n" + "\n".join(batch) + "\nEOF")
    # rebuild rules if the monitored set changed OR (where supported) the per-port
    # set-update rules aren't present yet (e.g. upgrade from a portless meter)
    need = (chain_ports("meter_pre") != want or chain_ports("meter_post") != want
            or (ipsets_ok and ports and not chain_mentions("meter_pre", "@si_")))
    if need:
        lines = [f"flush chain ip {TABLE} meter_pre", f"flush chain ip {TABLE} meter_post"]
        for p in ports:
            for proto in ("tcp", "udp"):
                if ipsets_ok:
                    lines.append(f'add rule ip {TABLE} meter_pre {proto} dport {p} counter name "in_{p}" update @si_{p} {{ ip saddr }}')
                    lines.append(f'add rule ip {TABLE} meter_post {proto} sport {p} counter name "out_{p}" update @so_{p} {{ ip daddr }}')
                else:
                    lines.append(f'add rule ip {TABLE} meter_pre {proto} dport {p} counter name "in_{p}"')
                    lines.append(f'add rule ip {TABLE} meter_post {proto} sport {p} counter name "out_{p}"')
        sh("nft -f - <<'EOF'\n" + "\n".join(lines) + "\nEOF")
        # drop counters for ports we no longer monitor (now unreferenced)
        for name in existing_counters():
            try:
                cp = int(name.split("_", 1)[1])
            except (IndexError, ValueError):
                continue
            if cp not in want:
                sh(f"nft delete counter ip {TABLE} {name}", check=False)
    return ports, names


def default_iface():
    with open("/proc/net/route") as f:
        for line in f.readlines()[1:]:
            parts = line.split()
            if parts[1] == "00000000":
                return parts[0]
    return "eth0"


def host_bytes(iface):
    with open("/proc/net/dev") as f:
        for line in f:
            if ":" not in line:
                continue
            name, rest = line.split(":", 1)
            if name.strip() == iface:
                v = rest.split()
                return int(v[0]), int(v[8])
    return 0, 0


def set_elems(name):
    """{ip: cumulative_bytes} from a dynamic set with per-element counters."""
    out = {}
    j = nft_json(f"list set ip {TABLE} {name}", check=False)
    if not j:
        return out
    for item in j.get("nftables", []):
        s = item.get("set")
        if not s:
            continue
        for el in s.get("elem") or []:
            if not isinstance(el, dict):
                continue
            e = el.get("elem")
            if not isinstance(e, dict):
                continue
            ip = e.get("val")
            cnt = e.get("counter") or {}
            if isinstance(ip, str):
                out[ip] = int(cnt.get("bytes", 0))
    return out


MAX_IPS = 2000  # cap total (port,ip) pairs in the report payload

# --- ss fallback: per-source-IP accounting for nft too old for set counters ---
# Reads `ss` (read-only) each sample and turns per-socket TCP byte counters into
# monotonic per-(port,ip) totals kept in a small state file, so the dashboard's
# cumulative-delta model works. Long-lived proxy flows are captured accurately;
# flows that open AND close entirely between two samples are missed (approximate).
SS_STATE = "/var/lib/traffic-meter/ss_state.json"
IP4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _ss_load():
    try:
        with open(SS_STATE) as f:
            return json.load(f)
    except Exception:
        return None


def _ss_save(st):
    try:
        os.makedirs(os.path.dirname(SS_STATE), exist_ok=True)
        tmp = SS_STATE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f)
        os.replace(tmp, SS_STATE)
    except Exception as e:
        print(f"ss state save failed: {e}", file=sys.stderr)


def _parse_ss(text, portset):
    """{inode: (localport, peer_ip, bytes_received, bytes_sent)} for monitored ports."""
    out = {}
    lines = text.splitlines()
    i, n = 0, len(lines)
    while i < n:
        ln = lines[i]
        if not ln[:1].strip():           # indented info line without an addr line
            i += 1
            continue
        toks = ln.split()
        i += 1
        info = ""
        if i < n and not lines[i][:1].strip():   # the following tcp_info line
            info = lines[i]
            i += 1
        if len(toks) < 4:
            continue
        lp = toks[2].rpartition(":")[2]
        if not lp.isdigit() or int(lp) not in portset:
            continue
        ino = next((t[4:] for t in toks[4:] if t.startswith("ino:")), None)
        if not ino:
            continue
        ip = toks[3].rpartition(":")[0].strip("[]")
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        if not IP4_RE.match(ip):
            continue
        br = bs = 0
        for t in info.split():
            if t.startswith("bytes_received:"):
                br = int(t[15:] or 0)
            elif t.startswith("bytes_sent:"):
                bs = int(t[11:] or 0)
        out[ino] = (int(lp), ip, br, bs)
    return out


def ss_ip_bytes(ports):
    """Monotonic {port: {ip: {"in":upload,"out":download}}} via ss + state file."""
    portset = set(ports)
    p = sh("ss -tineH state established", check=False)
    cur = _parse_ss(p.stdout or "", portset) if p.returncode == 0 else {}
    st = _ss_load()
    now = int(time.time())
    if st is None:   # first ever run: seed baseline, don't count pre-existing bytes
        _ss_save({"socks": {k: list(v) for k, v in cur.items()}, "acc": {}})
        return {}
    prev, acc = st.get("socks", {}), st.get("acc", {})
    for ino, (port, ip, br, bs) in cur.items():
        key = f"{port}|{ip}"
        pv = prev.get(ino)
        if pv and pv[0] == port and pv[1] == ip:
            din = br - pv[2]; dout = bs - pv[3]
            if din < 0: din = br           # socket/inode reused
            if dout < 0: dout = bs
        else:
            din, dout = br, bs             # newly seen socket
        a = acc.get(key) or [0, 0, now]
        a[0] += din; a[1] += dout; a[2] = now
        acc[key] = a
    cut = now - 26 * 3600                   # drop idle keys (mirror the nft 26h timeout)
    acc = {k: v for k, v in acc.items() if v[2] >= cut}
    if len(acc) > MAX_IPS:
        acc = dict(sorted(acc.items(), key=lambda kv: kv[1][0] + kv[1][1], reverse=True)[:MAX_IPS])
    _ss_save({"socks": {k: list(v) for k, v in cur.items()}, "acc": acc})
    ips = {}
    for key, (cin, cout, _ts) in acc.items():
        port, ip = key.split("|", 1)
        ips.setdefault(port, {})[ip] = {"in": cin, "out": cout}
    return ips


def report(source, include, exclude):
    ports, names = ensure(source, include, exclude)
    pset = {str(p) for p in ports}
    j = nft_json(f"list counters table ip {TABLE}")
    out_ports = {}
    for item in j.get("nftables", []):
        c = item.get("counter")
        if not c:
            continue
        d, p = c["name"].split("_", 1)
        if p in pset:
            out_ports.setdefault(p, {})[d] = c.get("bytes", 0)
    # per-port source-IP maps: {port: {ip: {"in":x,"out":y}}}
    # Prefer kernel nft set counters; fall back to ss sampling on old nft.
    ips = {}
    total_pairs = 0
    have_sets = list_sets()
    if ports and any(f"si_{p}" in have_sets for p in ports):
        for p in ports:
            pd = {}
            for ip, b in set_elems(f"si_{p}").items():
                pd.setdefault(ip, {})["in"] = b
            for ip, b in set_elems(f"so_{p}").items():
                pd.setdefault(ip, {})["out"] = b
            if pd:
                ips[str(p)] = pd
                total_pairs += len(pd)
    else:
        ips = ss_ip_bytes(ports)
        total_pairs = sum(len(pd) for pd in ips.values())
    if total_pairs > MAX_IPS:                      # keep the heaviest pairs
        flat = [(pt, ip, v.get("in", 0) + v.get("out", 0))
                for pt, pd in ips.items() for ip, v in pd.items()]
        flat.sort(key=lambda x: x[2], reverse=True)
        keep = {(pt, ip) for pt, ip, _ in flat[:MAX_IPS]}
        ips = {pt: {ip: v for ip, v in pd.items() if (pt, ip) in keep}
               for pt, pd in ips.items()}
        ips = {pt: pd for pt, pd in ips.items() if pd}
    iface = default_iface()
    rx, tx = host_bytes(iface)
    print(json.dumps({"ts": int(time.time()), "ports": out_ports,
                      "names": {str(k): v for k, v in names.items()},
                      "ips": ips,
                      "host": {"rx": rx, "tx": tx, "iface": iface}}))


def parse_args(argv):
    mode, source, include, exclude = "report", "none", [], []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("ensure", "report"):
            mode = a
        elif a == "--source" and i + 1 < len(argv):
            i += 1; source = argv[i]
        elif a == "--include" and i + 1 < len(argv):
            i += 1; include = [int(x) for x in argv[i].split(",") if x.strip().isdigit()]
        elif a == "--exclude" and i + 1 < len(argv):
            i += 1; exclude = [int(x) for x in argv[i].split(",") if x.strip().isdigit()]
        i += 1
    return mode, source, include, exclude


if __name__ == "__main__":
    mode, source, include, exclude = parse_args(sys.argv[1:])
    if mode == "ensure":
        ports, names = ensure(source, include, exclude)
        print(json.dumps({"ports": ports, "names": {str(k): v for k, v in names.items()}}))
    else:
        report(source, include, exclude)
