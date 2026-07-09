# Traffic Dashboard

Self-hosted traffic monitoring for relay / exit-node setups. Per-port byte counters
via a dedicated nftables table (never touches your forwarding rules, no service
restarts), a 10-second collector over SSH, SQLite rollups, and a themeable web
dashboard with per-server quotas, reset days, and time zones.

- **Relay servers**: ports auto-discovered from `nft_forward` DNAT rules (nft.sh compatible)
- **Exit nodes / client nodes**: ports auto-discovered from 3x-ui inbounds (`/etc/x-ui/x-ui.db`), remarks become port names
- **Country flags** per server, resolved from each node's real public IP (works even for nodes reached through an optimized route)
- **Nodes without a direct route** to the dashboard are supported via an SSH port-forward relay (`conn.host`/`conn.port` point at the forwarder; `public_ip` still holds the node's real IP for the flag)
- Three kinds: `relay`, `exit`, `client` — each with its own quota, reset day, and time zone
- No Python dependencies (stdlib only), no database server, ~30 MB RAM

## One-key install

> Replace `alexchen7` with your GitHub username after uploading this repo.

**1. Dashboard host** (usually your exit node — this also meters the host itself):

```bash
curl -fsSL https://raw.githubusercontent.com/alexchen7/traffic-dashboard/main/install.sh | bash -s -- dashboard
```

You'll be asked for a TLS cert path (leave empty to auto-generate a self-signed
one). At the end it prints the dashboard URL and a generated password.

Options: `--tls-port 15443` `--http-port 15080` `--cert /path/fullchain.pem --key /path/privkey.pem` `--domain your.domain` `--no-nginx` (plain HTTP, no TLS)

**2. Add each relay / exit node** — run on the dashboard host:

```bash
bash /opt/traffic-dash/install.sh add-server
```

Interactive: asks for id, name, kind, SSH host/port, and port source
(auto-detected). It installs its SSH key on the node, **pushes the meter over
SSH**, and registers the node — the node never needs to reach GitHub (works for
a node can't reach GitHub directly). Use the address the dashboard host can
actually reach (private IP for relays whose public IP is unstable).

**Alternative — install the meter directly on a node** (if it can reach GitHub):

```bash
curl -fsSL https://raw.githubusercontent.com/alexchen7/traffic-dashboard/main/install.sh | bash -s -- node
```

then run `add-server` on the dashboard host to register it.

**Uninstall** (either role): `bash install.sh uninstall`

## Requirements

Debian/Ubuntu with systemd, `python3`, `nftables` (installed automatically if
missing). Root required. The dashboard host must be able to SSH to each node as
root (key auth is set up by `add-server`; it also flips `PubkeyAuthentication yes`
if the node's sshd has it disabled).

## How counting works

A separate `ip traffic_meter` nft table with accept-policy chains:
`prerouting −150` counts bytes addressed to each monitored port (before DNAT),
`postrouting 200` counts bytes leaving with that source port (after SNAT).
For a forwarded port this equals the user-facing upload/download; the relay's
NIC total (also tracked, from `/proc/net/dev`) is ~2× the port sum by design.
Named counters survive rule rebuilds; a oneshot systemd unit recreates the
table after reboot. Counter resets are handled by the collector. Changing a
server's time zone only affects future daily buckets, so monthly totals near a
reset boundary may shift slightly.

Rollups: 10 s kept 6 h → 1 min kept 8 d → 1 h kept 120 d → daily kept forever.

## Repo layout

```
install.sh                  # one-key installer (dashboard | node | add-server | uninstall)
meter/meter.py              # per-server nft counter agent
dashboard/app.py            # collector + web app (stdlib Python)
dashboard/static/           # UI (6 themes) + Chart.js
```

## Security notes

- Change the generated password after first login (Settings → Dashboard password).
- The dashboard binds to 127.0.0.1 and is exposed only through nginx TLS
  (except with `--no-nginx`, which serves plain HTTP — use only on trusted networks).
- Login is rate-limited (8 attempts / 5 min / IP