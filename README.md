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

## Migration / backup

Export bundles everything portable into one JSON file: registered node configs
(id, name, kind, SSH conn, port source, public IP), per-server settings (quotas,
reset days, time zones, port names, include/exclude lists, card order), the geo
cache, and the full traffic history (all rollup tiers + raw counter state).
Secrets are deliberately excluded — the dashboard password, cookie secret, and
the collector's SSH key stay with each installation.

**Web UI**: Settings → Backup & migration → Export data / Import data
(web import is capped at 128 MB; use the CLI for bigger files).

**CLI** (on the dashboard host):

```bash
bash /opt/traffic-dash/install.sh export            # -> /root/traffic-dash-export-<ts>.json
bash /opt/traffic-dash/install.sh import file.json  # stops the service, imports, restarts
```

Import **merges**: servers, settings, and traffic buckets present in the file
overwrite matching ones on the target; everything else is kept. Typical
migration: install a fresh dashboard on the new host, import the file, then
either copy `/root/.ssh/id_ed25519` from the old host or run
`ssh-copy-id root@<node>` per node so the collector can reach them. After a web
import, restart the service (`systemctl restart traffic-dash`) if new nodes
don't start reporting on their own.

## Traffic sources & node health

Two analytics panels on the dashboard:

- **Traffic sources** — per-source-IP byte counts with country roll-up. The
  meter keeps two nftables dynamic sets (`src_in`/`src_out`) with per-element
  counters over the monitored-port set; the collector deltas them into daily
  per-IP buckets. The dashboard geolocates the top IPs via ip-api's batch
  endpoint (cached in the DB) and shows country cards with share bars plus a
  top-50 source-IP table. Toggle a single server or all servers, over 24h/7d/30d/90d.
  Selecting a port chip in the Bandwidth panel filters the sources view to that
  port (the meter keeps per-port source-IP sets, `si_<port>`/`so_<port>`, so
  traffic is attributed to the exact port it used). Relays see real end-user
  IPs; exit/client nodes mostly see the relay's IP.
- **Node health** — every 10 s sample records an up/down tick per node into a
  per-minute `health` table. The panel shows uptime %, a 96-segment status
  strip (green/amber/red/grey-for-no-data) and the last recorded downtime,
  over 24h/7d/30d/90d.

Enabling per-source-IP tracking on existing nodes (one-time, after upgrading):

```bash
bash /opt/traffic-dash/install.sh update-nodes
```

This pushes the new `meter.py` to every SSH-registered node and re-runs
`ensure` so the nft sets are created. Uptime tracking and the dashboard-host's
own IP data need no node changes. Retention for both datasets is configurable
in Settings → Data retention (defaults: per-source-IP 60 d, uptime 120 d).

Requires an nftables new enough for stateful set counters (Debian 11+/Ubuntu
20.04+ are fine). On older nft the meter simply omits per-IP data and
everything else keeps working.

## Long-term archive (optional)

If the dashboard VPS is short on disk, ship old rollups to a bigger server and
keep only recent data locally. The archive is a ~180-line stdlib service
(`archive/archive.py`) that owns its own SQLite file — SQLite is never exposed
over the network directly.

Setup:

```bash
# on the storage server (prints a token):
curl -fsSL https://raw.githubusercontent.com/alexchen7/traffic-dashboard/main/install.sh | bash -s -- archive
# then on the dashboard host (asks for URL + token):
bash /opt/traffic-dash/install.sh link-archive
```

How it works: every 10 minutes the dashboard pushes finalized rows (default:
the `m1` tier) to the archive with idempotent upserts, resuming from the
archive's own per-entity watermarks. **Pruning never deletes a row the archive
hasn't confirmed** — if the archive is down, local data is held until shipping
catches up (watch local disk if the outage is long). When a chart request
reaches past local retention, the dashboard fetches the missing range from the
archive and merges it into the response; if the archive is unreachable the
chart just shows local data. With this in place you can safely drop local m1
retention to a few days while keeping a year+ of minute-level history.

Security: the bearer token (in each side's `config.json`, mode 600) is the only
auth — run the archive on a private network / VPN or firewall its port to the
dashboard host. The token is deliberately excluded from data exports.

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

Rollups: 10 s kept 6 h (fixed) → 1 min → 1 h → daily. Retention for the 1-min,
1-hour and daily tiers is adjustable in Settings → Data retention (defaults
8 d / 120 d / forever; 0 = forever, max 3650 d). Lowering a value permanently
deletes older rows within ~5 minutes. Rough cost per port/host per year:
1-min ≈ 43 MB, 1-hour ≈ 0.7 MB, daily ≈ 0.03 MB.

## Repo layout

```
install.sh                  # one-key installer (dashboard | node | add-server | export | import | archive | link-archive | update-nodes | uninstall)
meter/meter.py              # per-server nft counter agent
dashboard/app.py            # collector + web app (stdlib Python)
dashboard/static/           # UI (6 themes) + Chart.js
archive/archive.py          # optional long-term storage service (stdlib Python)
```

## Security notes

- Change the generated password after first login (Settings → Dashboard password).
- The dashboard binds to 127.0.0.1 and is exposed only through nginx TLS
  (except with `--no-nginx`, which serves plain HTTP — use only on trusted networks).
- Login is rate-limited (8 attempts / 5 min / IP