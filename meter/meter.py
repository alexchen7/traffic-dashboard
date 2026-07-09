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

Usage: meter.py [ensure|report] [--source S] [--include CSV] [--exclude CSV]
"""
import json, subprocess, sys, time

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


def ensure(source, include, exclude):
    ports, names = discover(source, include, exclude)
    if not table_exists():
        sh(f"nft add table ip {TABLE}")
    sh(f"nft add chain ip {TABLE} meter_pre '{{ type filter hook prerouting priority -150 ; policy accept ; }}'", check=False)
    sh(f"nft add chain ip {TABLE} meter_post '{{ type filter hook postrouting priority 200 ; policy accept ; }}'", check=False)
    have = existing_counters()
    batch = [f"add counter ip {TABLE} {d}_{p}" for p in ports for d in ("in", "out")
             if f"{d}_{p}" not in have]
    if batch:
        sh("nft -f - <<'EOF'\n" + "\n".join(batch) + "\nEOF")
    want = set(ports)
    if chain_ports("meter_pre") != want or chain_ports("meter_post") != want:
        lines = [f"flush chain ip {TABLE} meter_pre", f"flush chain ip {TABLE} meter_post"]
        for p in ports:
            lines.append(f'add rule ip {TABLE} meter_pre tcp dport {p} counter name "in_{p}"')
            lines.append(f'add rule ip {TABLE} meter_pre udp dport {p} counter name "in_{p}"')
            lines.append(f'add rule ip {TABLE} meter_post tcp sport {p} counter name "out_{p}"')
            lines.append(f'add rule ip {TABLE} meter_post udp sport {p} counter name "out_{p}"')
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
    iface = default_iface()
    rx, tx = host_bytes(iface)
    print(json.dumps({"ts": int(time.time()), "ports": out_ports,
                      "names": {str(k): v for k, v in names.items()},
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
