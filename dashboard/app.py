#!/usr/bin/env python3
"""Traffic dashboard v2 — multi-server (relays + exit nodes). Stdlib only.

- Collector samples every 10s from all servers in config.json (parallel threads,
  SQLite writes serialized in the collector thread).
- Per-server settings: quota, reset day, timezone offset, port names,
  monitored-port include/exclude.
- Rollups: s10 (6h fixed); m1/h1/d1 retention adjustable in Settings
  (defaults: m1 8d, h1 120d, d1 forever; 0 = keep forever).
- Web app on 127.0.0.1:15080 behind nginx TLS (15443).
- Migration: GET /api/export + POST /api/import (Settings → Backup & migration),
  or `python3 app.py export [file]` / `python3 app.py import <file>` on the host.
- Traffic sources: per-source-IP daily buckets (from the meter's nft dynamic
  sets) with country aggregation (/api/sources), plus per-minute uptime
  history for every node (/api/health).
- Optional remote archive (config.json "archive" key, set up with
  `install.sh archive` + `install.sh link-archive`): finalized m1/h1/d1 rows
  are shipped to archive/archive.py on a storage server BEFORE local pruning
  may delete them; chart requests older than local retention fetch the
  missing range back from the archive and merge it in transparently.
"""
import calendar, concurrent.futures, hashlib, hmac, http.cookies, json, os, re, secrets
import socketserver, sqlite3, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "data.db")
CFG_PATH = os.path.join(BASE, "config.json")
STATIC = os.path.join(BASE, "static")
SAMPLE_SEC = 10

CFG_LOCK = threading.Lock()
CFG = json.load(open(CFG_PATH))
LISTEN = (CFG.get("listen_host", "127.0.0.1"), int(CFG.get("listen_port", 15080)))
SERVERS = {s["id"]: s for s in CFG["servers"]}

DEFAULT_SRV = {"reset_day": 1, "quota_gb": 0, "tz_offset": 8,
               "port_names": {}, "ports_include": [], "ports_exclude": []}

# days each tier is kept; 0 = forever (s10 is fixed at 6 hours).
# ips = per-source-IP daily buckets, health = per-minute uptime samples.
DEFAULT_RETENTION = {"m1": 8, "h1": 120, "d1": 0, "ips": 60, "health": 120}
RETENTION_MAX_DAYS = 3650
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

RATES = {}
RATES_LOCK = threading.Lock()
SETTINGS_LOCK = threading.Lock()
XUI_NAMES = {}      # sid -> {port_str: remark}
HEALTH = {}         # sid -> last ok ts
GEO = {}            # server ip -> {"cc": "US", "country": "United States"}
IPGEO = {}          # source ip -> {"cc", "country"} (traffic-sources view)


def db():
    c = sqlite3.connect(DB, timeout=15)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    return c


def init_db():
    c = db()
    for t in ("s10", "m1", "h1", "d1"):
        c.execute(f"CREATE TABLE IF NOT EXISTS {t} (entity TEXT, ts INTEGER, din INTEGER, dout INTEGER, PRIMARY KEY(entity, ts))")
    c.execute("CREATE TABLE IF NOT EXISTS raw_last (entity TEXT PRIMARY KEY, ts INTEGER, bin INTEGER, bout INTEGER)")
    c.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
    # ips gained a "port" column in v3; recreate the (portless v2) table if
    # present so per-port attribution works. The dropped data is at most a day
    # or two of aggregate per-IP counts, superseded by per-port collection.
    cols = [r[1] for r in c.execute("PRAGMA table_info(ips)")]
    if cols and "port" not in cols:
        c.execute("DROP TABLE ips")
    c.execute("CREATE TABLE IF NOT EXISTS ips (sid TEXT, ip TEXT, port INTEGER, day INTEGER, din INTEGER, dout INTEGER, PRIMARY KEY(sid, ip, port, day))")
    c.execute("CREATE TABLE IF NOT EXISTS health (sid TEXT, ts INTEGER, ok INTEGER, total INTEGER, PRIMARY KEY(sid, ts))")
    c.commit()
    # ---- migrate v1 entities -> v2 namespaced ----
    row = c.execute("SELECT v FROM meta WHERE k='schema_v'").fetchone()
    if not row or int(row[0]) < 2:
        for t in ("s10", "m1", "h1", "d1", "raw_last"):
            c.execute(f"UPDATE OR IGNORE {t} SET entity='relay1' WHERE entity='relay'")
            c.execute(f"UPDATE OR IGNORE {t} SET entity='exit1' WHERE entity='exit'")
            c.execute(f"UPDATE OR IGNORE {t} SET entity='relay1:'||entity WHERE entity LIKE 'port:%'")
        # migrate old global settings -> relay1
        row = c.execute("SELECT v FROM meta WHERE k='settings'").fetchone()
        if row:
            old = json.loads(row[0])
            if "servers" not in old:
                new = {"servers": {"relay1": {
                    "reset_day": old.get("reset_day", 1), "quota_gb": old.get("quota_gb", 500),
                    "tz_offset": old.get("tz_offset", 8), "port_names": old.get("port_names", {}),
                    "ports_include": [], "ports_exclude": []}}}
                c.execute("UPDATE meta SET v=? WHERE k='settings'", (json.dumps(new),))
        c.execute("INSERT INTO meta(k,v) VALUES('schema_v','2') ON CONFLICT(k) DO UPDATE SET v='2'")
    c.commit(); c.close()


def get_settings():
    c = db()
    row = c.execute("SELECT v FROM meta WHERE k='settings'").fetchone()
    c.close()
    s = json.loads(row[0]) if row else {"servers": {}}
    if "servers" not in s:
        s = {"servers": {}}
    for sid, srv in SERVERS.items():
        cur = dict(DEFAULT_SRV)
        if srv.get("kind") == "relay":
            cur["quota_gb"] = 500
        elif srv.get("kind") == "client":
            cur["quota_gb"] = 1024
        cur.update(s["servers"].get(sid, {}))
        s["servers"][sid] = cur
    seen = set()
    order = []
    for sid in (s.get("order") or []):
        if sid in SERVERS and sid not in seen:
            seen.add(sid)
            order.append(sid)
    for sid in SERVERS:
        if sid not in order:
            order.append(sid)
    s["order"] = order
    ret = dict(DEFAULT_RETENTION)
    for k, v in (s.get("retention") or {}).items():
        if k in ret:
            try:
                ret[k] = min(max(0, int(v)), RETENTION_MAX_DAYS)
            except (TypeError, ValueError):
                pass
    s["retention"] = ret
    return s


def save_settings(s):
    c = db()
    c.execute("INSERT INTO meta(k,v) VALUES('settings',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (json.dumps(s),))
    c.commit(); c.close()


# ---------------- collector ----------------

def upsert(c, table, entity, bucket_ts, din, dout):
    c.execute(f"""INSERT INTO {table}(entity,ts,din,dout) VALUES(?,?,?,?)
                  ON CONFLICT(entity,ts) DO UPDATE SET din=din+excluded.din, dout=dout+excluded.dout""",
              (entity, bucket_ts, din, dout))


def record(c, entity, ts, cum_in, cum_out, last, tzoff):
    prev = last.get(entity)
    last[entity] = (ts, cum_in, cum_out)
    if prev is None:
        return
    lts, lin, lout = prev
    dt = ts - lts
    if dt <= 0 or dt > 3600:
        return
    din = cum_in - lin
    dout = cum_out - lout
    if din < 0: din = cum_in
    if dout < 0: dout = cum_out
    upsert(c, "s10", entity, ts - ts % 10, din, dout)
    upsert(c, "m1", entity, ts - ts % 60, din, dout)
    upsert(c, "h1", entity, ts - ts % 3600, din, dout)
    day = ((ts + tzoff * 3600) // 86400) * 86400 - tzoff * 3600
    upsert(c, "d1", entity, day, din, dout)
    with RATES_LOCK:
        RATES[entity] = (round(din / dt), round(dout / dt), ts)


def record_ip(c, sid, ip, port, ts, cum_in, cum_out, last, tzoff):
    """Delta a per-source-IP-per-port cumulative counter into a daily bucket."""
    if not IP_RE.match(ip):
        return
    key = f"{sid}:ip:{port}:{ip}"
    prev = last.get(key)
    last[key] = (ts, cum_in, cum_out)
    if prev is None:
        return
    lts, lin, lout = prev
    dt = ts - lts
    if dt <= 0 or dt > 3600:
        return
    din = cum_in - lin
    dout = cum_out - lout
    if din < 0: din = cum_in       # set element expired & recreated
    if dout < 0: dout = cum_out
    if din == 0 and dout == 0:
        return
    day = ((ts + tzoff * 3600) // 86400) * 86400 - tzoff * 3600
    c.execute("""INSERT INTO ips(sid,ip,port,day,din,dout) VALUES(?,?,?,?,?,?)
                 ON CONFLICT(sid,ip,port,day) DO UPDATE SET din=din+excluded.din, dout=dout+excluded.dout""",
              (sid, ip, port, day, din, dout))


def record_health(c, sid, ts, ok):
    c.execute("""INSERT INTO health(sid,ts,ok,total) VALUES(?,?,?,1)
                 ON CONFLICT(sid,ts) DO UPDATE SET ok=ok+excluded.ok, total=total+1""",
              (sid, ts - ts % 60, 1 if ok else 0))


def meter_cmd(srv, st):
    inc = ",".join(str(p) for p in st.get("ports_include", []))
    exc = ",".join(str(p) for p in st.get("ports_exclude", []))
    cmd = f"python3 /opt/traffic-meter/meter.py report --source {srv.get('source','none')}"
    if inc: cmd += f" --include {inc}"
    if exc: cmd += f" --exclude {exc}"
    return cmd


def sample_server(srv, st):
    """Runs in worker thread; returns parsed report dict or None."""
    cmd = meter_cmd(srv, st)
    try:
        conn = srv.get("conn", {})
        if conn.get("mode") == "local":
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=9)
        else:
            ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6",
                   "-o", "StrictHostKeyChecking=accept-new",
                   "-p", str(conn.get("port", 22)), f"root@{conn['host']}", cmd]
            out = subprocess.run(ssh, capture_output=True, text=True, timeout=9)
        if out.returncode == 0 and out.stdout.strip():
            return json.loads(out.stdout)
    except Exception as e:
        print(f"sample {srv['id']} failed: {e}", file=sys.stderr)
    return None


def load_last(c):
    return {e: (ts, bi, bo) for e, ts, bi, bo in c.execute("SELECT entity,ts,bin,bout FROM raw_last")}


def save_last(c, last):
    for e, (ts, bi, bo) in last.items():
        c.execute("""INSERT INTO raw_last(entity,ts,bin,bout) VALUES(?,?,?,?)
                     ON CONFLICT(entity) DO UPDATE SET ts=excluded.ts,bin=excluded.bin,bout=excluded.bout""",
                  (e, ts, bi, bo))


def prune(c, now, retention=None):
    r = retention or DEFAULT_RETENTION
    shipped = load_shipped(c) if archive_enabled() else {}
    c.execute("DELETE FROM s10 WHERE ts < ?", (now - 6 * 3600,))
    for t in ("m1", "h1", "d1"):
        days = int(r.get(t, DEFAULT_RETENTION[t]) or 0)
        if days > 0:
            cut = now - days * 86400
            if archive_enabled() and t in arch_tables():
                # never delete rows the archive hasn't confirmed receiving
                cut = min(cut, int(shipped.get(t, 0)))
            c.execute(f"DELETE FROM {t} WHERE ts < ?", (cut,))
    days = int(r.get("ips", DEFAULT_RETENTION["ips"]) or 0)
    if days > 0:
        c.execute("DELETE FROM ips WHERE day < ?", (now - days * 86400,))
    days = int(r.get("health", DEFAULT_RETENTION["health"]) or 0)
    if days > 0:
        c.execute("DELETE FROM health WHERE ts < ?", (now - days * 86400,))
    # raw counter baselines for IPs that went quiet
    c.execute("DELETE FROM raw_last WHERE entity LIKE '%:ip:%' AND ts < ?", (now - 3 * 86400,))


def collector():
    c = db()
    last = load_last(c)
    n = 0
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(4, len(SERVERS) + 1))
    while True:
        t0 = time.time()
        try:
            settings = get_settings()
            futs = {}
            for sid, srv in SERVERS.items():
                futs[sid] = pool.submit(sample_server, srv, settings["servers"][sid])
            for sid, fut in futs.items():
                try:
                    r = fut.result(timeout=12)
                except Exception:
                    r = None
                record_health(c, sid, int(time.time()), bool(r))
                if not r:
                    continue
                tzoff = settings["servers"][sid].get("tz_offset", 8)
                ts = int(time.time())
                for port, v in r.get("ports", {}).items():
                    record(c, f"{sid}:port:{port}", ts, v.get("in", 0), v.get("out", 0), last, tzoff)
                for port_str, ipmap in (r.get("ips") or {}).items():
                    try:
                        port = int(port_str)
                    except (TypeError, ValueError):
                        continue
                    if not isinstance(ipmap, dict):
                        continue
                    for ip, v in ipmap.items():
                        try:
                            record_ip(c, sid, str(ip), port, ts, int(v.get("in", 0)), int(v.get("out", 0)), last, tzoff)
                        except (TypeError, ValueError, AttributeError):
                            pass
                h = r.get("host", {})
                record(c, sid, ts, h.get("rx", 0), h.get("tx", 0), last, tzoff)
                if r.get("names"):
                    XUI_NAMES[sid] = r["names"]
                HEALTH[sid] = ts
            save_last(c, last)
            n += 1
            if n % 30 == 0:
                prune(c, int(time.time()), settings.get("retention"))
            c.commit()
        except Exception as e:
            print("collector loop error:", repr(e), file=sys.stderr)
            try:
                c.rollback()
            except Exception:
                pass
        time.sleep(max(1, SAMPLE_SEC - (time.time() - t0)))


# ---------------- period / usage ----------------

def clamp_day(y, m, d):
    return min(d, calendar.monthrange(y, m)[1])


def period_bounds(reset_day, tzoff, now=None):
    now = now or time.time()
    lt = time.gmtime(now + tzoff * 3600)
    y, m, d = lt.tm_year, lt.tm_mon, lt.tm_mday
    if d >= reset_day:
        sy, sm = y, m
    else:
        sy, sm = (y - 1, 12) if m == 1 else (y, m - 1)
    start = calendar.timegm((sy, sm, clamp_day(sy, sm, reset_day), 0, 0, 0)) - tzoff * 3600
    ey, em = (sy + 1, 1) if sm == 12 else (sy, sm + 1)
    end = calendar.timegm((ey, em, clamp_day(ey, em, reset_day), 0, 0, 0)) - tzoff * 3600
    return int(start), int(end)


def usage_between(c, entity, start, end):
    row = c.execute("SELECT COALESCE(SUM(din),0), COALESCE(SUM(dout),0) FROM d1 WHERE entity=? AND ts>=? AND ts<?",
                    (entity, start, end)).fetchone()
    return row[0], row[1]


def geo_ip_for(srv):
    """The IP to geolocate: explicit public_ip, else conn host if it's public."""
    ip = srv.get("public_ip")
    if ip:
        return ip
    host = srv.get("conn", {}).get("host", "")
    # skip private / loopback ranges (relays use private IPs, local exit has none)
    if host and not re.match(r"^(10\.|127\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)", host):
        return host
    return None


def load_geo():
    c = db()
    row = c.execute("SELECT v FROM meta WHERE k='geo'").fetchone()
    c.close()
    if row:
        try:
            GEO.update(json.loads(row[0]))
        except Exception:
            pass


def save_geo():
    c = db()
    c.execute("INSERT INTO meta(k,v) VALUES('geo',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
              (json.dumps(GEO),))
    c.commit(); c.close()


def resolve_geos():
    """Fill GEO for any server IP we don't have yet (called from collector)."""
    import urllib.request
    changed = False
    for sid, srv in SERVERS.items():
        ip = geo_ip_for(srv)
        if not ip or ip in GEO:
            continue
        try:
            with urllib.request.urlopen(
                    f"http://ip-api.com/json/{ip}?fields=status,countryCode,country", timeout=6) as r:
                d = json.loads(r.read().decode())
            if d.get("status") == "success":
                GEO[ip] = {"cc": d.get("countryCode", ""), "country": d.get("country", "")}
                changed = True
        except Exception as e:
            print(f"geo lookup failed for {ip}: {e}", file=sys.stderr)
    if changed:
        save_geo()


def load_ipgeo():
    c = db()
    row = c.execute("SELECT v FROM meta WHERE k='ipgeo'").fetchone()
    c.close()
    if row:
        try:
            IPGEO.update(json.loads(row[0]))
        except Exception:
            pass


def save_ipgeo():
    c = db()
    c.execute("INSERT INTO meta(k,v) VALUES('ipgeo',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
              (json.dumps(IPGEO),))
    c.commit(); c.close()


def resolve_ip_geos():
    """Geolocate the top source IPs of the last 7 days that we don't know yet
    (ip-api batch endpoint, 100 per call, well under its rate limit)."""
    import urllib.request
    c = db()
    rows = c.execute("""SELECT ip, SUM(din+dout) t FROM ips WHERE day >= ?
                        GROUP BY ip ORDER BY t DESC LIMIT 400""",
                     (int(time.time()) - 7 * 86400,)).fetchall()
    c.close()
    todo = [ip for ip, _ in rows if ip not in IPGEO][:100]
    if not todo:
        return
    req = urllib.request.Request("http://ip-api.com/batch?fields=status,countryCode,country,query",
                                 data=json.dumps(todo).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        for d in json.loads(r.read().decode()):
            ip = d.get("query", "")
            if not ip:
                continue
            if d.get("status") == "success":
                IPGEO[ip] = {"cc": d.get("countryCode", ""), "country": d.get("country", "")}
            else:
                IPGEO[ip] = {"cc": "", "country": ""}   # private/unresolvable: cache the miss
    save_ipgeo()


def geo_loop():
    """Runs geo lookups OFF the collector thread so network stalls never
    freeze sampling."""
    while True:
        try:
            resolve_geos()
        except Exception as e:
            print("geo_loop error:", e, file=sys.stderr)
        try:
            resolve_ip_geos()
        except Exception as e:
            print("ipgeo error:", e, file=sys.stderr)
        time.sleep(1800)


def tz_label(off):
    sign = "+" if off >= 0 else "-"
    a = abs(off)
    hh = int(a)
    mm = int(round((a - hh) * 60))
    return f"UTC{sign}{hh:02d}:{mm:02d}"


# ---------------- remote archive (optional) ----------------
# config.json:  "archive": {"url": "http://10.0.0.9:15100", "token": "...",
#                           "ship": ["m1"], "interval_sec": 600}
# The token lives in config.json (never in the exportable settings blob).

ARCH = CFG.get("archive") or {}
ARCH_MARGIN = {"m1": 600, "h1": 2 * 3600, "d1": 2 * 86400}  # ship only finalized buckets
ARCH_BATCH = 5000


def archive_enabled():
    return bool(ARCH.get("url") and ARCH.get("token"))


def arch_tables():
    return [t for t in (ARCH.get("ship") or ["m1"]) if t in ("m1", "h1", "d1")]


def arch_req(path, payload=None, timeout=8):
    import urllib.request
    req = urllib.request.Request(
        ARCH["url"].rstrip("/") + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Authorization": "Bearer " + ARCH["token"], "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def load_shipped(c=None):
    """Per-table 'archive has everything up to this ts' watermarks."""
    own = c is None
    if own:
        c = db()
    row = c.execute("SELECT v FROM meta WHERE k='archive_shipped'").fetchone()
    if own:
        c.close()
    try:
        return json.loads(row[0]) if row else {}
    except Exception:
        return {}


def save_shipped(d):
    c = db()
    c.execute("INSERT INTO meta(k,v) VALUES('archive_shipped',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
              (json.dumps(d),))
    c.commit(); c.close()


def archive_ship_once():
    """Push finalized rows the archive doesn't have yet (resumes from the
    archive's own per-entity watermarks, idempotent upserts). Returns
    per-table shipped-up-to timestamps; raises on any failure so the caller
    keeps the old watermarks and prune keeps holding rows back."""
    now = int(time.time())
    shipped = {}
    c = db()
    try:
        for t in arch_tables():
            wm = arch_req(f"/watermarks?table={t}").get("watermarks") or {}
            cutoff = now - ARCH_MARGIN[t]
            for (e,) in c.execute(f"SELECT DISTINCT entity FROM {t}").fetchall():
                start = int(wm.get(e, -1)) + 1
                while True:
                    rows = c.execute(
                        f"SELECT entity,ts,din,dout FROM {t} WHERE entity=? AND ts>=? AND ts<? ORDER BY ts LIMIT ?",
                        (e, start, cutoff, ARCH_BATCH)).fetchall()
                    if not rows:
                        break
                    arch_req("/ingest", {"table": t, "rows": [list(r) for r in rows]}, timeout=30)
                    start = rows[-1][1] + 1
                    if len(rows) < ARCH_BATCH:
                        break
            shipped[t] = cutoff
    finally:
        c.close()
    return shipped


def archive_loop():
    time.sleep(20)
    while True:
        try:
            if archive_enabled():
                cur = load_shipped()
                cur.update(archive_ship_once())
                save_shipped(cur)
        except Exception as e:
            print("archive ship error:", e, file=sys.stderr)
        time.sleep(max(60, int(ARCH.get("interval_sec", 600))))


# ---------------- export / import (migration) ----------------

EXPORT_FORMAT = "traffic-dash-export"
EXPORT_VERSION = 2   # v2 adds "ips" (per-source-IP) and "health" (uptime) tables
DATA_TABLES = ("s10", "m1", "h1", "d1")


def export_payload():
    """Portable snapshot: node (client machine) configs, per-server settings,
    geo cache, full traffic history and raw counter state. Secrets
    (password_hash, secret) are deliberately NOT exported — auth stays with
    each installation. The collector SSH key isn't exported either; copy
    /root/.ssh/id_ed25519 or re-run ssh-copy-id per node on the new host."""
    c = db()
    data = {t: [list(r) for r in
                c.execute(f"SELECT entity,ts,din,dout FROM {t} ORDER BY entity,ts")]
            for t in DATA_TABLES}
    raw_last = [list(r) for r in c.execute("SELECT entity,ts,bin,bout FROM raw_last")]
    ips = [list(r) for r in c.execute("SELECT sid,ip,port,day,din,dout FROM ips ORDER BY sid,ip,port,day")]
    health = [list(r) for r in c.execute("SELECT sid,ts,ok,total FROM health ORDER BY sid,ts")]
    row = c.execute("SELECT v FROM meta WHERE k='settings'").fetchone()
    settings = json.loads(row[0]) if row else {"servers": {}}
    row = c.execute("SELECT v FROM meta WHERE k='geo'").fetchone()
    geo = json.loads(row[0]) if row else {}
    row = c.execute("SELECT v FROM meta WHERE k='ipgeo'").fetchone()
    ipgeo = json.loads(row[0]) if row else {}
    c.close()
    with CFG_LOCK:
        servers = json.loads(json.dumps(CFG["servers"]))  # deep copy
    return {"format": EXPORT_FORMAT, "version": EXPORT_VERSION,
            "exported_at": int(time.time()),
            "servers": servers, "settings": settings, "geo": geo, "ipgeo": ipgeo,
            "data": data, "raw_last": raw_last, "ips": ips, "health": health}


def _clean_server(s):
    """Validate an imported node config; returns a cleaned dict or None.
    Strict on id/kind/source/conn so a tampered export file can't smuggle
    shell metacharacters into the ssh/meter command line."""
    if not isinstance(s, dict) or not re.fullmatch(r"[a-z0-9_]+", str(s.get("id", ""))):
        return None
    if s.get("kind") not in ("relay", "exit", "client"):
        return None
    if s.get("source", "none") not in ("nft", "xui", "none"):
        return None
    conn = s.get("conn", {})
    if not isinstance(conn, dict) or conn.get("mode") not in ("local", "ssh"):
        return None
    out = {"id": s["id"], "name": str(s.get("name", s["id"]))[:64],
           "kind": s["kind"], "source": s.get("source", "none")}
    if conn["mode"] == "local":
        out["conn"] = {"mode": "local"}
    else:
        host = str(conn.get("host", ""))
        try:
            port = int(conn.get("port", 22))
        except (TypeError, ValueError):
            return None
        if not host or host.startswith("-") or not 1 <= port <= 65535:
            return None
        out["conn"] = {"mode": "ssh", "host": host, "port": port}
    if s.get("public_ip"):
        out["public_ip"] = str(s["public_ip"])[:64]
    return out


def _clean_rows(rows):
    out = []
    for r in rows or []:
        try:
            e, ts, a, b = str(r[0]), int(r[1]), int(r[2]), int(r[3])
        except (TypeError, ValueError, IndexError, KeyError):
            continue
        if ENTITY_RE.match(e) and ts >= 0 and a >= 0 and b >= 0:
            out.append((e, ts, a, b))
    return out


def import_payload(d):
    """Merge an export into this dashboard — imported values win on conflict,
    everything not mentioned in the file is kept. Returns counts."""
    if not isinstance(d, dict) or d.get("format") != EXPORT_FORMAT:
        raise ValueError("not a traffic-dash export file")
    try:
        ver = int(d.get("version", 0))
    except (TypeError, ValueError):
        raise ValueError("bad export version")
    if ver < 1 or ver > EXPORT_VERSION:
        raise ValueError(f"unsupported export version {d.get('version')}")
    stats = {"servers": 0, "rows": 0, "skipped_servers": 0}

    # 1. node (client machine) configs -> config.json, imported wins by id
    raw_servers = d.get("servers") or []
    imported = []
    for s in raw_servers:
        cs = _clean_server(s)
        if cs:
            imported.append(cs)
        else:
            stats["skipped_servers"] += 1
    if imported:
        with CFG_LOCK:
            byid = {s["id"]: s for s in CFG["servers"]}
            for s in imported:
                byid[s["id"]] = s
            CFG["servers"] = list(byid.values())
            tmp = CFG_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump(CFG, f, indent=1)
            os.chmod(tmp, 0o600)
            os.replace(tmp, CFG_PATH)
        for s in imported:  # live collector picks these up on its next loop
            SERVERS[s["id"]] = s
        stats["servers"] = len(imported)

    # 2. per-server settings + card order, imported wins per key
    imp_set = d.get("settings") or {}
    with SETTINGS_LOCK:
        cur = get_settings()
        for sid, st in (imp_set.get("servers") or {}).items():
            if isinstance(st, dict) and re.fullmatch(r"[a-z0-9_]+", str(sid)):
                merged = cur["servers"].get(sid, dict(DEFAULT_SRV))
                merged.update(st)
                cur["servers"][sid] = merged
        imp_order = [x for x in (imp_set.get("order") or []) if x in SERVERS]
        cur["order"] = imp_order + [x for x in cur["order"] if x not in imp_order]
        if isinstance(imp_set.get("retention"), dict):
            for k in ("m1", "h1", "d1", "ips", "health"):
                if k in imp_set["retention"]:
                    try:
                        cur["retention"][k] = min(max(0, int(imp_set["retention"][k])), RETENTION_MAX_DAYS)
                    except (TypeError, ValueError):
                        pass
        save_settings(cur)

    # 3. geo caches
    if isinstance(d.get("geo"), dict):
        GEO.update({str(k): v for k, v in d["geo"].items() if isinstance(v, dict)})
        save_geo()
    if isinstance(d.get("ipgeo"), dict):
        IPGEO.update({str(k): v for k, v in d["ipgeo"].items() if isinstance(v, dict)})
        save_ipgeo()

    # 4. traffic history — imported row replaces an existing bucket
    c = db()
    for t in DATA_TABLES:
        rows = _clean_rows((d.get("data") or {}).get(t))
        c.executemany(f"""INSERT INTO {t}(entity,ts,din,dout) VALUES(?,?,?,?)
                          ON CONFLICT(entity,ts) DO UPDATE SET din=excluded.din, dout=excluded.dout""", rows)
        stats["rows"] += len(rows)
    rl = _clean_rows(d.get("raw_last"))
    c.executemany("""INSERT INTO raw_last(entity,ts,bin,bout) VALUES(?,?,?,?)
                     ON CONFLICT(entity) DO UPDATE SET ts=excluded.ts,bin=excluded.bin,bout=excluded.bout""", rl)
    # 5. v2 extras: per-source-IP buckets + uptime history — imported wins
    ips_rows = []
    for r in d.get("ips") or []:
        try:
            if len(r) >= 6:                       # v3: sid,ip,port,day,din,dout
                sid_, ip_, port_, day_, di_, do_ = str(r[0]), str(r[1]), int(r[2]), int(r[3]), int(r[4]), int(r[5])
            else:                                 # v2 legacy: sid,ip,day,din,dout -> port 0
                sid_, ip_, port_, day_, di_, do_ = str(r[0]), str(r[1]), 0, int(r[2]), int(r[3]), int(r[4])
        except (TypeError, ValueError, IndexError):
            continue
        if re.fullmatch(r"[a-z0-9_]+", sid_) and IP_RE.match(ip_) and port_ >= 0 and day_ >= 0 and di_ >= 0 and do_ >= 0:
            ips_rows.append((sid_, ip_, port_, day_, di_, do_))
    c.executemany("""INSERT INTO ips(sid,ip,port,day,din,dout) VALUES(?,?,?,?,?,?)
                     ON CONFLICT(sid,ip,port,day) DO UPDATE SET din=excluded.din, dout=excluded.dout""", ips_rows)
    hp_rows = []
    for r in d.get("health") or []:
        try:
            sid_, ts_, ok_, tot_ = str(r[0]), int(r[1]), int(r[2]), int(r[3])
        except (TypeError, ValueError, IndexError):
            continue
        if re.fullmatch(r"[a-z0-9_]+", sid_) and ts_ >= 0 and 0 <= ok_ <= tot_:
            hp_rows.append((sid_, ts_, ok_, tot_))
    c.executemany("""INSERT INTO health(sid,ts,ok,total) VALUES(?,?,?,?)
                     ON CONFLICT(sid,ts) DO UPDATE SET ok=excluded.ok, total=excluded.total""", hp_rows)
    stats["rows"] += len(ips_rows) + len(hp_rows)
    c.commit(); c.close()
    return stats


# ---------------- auth ----------------

LOGIN_ATTEMPTS = {}


def hash_password(pw):
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200000).hex()
    return f"pbkdf2_sha256$200000${salt}${dk}"


def verify_password(pw, stored):
    # New format: pbkdf2_sha256$iters$salt$hash ; legacy: bare sha256 hex.
    try:
        if stored.startswith("pbkdf2_sha256$"):
            _, iters, salt, want = stored.split("$", 3)
            dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), int(iters)).hex()
            return hmac.compare_digest(dk, want)
        return hmac.compare_digest(hashlib.sha256(pw.encode()).hexdigest(), stored)
    except Exception:
        return False

def _token_key():
    # Binding the signing key to the current password hash means a password
    # change invalidates every previously issued token.
    return (CFG["secret"] + "|" + CFG.get("password_hash", "")).encode()


def make_token():
    ts = str(int(time.time()))
    nonce = secrets.token_hex(8)
    sig = hmac.new(_token_key(), f"{ts}.{nonce}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{nonce}.{sig}"


def cookie_header(token, max_age=30 * 86400):
    # Secure is omitted when serving plain HTTP (--no-nginx), otherwise the
    # browser would refuse to store/send the cookie and login would loop.
    sec = "; Secure" if CFG.get("secure_cookies", True) else ""
    return f"td={token}; Path=/; HttpOnly; SameSite=Lax{sec}; Max-Age={max_age}"


def check_token(tok):
    try:
        ts, nonce, sig = tok.split(".", 2)
        expect = hmac.new(_token_key(), f"{ts}.{nonce}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expect):
            return False
        return time.time() - int(ts) < 30 * 86400
    except Exception:
        return False


def set_password_hash(new_hash):
    with CFG_LOCK:
        CFG["password_hash"] = new_hash
        tmp = CFG_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(CFG, f, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, CFG_PATH)


# ---------------- HTTP ----------------

GRAN_TABLE = {"10s": ("s10", 10), "1m": ("m1", 60), "1h": ("h1", 3600), "1d": ("d1", 86400)}
ENTITY_RE = re.compile(r"^([a-z0-9_]+)(?::port:(\d+))?$")


def series_data(entity, gran, rng):
    """Local rows for the range; if the range reaches past what's stored
    locally and the archive holds this tier, fetch the missing head from the
    archive and merge (local rows win on overlap). Archive failures degrade
    to local-only data instead of failing the chart."""
    table, bucket = GRAN_TABLE.get(gran, ("m1", 60))
    now = int(time.time())
    start = now - rng
    c = db()
    rows = c.execute(f"SELECT ts, din, dout FROM {table} WHERE entity=? AND ts>=? ORDER BY ts",
                     (entity, start)).fetchall()
    c.close()
    points = {r[0]: (r[1], r[2]) for r in rows}
    arch_used = False
    if archive_enabled() and table in arch_tables():
        local_min = rows[0][0] if rows else now
        # small tolerance so a head gap from an idle node / recent restart
        # doesn't trigger a pointless archive round-trip
        if start < local_min - 2 * bucket:
            try:
                import urllib.parse
                rem = arch_req(f"/series?table={table}&entity={urllib.parse.quote(entity)}"
                               f"&start={start}&end={local_min}", timeout=6)
                for ts_, di, do_ in rem.get("rows") or []:
                    points.setdefault(int(ts_), (int(di), int(do_)))
                arch_used = True
            except Exception as e:
                print(f"archive fetch failed for {entity}: {e}", file=sys.stderr)
    return {"entity": entity, "bucket": bucket, "start": start, "end": now,
            "archive": arch_used,
            "points": [[t, v[0], v[1]] for t, v in sorted(points.items())]}


class Handler(BaseHTTPRequestHandler):
    server_version = "TrafficDash/2.0"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        ck = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return "td" in ck and check_token(ck["td"].value)

    def _body_json(self, limit=65536):
        ln = int(self.headers.get("Content-Length", 0) or 0)
        if ln > limit:
            return None
        try:
            return json.loads(self.rfile.read(ln))
        except Exception:
            return None

    def _qs(self):
        if "?" not in self.path:
            return self.path, {}
        p, q = self.path.split("?", 1)
        params = {}
        for kv in q.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k] = v
        return p, params

    def do_GET(self):
        path, q = self._qs()
        if path in ("/", "/index.html"):
            page = "index.html" if self._authed() else "login.html"
            self._send(200, open(os.path.join(STATIC, page), "rb").read(), "text/html; charset=utf-8")
            return
        if path == "/static/chart.umd.js":
            self._send(200, open(os.path.join(STATIC, "chart.umd.js"), "rb").read(),
                       "application/javascript", {"Cache-Control": "public, max-age=604800"})
            return
        if not self._authed():
            self._send(401, {"error": "unauthorized"})
            return
        if path == "/api/overview":
            self._send(200, self.overview())
            return
        if path == "/api/series":
            self._send(200, self.series(q))
            return
        if path == "/api/sources":
            self._send(200, self.sources(q))
            return
        if path == "/api/health":
            self._send(200, self.health_api(q))
            return
        if path == "/api/export":
            fname = time.strftime("traffic-dash-export-%Y%m%d-%H%M%S.json")
            self._send(200, export_payload(),
                       extra={"Content-Disposition": f'attachment; filename="{fname}"'})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        path, _ = self._qs()
        if path == "/api/login":
            # real client IP (nginx forwards it) so rate-limiting isn't one
            # global 127.0.0.1 bucket behind nginx
            peer = self.client_address[0]
            # Only trust forwarded-for headers from the local reverse proxy; a
            # direct client (--no-nginx on 0.0.0.0) could otherwise spoof them.
            if peer in ("127.0.0.1", "::1"):
                fwd = self.headers.get("X-Real-IP") or self.headers.get("X-Forwarded-For", "")
                ip = fwd.split(",")[0].strip() if fwd else peer
            else:
                ip = peer
            att = [t for t in LOGIN_ATTEMPTS.get(ip, []) if time.time() - t < 300]
            if len(att) >= 8:
                self._send(429, {"error": "too many attempts, wait 5 min"})
                return
            body = self._body_json() or {}
            pw = body.get("password") or ""
            if verify_password(pw, CFG["password_hash"]):
                LOGIN_ATTEMPTS.pop(ip, None)
                self._send(200, {"ok": True}, extra={"Set-Cookie": cookie_header(make_token())})
            else:
                att.append(time.time())
                LOGIN_ATTEMPTS[ip] = att
                self._send(403, {"error": "wrong password"})
            return
        if not self._authed():
            self._send(401, {"error": "unauthorized"})
            return
        if path == "/api/logout":
            self._send(200, {"ok": True}, extra={"Set-Cookie": "td=; Path=/; Max-Age=0"})
            return
        if path == "/api/password":
            body = self._body_json() or {}
            cur = body.get("current") or ""
            new = body.get("new") or ""
            if not verify_password(cur, CFG["password_hash"]):
                self._send(403, {"error": "current password is wrong"})
                return
            if len(new) < 8:
                self._send(400, {"error": "new password must be at least 8 characters"})
                return
            set_password_hash(hash_password(new))
            self._send(200, {"ok": True})
            return
        if path == "/api/settings":
            body = self._body_json() or {}
            sid = body.get("server")
            if sid not in SERVERS:
                self._send(400, {"error": "unknown server"})
                return
            with SETTINGS_LOCK:
                s = get_settings()
                st = s["servers"][sid]
                if "display_name" in body:
                    dn = str(body["display_name"]).strip()[:48]
                    if dn:
                        st["display_name"] = dn
                    else:
                        st.pop("display_name", None)
                if "reset_day" in body:
                    rd = int(body["reset_day"])
                    if 1 <= rd <= 28:
                        st["reset_day"] = rd
                if "quota_gb" in body:
                    qg = float(body["quota_gb"])
                    if qg >= 0:
                        st["quota_gb"] = qg
                if "tz_offset" in body:
                    tz = float(body["tz_offset"])
                    if -12 <= tz <= 14:
                        st["tz_offset"] = tz
                if "port_names" in body and isinstance(body["port_names"], dict):
                    st["port_names"].update({str(k): str(v)[:40] for k, v in body["port_names"].items()
                                             if re.fullmatch(r"\d+", str(k))})
                for key in ("ports_include", "ports_exclude"):
                    if key in body and isinstance(body[key], list):
                        st[key] = sorted({int(p) for p in body[key]
                                          if str(p).isdigit() and 1 <= int(p) <= 65535})
                save_settings(s)
            self._send(200, {"ok": True, "settings": st})
            return
        if path == "/api/order":
            body = self._body_json() or {}
            order = body.get("order")
            if not isinstance(order, list):
                self._send(400, {"error": "order must be a list"})
                return
            order = [sid for sid in order if sid in SERVERS]
            if len(order) != len(SERVERS) or set(order) != set(SERVERS):
                self._send(400, {"error": "order must include every server exactly once"})
                return
            with SETTINGS_LOCK:
                s = get_settings()
                s["order"] = order
                save_settings(s)
            self._send(200, {"ok": True, "order": order})
            return
        if path == "/api/retention":
            body = self._body_json() or {}
            with SETTINGS_LOCK:
                s = get_settings()
                ret = s["retention"]
                for k in ("m1", "h1", "d1", "ips", "health"):
                    if k in body:
                        try:
                            v = int(body[k])
                        except (TypeError, ValueError):
                            self._send(400, {"error": f"{k} must be a whole number of days (0 = forever)"})
                            return
                        if not 0 <= v <= RETENTION_MAX_DAYS:
                            self._send(400, {"error": f"{k} must be between 0 and {RETENTION_MAX_DAYS} days"})
                            return
                        ret[k] = v
                save_settings(s)
            self._send(200, {"ok": True, "retention": ret})
            return
        if path == "/api/import":
            # 128 MB cap; for bigger exports use the CLI on the host:
            #   bash /opt/traffic-dash/install.sh import <file>
            body = self._body_json(limit=128 * 1024 * 1024)
            if body is None:
                self._send(400, {"error": "invalid JSON or file too large — use the CLI import for very large exports"})
                return
            try:
                stats = import_payload(body)
            except ValueError as e:
                self._send(400, {"error": str(e)})
                return
            self._send(200, {"ok": True, **stats})
            return
        self._send(404, {"error": "not found"})

    def overview(self):
        s = get_settings()
        c = db()
        now = time.time()
        with RATES_LOCK:
            rates = {k: {"in": v[0], "out": v[1], "ts": v[2]} for k, v in RATES.items()}
        servers_out = []
        for sid in s["order"]:
            srv = SERVERS[sid]
            st = s["servers"][sid]
            start, end = period_bounds(st["reset_day"], st["tz_offset"])
            hin, hout = usage_between(c, sid, start, end)
            ents = [r[0] for r in c.execute("SELECT DISTINCT entity FROM d1 WHERE entity LIKE ?", (f"{sid}:port:%",))]
            ports = sorted(int(e.rsplit(":", 1)[1]) for e in ents)
            exc = set(st.get("ports_exclude", []))
            xnames = XUI_NAMES.get(sid, {})
            plist = []
            psum = 0
            for p in ports:
                if p in exc:
                    continue
                pi, po = usage_between(c, f"{sid}:port:{p}", start, end)
                psum += pi + po
                name = st["port_names"].get(str(p)) or xnames.get(str(p)) or f"Port {p}"
                plist.append({"port": p, "name": name, "in": pi, "out": po, "total": pi + po})
            for pl in plist:
                pl["pct"] = round(100 * pl["total"] / psum, 1) if psum else 0
            gip = geo_ip_for(srv)
            geo = GEO.get(gip, {}) if gip else {}
            servers_out.append({
                "id": sid, "name": st.get("display_name") or srv["name"],
                "default_name": srv["name"], "kind": srv["kind"],
                "country_code": geo.get("cc", ""), "country": geo.get("country", ""),
                "geo_ip": gip or "",
                "usage": {"in": hin, "out": hout, "total": hin + hout},
                "quota_bytes": st["quota_gb"] * 1024**3 if st["quota_gb"] else 0,
                "settings": st, "tz_label": tz_label(st["tz_offset"]),
                "period": {"start": start, "end": end, "days_left": max(0, round((end - now) / 86400, 1))},
                "ports": plist,
                "rate": rates.get(sid) if now - HEALTH.get(sid, 0) < 60 else None,
                "health_last": HEALTH.get(sid, 0),
            })
        c.close()
        return {"servers": servers_out, "rates": rates, "now": int(now),
                "retention": s["retention"]}

    def series(self, q):
        entity = q.get("entity", "")
        m = ENTITY_RE.match(entity)
        if not m or m.group(1) not in SERVERS:
            return {"error": "bad entity"}
        gran = q.get("gran", "1m")
        try:
            rng = min(int(q.get("range", 3600)), (RETENTION_MAX_DAYS + 10) * 86400)
        except ValueError:
            rng = 3600
        return series_data(entity, gran, rng)

    def sources(self, q):
        """Per-source-IP traffic + per-country aggregation. Optionally filtered
        to one server and one port (port filter only applies with a server)."""
        sid = q.get("server", "")
        if sid and sid not in SERVERS:
            return {"error": "unknown server"}
        try:
            days = max(1, min(int(q.get("days", 7)), 365))
        except ValueError:
            days = 7
        port = None
        if sid and str(q.get("port", "")).isdigit():
            port = int(q["port"])
        since = int(time.time()) - days * 86400
        c = db()
        if sid and port is not None:
            rows = c.execute("SELECT ip, SUM(din), SUM(dout) FROM ips WHERE sid=? AND port=? AND day>=? GROUP BY ip",
                             (sid, port, since)).fetchall()
        elif sid:
            rows = c.execute("SELECT ip, SUM(din), SUM(dout) FROM ips WHERE sid=? AND day>=? GROUP BY ip",
                             (sid, since)).fetchall()
        else:
            rows = c.execute("SELECT ip, SUM(din), SUM(dout) FROM ips WHERE day>=? GROUP BY ip",
                             (since,)).fetchall()
        c.close()
        rows.sort(key=lambda r: r[1] + r[2], reverse=True)
        total_all = sum(r[1] + r[2] for r in rows)
        denom = total_all or 1
        top = []
        for ip, di, do_ in rows[:50]:
            g = IPGEO.get(ip) or {}
            top.append({"ip": ip, "in": di, "out": do_, "total": di + do_,
                        "share": round(100 * (di + do_) / denom, 2),
                        "cc": g.get("cc", ""), "country": g.get("country", "")})
        other = sum(r[1] + r[2] for r in rows[50:])
        countries = {}
        for ip, di, do_ in rows:
            g = IPGEO.get(ip) or {}
            key = g.get("cc") or "??"
            cn = countries.setdefault(key, {"cc": g.get("cc", ""),
                                            "country": g.get("country") or "Unknown",
                                            "in": 0, "out": 0, "ips": 0})
            cn["in"] += di; cn["out"] += do_; cn["ips"] += 1
        clist = []
        for cn in countries.values():
            cn["total"] = cn["in"] + cn["out"]
            cn["share"] = round(100 * cn["total"] / denom, 2)
            clist.append(cn)
        clist.sort(key=lambda x: -x["total"])
        return {"days": days, "server": sid or "all", "port": port, "total": total_all,
                "ips_tracked": len(rows), "top": top, "other": other,
                "countries": clist[:30]}

    def health_api(self, q):
        """Uptime per server: percentage, 96-segment strip, last incident."""
        try:
            days = max(1, min(int(q.get("days", 1)), 90))
        except ValueError:
            days = 1
        now = int(time.time())
        since = now - days * 86400
        nbuck = 96
        bsz = max(60, (days * 86400) // nbuck)
        s = get_settings()
        c = db()
        out = []
        for sid in s["order"]:
            rows = c.execute("SELECT ts, ok, total FROM health WHERE sid=? AND ts>=?",
                             (sid, since)).fetchall()
            okc = sum(r[1] for r in rows)
            tot = sum(r[2] for r in rows)
            buckets = [[0, 0] for _ in range(nbuck)]
            for ts_, ok_, tot_ in rows:
                i = min(nbuck - 1, max(0, (ts_ - since) // bsz))
                buckets[i][0] += ok_
                buckets[i][1] += tot_
            strip = [round(100 * b[0] / b[1]) if b[1] else -1 for b in buckets]
            row = c.execute("SELECT MAX(ts) FROM health WHERE sid=? AND total>0 AND ok=0",
                            (sid,)).fetchone()
            out.append({"id": sid,
                        "name": s["servers"][sid].get("display_name") or SERVERS[sid]["name"],
                        "kind": SERVERS[sid]["kind"],
                        "up_now": now - HEALTH.get(sid, 0) < 60,
                        "uptime": round(100 * okc / tot, 2) if tot else None,
                        "strip": strip, "bucket_sec": bsz,
                        "last_down": row[0] if row and row[0] else None})
        c.close()
        return {"days": days, "since": since, "now": now, "servers": out}


class ThreadingHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    init_db()
    load_geo()
    load_ipgeo()
    threading.Thread(target=geo_loop, daemon=True).start()
    threading.Thread(target=collector, daemon=True).start()
    threading.Thread(target=archive_loop, daemon=True).start()
    srv = ThreadingHTTPServer(LISTEN, Handler)
    print(f"listening on {LISTEN}")
    srv.serve_forever()


def cli(argv):
    cmd = argv[0]
    if cmd == "export":
        init_db()
        payload = export_payload()
        if len(argv) > 1:
            with open(argv[1], "w") as f:
                json.dump(payload, f)
            print(f"exported {sum(len(v) for v in payload['data'].values())} traffic rows, "
                  f"{len(payload['servers'])} server configs -> {argv[1]}")
        else:
            json.dump(payload, sys.stdout)
    elif cmd == "import":
        if len(argv) < 2:
            sys.exit("usage: app.py import <export.json>")
        init_db()
        load_geo()    # so the merged geo caches keep existing entries
        load_ipgeo()
        with open(argv[1]) as f:
            d = json.load(f)
        try:
            stats = import_payload(d)
        except ValueError as e:
            sys.exit(f"import failed: {e}")
        print(f"imported {stats['rows']} traffic rows, {stats['servers']} server configs"
              + (f" ({stats['skipped_servers']} invalid server entries skipped)" if stats["skipped_servers"] else ""))
        print("restart the service to pick up new servers: systemctl restart traffic-dash")
    else:
        sys.exit("usage: app.py [export [file.json] | import <file.json>]")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli(sys.argv[1:])
    else:
        main()
