#!/usr/bin/env python3
"""Traffic dashboard v2 — multi-server (relays + exit nodes). Stdlib only.

- Collector samples every 10s from all servers in config.json (parallel threads,
  SQLite writes serialized in the collector thread).
- Per-server settings: quota, reset day, timezone offset, port names,
  monitored-port include/exclude.
- Rollups: s10 (6h), m1 (8d), h1 (120d), d1 (kept forever).
- Web app on 127.0.0.1:15080 behind nginx TLS (15443).
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

RATES = {}
RATES_LOCK = threading.Lock()
SETTINGS_LOCK = threading.Lock()
XUI_NAMES = {}      # sid -> {port_str: remark}
HEALTH = {}         # sid -> last ok ts
GEO = {}            # ip -> {"cc": "US", "country": "United States"}


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


def prune(c, now):
    c.execute("DELETE FROM s10 WHERE ts < ?", (now - 6 * 3600,))
    c.execute("DELETE FROM m1 WHERE ts < ?", (now - 8 * 86400,))
    c.execute("DELETE FROM h1 WHERE ts < ?", (now - 120 * 86400,))


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
                if not r:
                    continue
                tzoff = settings["servers"][sid].get("tz_offset", 8)
                ts = int(time.time())
                for port, v in r.get("ports", {}).items():
                    record(c, f"{sid}:port:{port}", ts, v.get("in", 0), v.get("out", 0), last, tzoff)
                h = r.get("host", {})
                record(c, sid, ts, h.get("rx", 0), h.get("tx", 0), last, tzoff)
                if r.get("names"):
                    XUI_NAMES[sid] = r["names"]
                HEALTH[sid] = ts
            save_last(c, last)
            n += 1
            if n % 30 == 0:
                prune(c, int(time.time()))
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


def geo_loop():
    """Runs geo lookups OFF the collector thread so network stalls never
    freeze sampling."""
    while True:
        try:
            resolve_geos()
        except Exception as e:
            print("geo_loop error:", e, file=sys.stderr)
        time.sleep(1800)


def tz_label(off):
    sign = "+" if off >= 0 else "-"
    a = abs(off)
    hh = int(a)
    mm = int(round((a - hh) * 60))
    return f"UTC{sign}{hh:02d}:{mm:02d}"


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

    def _body_json(self):
        ln = int(self.headers.get("Content-Length", 0) or 0)
        if ln > 65536:
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
        return {"servers": servers_out, "rates": rates, "now": int(now)}

    def series(self, q):
        entity = q.get("entity", "")
        m = ENTITY_RE.match(entity)
        if not m or m.group(1) not in SERVERS:
            return {"error": "bad entity"}
        gran = q.get("gran", "1m")
        table, bucket = GRAN_TABLE.get(gran, ("m1", 60))
        try:
            rng = min(int(q.get("range", 3600)), 400 * 86400)
        except ValueError:
            rng = 3600
        now = int(time.time())
        start = now - rng
        c = db()
        rows = c.execute(f"SELECT ts, din, dout FROM {table} WHERE entity=? AND ts>=? ORDER BY ts",
                         (entity, start)).fetchall()
        c.close()
        return {"entity": entity, "bucket": bucket, "start": start, "end": now,
                "points": [[r[0], r[1], r[2]] for r in rows]}


class ThreadingHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    init_db()
    load_geo()
    threading.Thread(target=geo_loop, daemon=True).start()
    threading.Thread(target=collector, daemon=True).start()
    srv = ThreadingHTTPServer(LISTEN, Handler)
    print(f"listening on {LISTEN}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
