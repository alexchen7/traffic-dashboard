#!/usr/bin/env python3
"""Traffic dashboard archive — long-term rollup storage. Stdlib only.

Runs on a storage server and owns its own SQLite file (archive.db).
The dashboard host ships finalized m1/h1/d1 rows here and fetches old
ranges back on demand when a chart request reaches past local retention.

Endpoints (all require "Authorization: Bearer <token>"):
  POST /ingest      {"table": "m1", "rows": [[entity,ts,din,dout], ...]}
                    idempotent upsert; safe to retry any batch
  GET  /watermarks?table=m1
                    {"watermarks": {entity: max_ts}} — lets the shipper
                    resume with no local state
  GET  /series?table=m1&entity=<e>&start=<ts>&end=<ts>
                    {"rows": [[ts,din,dout], ...]} half-open [start, end)
  GET  /status      row counts per table + db size

Config: config.json next to this file — {"token": ..., "listen_host": ...,
"listen_port": ...}. Bind to a private address or front with a tunnel/TLS;
the token is the only auth. install.sh's `archive` command sets all this up.
"""
import hmac, json, os, re, socketserver, sqlite3, sys, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "archive.db")
CFG = json.load(open(os.path.join(BASE, "config.json")))
LISTEN = (CFG.get("listen_host", "0.0.0.0"), int(CFG.get("listen_port", 15100)))

TABLES = ("m1", "h1", "d1")
ENTITY_RE = re.compile(r"^[a-z0-9_]+(?::port:\d+)?$")
MAX_BODY = 64 * 1024 * 1024
WRITE_LOCK = threading.Lock()


def db():
    c = sqlite3.connect(DB, timeout=30)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    return c


def init_db():
    c = db()
    for t in TABLES:
        c.execute(f"CREATE TABLE IF NOT EXISTS {t} (entity TEXT, ts INTEGER, din INTEGER, dout INTEGER, PRIMARY KEY(entity, ts))")
    c.commit(); c.close()


class Handler(BaseHTTPRequestHandler):
    server_version = "TrafficArchive/1.0"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body):
        body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        auth = self.headers.get("Authorization", "")
        return auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], CFG["token"])

    def _qs(self):
        if "?" not in self.path:
            return self.path, {}
        p, q = self.path.split("?", 1)
        params = {}
        for kv in q.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k] = urllib.parse.unquote(v)
        return p, params

    def do_GET(self):
        path, q = self._qs()
        if not self._authed():
            self._send(401, {"error": "unauthorized"})
            return
        if path == "/watermarks":
            t = q.get("table", "")
            if t not in TABLES:
                self._send(400, {"error": "bad table"})
                return
            c = db()
            wm = {e: ts for e, ts in c.execute(f"SELECT entity, MAX(ts) FROM {t} GROUP BY entity")}
            c.close()
            self._send(200, {"watermarks": wm})
            return
        if path == "/series":
            t = q.get("table", "")
            entity = q.get("entity", "")
            if t not in TABLES or not ENTITY_RE.match(entity):
                self._send(400, {"error": "bad table or entity"})
                return
            try:
                start, end = int(q.get("start", 0)), int(q.get("end", 0))
            except ValueError:
                self._send(400, {"error": "bad range"})
                return
            c = db()
            rows = c.execute(f"SELECT ts,din,dout FROM {t} WHERE entity=? AND ts>=? AND ts<? ORDER BY ts",
                             (entity, start, end)).fetchall()
            c.close()
            self._send(200, {"rows": [list(r) for r in rows]})
            return
        if path == "/status":
            c = db()
            counts = {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in TABLES}
            c.close()
            self._send(200, {"ok": True, "counts": counts,
                             "db_bytes": os.path.getsize(DB) if os.path.exists(DB) else 0})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        path, _ = self._qs()
        if not self._authed():
            self._send(401, {"error": "unauthorized"})
            return
        if path == "/ingest":
            ln = int(self.headers.get("Content-Length", 0) or 0)
            if ln > MAX_BODY:
                self._send(413, {"error": "body too large"})
                return
            try:
                body = json.loads(self.rfile.read(ln))
            except Exception:
                self._send(400, {"error": "bad JSON"})
                return
            t = body.get("table", "")
            if t not in TABLES:
                self._send(400, {"error": "bad table"})
                return
            rows = []
            for r in body.get("rows") or []:
                try:
                    e, ts, di, do_ = str(r[0]), int(r[1]), int(r[2]), int(r[3])
                except (TypeError, ValueError, IndexError):
                    continue
                if ENTITY_RE.match(e) and ts >= 0 and di >= 0 and do_ >= 0:
                    rows.append((e, ts, di, do_))
            with WRITE_LOCK:
                c = db()
                c.executemany(f"""INSERT INTO {t}(entity,ts,din,dout) VALUES(?,?,?,?)
                                  ON CONFLICT(entity,ts) DO UPDATE SET din=excluded.din, dout=excluded.dout""", rows)
                c.commit(); c.close()
            self._send(200, {"ok": True, "ingested": len(rows)})
            return
        self._send(404, {"error": "not found"})


class ThreadingHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    if not CFG.get("token"):
        sys.exit("config.json needs a non-empty \"token\"")
    init_db()
    srv = ThreadingHTTPServer(LISTEN, Handler)
    print(f"archive listening on {LISTEN}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
