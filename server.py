#!/usr/bin/env python3
"""
Heimdall IDS Dashboard — Version 1 (Alerts only)
Zero-dependency SSE server + SQLite + Auth. Python stdlib only.

Usage:
    python3 server.py
    python3 server.py --eve /var/log/suricata/eve.json --port 8765
    python3 server.py --password mysecretpassword
    python3 server.py --db /var/lib/heimdall/alerts.db --retain-days 90
"""

import argparse
import hashlib
import hmac
import json
import logging
import os
import secrets
import socketserver
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
from queue import Empty, Queue
from urllib.parse import urlparse, parse_qs

DEFAULT_EVE  = "/var/log/suricata/eve.json"
DEFAULT_PORT = 8765
DEFAULT_HOST = "0.0.0.0"
DEFAULT_DB   = Path(__file__).parent / "alerts.db"
RETAIN_DAYS  = 90
PING_EVERY   = 10
PURGE_EVERY  = 3600
SESSION_TTL  = 86400 * 7   # 7 days

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("suricata")

# ── Auth ──────────────────────────────────────────────────────────────────────

class AuthManager:
    def __init__(self, conn_fn):
        self._conn = conn_fn
        c = self._conn()
        c.execute("""CREATE TABLE IF NOT EXISTS auth (
            key TEXT PRIMARY KEY, value TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL)""")
        c.commit()

    def _hash(self, pw):
        salt = secrets.token_hex(16)
        h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260_000)
        return f"{salt}${h.hex()}"

    def _verify(self, pw, stored):
        try:
            salt, h = stored.split("$", 1)
            check = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260_000)
            return hmac.compare_digest(check.hex(), h)
        except Exception:
            return False

    def set_password(self, pw):
        c = self._conn()
        c.execute("INSERT OR REPLACE INTO auth (key,value) VALUES ('pw_hash',?)", (self._hash(pw),))
        c.commit()
        log.info("Password updated.")

    def get_hash(self):
        row = self._conn().execute("SELECT value FROM auth WHERE key='pw_hash'").fetchone()
        return row[0] if row else None

    def check_password(self, pw):
        stored = self.get_hash()
        return bool(stored and self._verify(pw, stored))

    def create_session(self):
        token = secrets.token_hex(32)
        now = time.time()
        c = self._conn()
        c.execute("INSERT INTO sessions (token,created_at,expires_at) VALUES (?,?,?)",
                  (token, now, now + SESSION_TTL))
        c.commit()
        return token

    def validate_session(self, token):
        if not token: return False
        row = self._conn().execute(
            "SELECT expires_at FROM sessions WHERE token=?", (token,)).fetchone()
        if not row: return False
        if time.time() > row[0]:
            self._conn().execute("DELETE FROM sessions WHERE token=?", (token,))
            self._conn().commit()
            return False
        return True

    def revoke_session(self, token):
        self._conn().execute("DELETE FROM sessions WHERE token=?", (token,))
        self._conn().commit()

    def purge_expired(self):
        cur = self._conn().execute("DELETE FROM sessions WHERE expires_at<?", (time.time(),))
        self._conn().commit()
        if cur.rowcount:
            log.info("Purged %d expired sessions", cur.rowcount)

auth = None

# ── Database ──────────────────────────────────────────────────────────────────

class AlertDB:
    def __init__(self, path, retain_days=RETAIN_DAYS):
        self.path = str(path)
        self.retain_days = retain_days
        self._local = threading.local()
        self._conn()
        log.info("Database: %s  (retain %d days)", self.path, self.retain_days)

    def _conn(self):
        if not hasattr(self._local, "conn"):
            c = sqlite3.connect(self.path, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("""CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY, ts TEXT NOT NULL, ts_epoch REAL NOT NULL,
                src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
                proto TEXT, iface TEXT, flow_id INTEGER,
                sig_id INTEGER, sig_msg TEXT, category TEXT,
                severity TEXT, action TEXT, raw_json TEXT)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_ts  ON alerts(ts_epoch)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_sev ON alerts(severity)")
            c.commit()
            self._local.conn = c
        return self._local.conn

    def _epoch(self, ts):
        from datetime import datetime
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try: return datetime.strptime(ts, fmt).timestamp()
            except ValueError: pass
        return time.time()

    # ── alerts ────────────────────────────────────────────────────────────────

    def insert_alert(self, a):
        try:
            self._conn().execute("""INSERT OR IGNORE INTO alerts
                (id,ts,ts_epoch,src_ip,src_port,dst_ip,dst_port,
                 proto,iface,flow_id,sig_id,sig_msg,category,severity,action,raw_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (a["id"], a.get("ts",""), self._epoch(a.get("ts","")),
                 a.get("src_ip",""), a.get("src_port",0),
                 a.get("dst_ip",""), a.get("dst_port",0),
                 a.get("proto",""), a.get("iface",""), a.get("flow_id",0),
                 a.get("sig_id",0), a.get("sig_msg",""), a.get("category",""),
                 a.get("severity","info"), a.get("action","allowed"),
                 json.dumps(a.get("raw",{}))))
            self._conn().commit()
        except sqlite3.Error as e:
            log.warning("DB insert_alert: %s", e)

    def fetch_alerts(self, days=None, limit=5000):
        cutoff = time.time() - (days or self.retain_days) * 86400
        rows = self._conn().execute("""
            SELECT id,ts,src_ip,src_port,dst_ip,dst_port,proto,iface,
                   flow_id,sig_id,sig_msg,category,severity,action,raw_json
            FROM alerts WHERE ts_epoch>=? ORDER BY ts_epoch DESC LIMIT ?""",
            (cutoff, limit)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try: d["raw"] = json.loads(d.pop("raw_json","{}"))
            except: d["raw"] = {}
            out.append(d)
        return out

    def clear_all(self):
        cur = self._conn().execute("DELETE FROM alerts")
        self._conn().commit()
        log.info("Alerts cleared — %d rows deleted", cur.rowcount)
        return cur.rowcount

    # ── maintenance ──────────────────────────────────────────────────────────────────


    def purge_old(self):
        cutoff = time.time() - self.retain_days * 86400
        cur = self._conn().execute("DELETE FROM alerts WHERE ts_epoch<?", (cutoff,))
        self._conn().commit()
        if cur.rowcount:
            log.info("Purged %d alerts older than %d days", cur.rowcount, self.retain_days)

    def stats(self):
        c = self._conn()
        total  = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        cutoff = time.time() - self.retain_days * 86400
        recent = c.execute("SELECT COUNT(*) FROM alerts WHERE ts_epoch>=?", (cutoff,)).fetchone()[0]
        oldest = c.execute("SELECT MIN(ts) FROM alerts").fetchone()[0]
        return {"total": total, "recent": recent, "oldest": oldest}

db = None

# ── Registry ──────────────────────────────────────────────────────────────────

class Registry:
    def __init__(self):
        self._lock = threading.Lock()
        self._clients = {}
        self._nid = 0

    def add(self):
        with self._lock:
            cid = self._nid; self._nid += 1
            self._clients[cid] = Queue(maxsize=500)
            log.info("Client connected    (total: %d)", len(self._clients))
            return cid, self._clients[cid]

    def remove(self, cid):
        with self._lock:
            self._clients.pop(cid, None)
            log.info("Client disconnected (total: %d)", len(self._clients))

    def broadcast(self, event_type, payload):
        msg = f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"
        with self._lock:
            dead = []
            for cid, q in self._clients.items():
                try: q.put_nowait(msg)
                except: dead.append(cid)
            for cid in dead: self._clients.pop(cid, None)

    def count(self):
        with self._lock: return len(self._clients)

registry = Registry()

# ── EVE parsing ───────────────────────────────────────────────────────────────

def map_severity(n):
    return {1:"critical",2:"high",3:"medium",4:"low"}.get(n,"info")

def parse_eve_line(raw):
    """Parse one EVE JSON line. Returns (event_type, parsed_dict) or (None, None)."""
    raw = raw.strip()
    if not raw: return None, None
    try: evt = json.loads(raw)
    except: return None, None

    etype = evt.get("event_type")

    if etype == "alert":
        a = evt.get("alert", {})
        return "alert", {
            "id":       f"{evt.get('flow_id',0)}-{int(time.time()*1000)}",
            "ts":       evt.get("timestamp",""),
            "src_ip":   evt.get("src_ip",""),
            "src_port": evt.get("src_port",0),
            "dst_ip":   evt.get("dest_ip",""),
            "dst_port": evt.get("dest_port",0),
            "proto":    evt.get("proto","TCP").upper(),
            "iface":    evt.get("in_iface",""),
            "flow_id":  evt.get("flow_id",0),
            "sig_id":   a.get("signature_id",0),
            "sig_msg":  a.get("signature",""),
            "category": a.get("category",""),
            "severity": map_severity(a.get("severity")),
            "action":   a.get("action","allowed"),
            "raw":      evt,
        }

    return None, None

# ── Background threads ────────────────────────────────────────────────────────

def tail_thread(path):
    log.info("Tailing %s", path)
    pos = 0
    try:
        pos = os.path.getsize(path)
        log.info("Starting at offset %d (skipping history)", pos)
    except OSError:
        log.warning("Eve file not found yet, will wait…")

    while True:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(pos)
                while True:
                    line = f.readline()
                    if line:
                        etype, parsed = parse_eve_line(line)
                        if etype == "alert":
                            db.insert_alert(parsed)
                            registry.broadcast("alert", parsed)
                        pos = f.tell()
                    else:
                        try:
                            if os.path.getsize(path) < pos:
                                log.info("Log rotation detected, rewinding…")
                                pos = 0; break
                        except OSError: pass
                        time.sleep(0.1)
        except OSError as e:
            log.warning("Cannot open %s: %s — retry in 3s", path, e)
            time.sleep(3)

def purge_thread():
    while True:
        time.sleep(PURGE_EVERY)
        db.purge_old()
        auth.purge_expired()

# ── HTTP handler ──────────────────────────────────────────────────────────────

DASHBOARD_PATH = Path(__file__).parent / "heimdall-dashboard.html"

class Handler(BaseHTTPRequestHandler):

    server_version = ""
    sys_version    = ""

    def log_message(self, fmt, *args):
        first = str(args[0]) if args else ""
        if "/events" not in first:
            log.info("%s %s", self.address_string(), fmt % args)

    def _token(self):
        raw = self.headers.get("Cookie","")
        if not raw: return ""
        try:
            c = SimpleCookie(raw)
            m = c.get("suri_session")
            return m.value if m else ""
        except: return ""

    def _authed(self): return auth.validate_session(self._token())

    def _require_auth(self):
        if self._authed(): return True
        p = urlparse(self.path).path
        api_paths = ("/alerts","/events","/health")
        if any(p.startswith(x) for x in api_paths):
            self._json({"error":"Unauthorized"}, 401)
        else:
            self._redirect("/login")
        return False

    def _redirect(self, loc):
        self.send_response(302)
        self.send_header("Location", loc)
        self.send_header("Content-Length","0")
        self.end_headers()

    def _json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _qs_int(self, qs, key, default, lo=1, hi=20000):
        try: return max(lo, min(int(qs.get(key,[default])[0]), hi))
        except: return default

    # ── routing ───────────────────────────────────────────────────────────────

    def do_GET(self):
        p  = urlparse(self.path)
        qs = parse_qs(p.query)

        if p.path == "/login":  self._login_page(); return
        if p.path == "/logout": self._logout();     return
        if not self._require_auth(): return

        routes = {
            "/":           lambda: self._file(DASHBOARD_PATH, "text/html; charset=utf-8"),
            "/index.html": lambda: self._file(DASHBOARD_PATH, "text/html; charset=utf-8"),
            "/events":     self._sse,
            "/alerts":     lambda: self._serve_alerts(qs),
            "/health":     lambda: self._json({
                               "status":"ok","clients":registry.count(),
                               "db":db.stats(),"time":int(time.time())}),
        }
        fn = routes.get(p.path)
        if fn: fn()
        else:  self.send_error(404)

    def do_POST(self):
        p = urlparse(self.path)
        if p.path == "/login": self._do_login()
        else: self.send_error(404)

    def do_DELETE(self):
        if not self._require_auth(): return
        p = urlparse(self.path)
        if p.path == "/alerts":
            self._json({"deleted": db.clear_all()})
        else:
            self.send_error(404)

    # ── auth ──────────────────────────────────────────────────────────────────

    def _login_page(self):
        data = LOGIN_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type",   "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control",  "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _do_login(self):
        try:
            n    = int(self.headers.get("Content-Length",0))
            body = json.loads(self.rfile.read(n))
            pw   = body.get("password","")
        except Exception:
            self._json({"error":"Bad request"},400); return

        if auth.check_password(pw):
            token = auth.create_session()
            log.info("Login OK from %s", self.address_string())
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.send_header("Set-Cookie",
                f"suri_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}")
            body = json.dumps({"ok":True}).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            log.warning("Failed login from %s", self.address_string())
            time.sleep(1)
            self._json({"error":"Invalid password"},401)

    def _logout(self):
        auth.revoke_session(self._token())
        self.send_response(302)
        self.send_header("Location","/login")
        self.send_header("Set-Cookie",
            "suri_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
        self.send_header("Content-Length","0")
        self.end_headers()

    # ── data endpoints ────────────────────────────────────────────────────────

    def _file(self, path, ctype):
        if not path.exists():
            self.send_error(404, f"{path.name} not found"); return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type",   ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control",  "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _serve_alerts(self, qs):
        days  = self._qs_int(qs, "days",  RETAIN_DAYS, 1, RETAIN_DAYS)
        limit = self._qs_int(qs, "limit", 5000,         1, 20000)
        body  = json.dumps(db.fetch_alerts(days=days, limit=limit)).encode()
        self.send_response(200)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control",  "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type",      "text/event-stream")
        self.send_header("Cache-Control",     "no-cache")
        self.send_header("Connection",        "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        cid, q = registry.add()
        try:
            self.wfile.write(f"event: ping\ndata: {int(time.time())}\n\n".encode())
            self.wfile.flush()
        except:
            registry.remove(cid); return

        while True:
            try:    msg = q.get(timeout=PING_EVERY)
            except Empty: msg = f"event: ping\ndata: {int(time.time())}\n\n"
            try:
                self.wfile.write(msg.encode())
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                break
        registry.remove(cid)

# ── Login page HTML ───────────────────────────────────────────────────────────

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Heimdall — Sign in</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'IBM Plex Sans',system-ui,sans-serif;background:#0a0c10;color:#e8eaf0;
     min-height:100vh;display:flex;align-items:center;justify-content:center}
.wrap{width:360px;max-width:92vw}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:36px}
.logo-box{width:34px;height:34px;background:#4f9cf9;border-radius:7px;
          display:flex;align-items:center;justify-content:center;flex-shrink:0}
.logo-box svg{width:18px;height:18px}
.logo-name{font-family:'IBM Plex Mono',monospace;font-size:15px;font-weight:500;letter-spacing:.06em}
.logo-tag{font-size:10px;color:#4a5163;font-family:'IBM Plex Mono',monospace;
          letter-spacing:.05em;margin-left:auto;white-space:nowrap}
.card{background:#0f1117;border:1px solid rgba(255,255,255,0.09);border-radius:12px;padding:32px}
.card-title{font-size:17px;font-weight:500;margin-bottom:4px}
.card-sub{font-size:12px;color:#7b8394;margin-bottom:24px}
label{display:block;font-size:10px;font-weight:500;letter-spacing:.1em;
      text-transform:uppercase;color:#4a5163;margin-bottom:6px}
.input-wrap{position:relative;margin-bottom:20px}
input[type=password],input[type=text]{width:100%;padding:10px 40px 10px 12px;background:#161b24;
  border:1px solid rgba(255,255,255,0.09);border-radius:6px;color:#e8eaf0;
  font-size:13px;font-family:'IBM Plex Sans',sans-serif;outline:none;transition:border .2s}
input:focus{border-color:rgba(79,156,249,.45)}
.eye{position:absolute;right:11px;top:50%;transform:translateY(-50%);
     cursor:pointer;color:#4a5163;background:none;border:none;padding:2px;
     display:flex;align-items:center;transition:color .15s}
.eye:hover{color:#7b8394}
.btn{width:100%;padding:10px;border-radius:6px;border:none;background:#4f9cf9;
     color:#fff;font-size:13px;font-family:'IBM Plex Sans',sans-serif;
     font-weight:500;cursor:pointer;transition:background .15s;letter-spacing:.02em}
.btn:hover:not(:disabled){background:#3d8de8}
.btn:disabled{background:#1a2030;color:#4a5163;cursor:not-allowed}
.err{margin-top:14px;font-size:12px;color:#f05454;text-align:center;
     background:rgba(240,84,84,.1);padding:8px 12px;border-radius:5px;
     border:1px solid rgba(240,84,84,.2);display:none}
</style>
</head>
<body>
<div class="wrap">
  <div class="logo">
    <div class="logo-box">
      <svg viewBox="0 0 24 24" fill="none" width="18" height="18">
        <ellipse cx="12" cy="12" rx="10" ry="7" stroke="white" stroke-width="1.8" stroke-opacity=".9"/>
        <circle cx="12" cy="12" r="3" fill="white" fill-opacity=".9"/>
        <circle cx="12" cy="12" r="1.2" fill="white" fill-opacity=".4"/>
      </svg>
    </div>
    <span class="logo-name">HEIMDALL</span>
    <span class="logo-tag">IDS DASHBOARD</span>
  </div>
  <div class="card">
    <div class="card-title">Sign in</div>
    <div class="card-sub">Enter your password to access the dashboard</div>
    <label for="pw">Password</label>
    <div class="input-wrap">
      <input type="password" id="pw" placeholder="••••••••••••"
             autofocus onkeydown="if(event.key==='Enter')login()">
      <button class="eye" onclick="togglePw()" tabindex="-1">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="1.5">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
          <circle cx="12" cy="12" r="3"/>
        </svg>
      </button>
    </div>
    <button class="btn" id="btn" onclick="login()">Sign in</button>
    <div class="err" id="err"></div>
  </div>
</div>
<script>
function togglePw(){const i=document.getElementById('pw');i.type=i.type==='password'?'text':'password';}
async function login(){
  const pw=document.getElementById('pw').value;
  const btn=document.getElementById('btn');
  const err=document.getElementById('err');
  if(!pw){document.getElementById('pw').focus();return;}
  btn.disabled=true;btn.textContent='Signing in…';err.style.display='none';
  try{
    const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:pw})});
    const d=await r.json();
    if(r.ok&&d.ok){window.location.href='/';return;}
    err.textContent=d.error||'Invalid password';err.style.display='block';
    document.getElementById('pw').value='';document.getElementById('pw').focus();
  }catch(e){err.textContent='Connection error';err.style.display='block';}
  btn.disabled=false;btn.textContent='Sign in';
}
</script>
</body>
</html>"""

# ── Main ──────────────────────────────────────────────────────────────────────

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

def main():
    parser = argparse.ArgumentParser(description="Heimdall IDS Dashboard (v1 - alerts)")
    parser.add_argument("--eve",         default=DEFAULT_EVE)
    parser.add_argument("--port",        default=DEFAULT_PORT, type=int)
    parser.add_argument("--host",        default=DEFAULT_HOST)
    parser.add_argument("--db",          default=str(DEFAULT_DB))
    parser.add_argument("--retain-days", default=RETAIN_DAYS, type=int)
    parser.add_argument("--password",    default=None,
                        help="Set or change the dashboard password")
    args = parser.parse_args()

    global db, auth
    db   = AlertDB(path=args.db, retain_days=args.retain_days)
    auth = AuthManager(conn_fn=db._conn)

    if args.password:
        auth.set_password(args.password)
        log.info("Password set. Restart without --password to run.")
        return

    if not auth.get_hash():
        pw = secrets.token_urlsafe(14)
        auth.set_password(pw)
        log.info("=" * 58)
        log.info("  No password set — generated one:")
        log.info("  PASSWORD: %s", pw)
        log.info("  Change:   python3 server.py --password <new>")
        log.info("=" * 58)

    s = db.stats()
    log.info("DB: %d total, %d in last %d days, oldest: %s",
             s["total"], s["recent"], args.retain_days, s["oldest"] or "none")

    threading.Thread(target=tail_thread, args=(args.eve,), daemon=True).start()
    threading.Thread(target=purge_thread, daemon=True).start()

    srv = ThreadedHTTPServer((args.host, args.port), Handler)
    srv.allow_reuse_address = True

    log.info("Login      →  http://localhost:%d/login",  args.port)
    log.info("Dashboard  →  http://localhost:%d/",       args.port)
    log.info("Health     →  http://localhost:%d/health", args.port)
    log.info("Ready.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down.")
        srv.server_close()

if __name__ == "__main__":
    main()
