#!/usr/bin/env python3
"""
Suricata Live Dashboard  Zero-dependency SSE server + SQLite persistence
Uses only Python stdlib. No pip install needed.

Usage:
    python3 server.py
    python3 server.py --eve /var/log/suricata/eve.json --port 8765
    python3 server.py --db /var/lib/suricata/alerts.db --retain-days 60
"""

import argparse
import json
import logging
import os
import socketserver
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from queue import Empty, Queue
from urllib.parse import urlparse, parse_qs

DEFAULT_EVE     = "/var/log/suricata/eve.json"
DEFAULT_PORT    = 8765
DEFAULT_HOST    = "0.0.0.0"
DEFAULT_DB      = Path(__file__).parent / "alerts.db"
RETAIN_DAYS     = 90
PING_EVERY      = 10
PURGE_EVERY     = 3600

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("suricata")

# ── Database ──────────────────────────────────────────────────────────────────

class AlertDB:
    """Thread-safe SQLite store. Each thread gets its own connection via threading.local."""

    def __init__(self, path, retain_days=RETAIN_DAYS):
        self.path = str(path)
        self.retain_days = retain_days
        self._local = threading.local()
        self._conn()  # create schema now on main thread
        log.info("Database: %s  (retain %d days)", self.path, self.retain_days)

    def _conn(self):
        if not hasattr(self._local, "conn"):
            c = sqlite3.connect(self.path, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("""CREATE TABLE IF NOT EXISTS alerts (
                id        TEXT PRIMARY KEY,
                ts        TEXT NOT NULL,
                ts_epoch  REAL NOT NULL,
                src_ip    TEXT, src_port  INTEGER,
                dst_ip    TEXT, dst_port  INTEGER,
                proto     TEXT, iface     TEXT,
                flow_id   INTEGER,
                sig_id    INTEGER, sig_msg TEXT,
                category  TEXT, severity  TEXT,
                action    TEXT, raw_json  TEXT)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_ts  ON alerts(ts_epoch)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_sev ON alerts(severity)")
            c.commit()
            self._local.conn = c
        return self._local.conn

    def _epoch(self, ts_str):
        from datetime import datetime
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(ts_str, fmt).timestamp()
            except ValueError:
                pass
        return time.time()

    def insert(self, a):
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
            log.warning("DB insert: %s", e)

    def fetch_recent(self, days=None, limit=5000):
        cutoff = time.time() - (days or self.retain_days) * 86400
        rows = self._conn().execute("""
            SELECT id,ts,src_ip,src_port,dst_ip,dst_port,proto,iface,
                   flow_id,sig_id,sig_msg,category,severity,action,raw_json
            FROM alerts WHERE ts_epoch>=? ORDER BY ts_epoch DESC LIMIT ?""",
            (cutoff, limit)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["raw"] = json.loads(d.pop("raw_json", "{}"))
            except Exception:
                d["raw"] = {}
            out.append(d)
        return out

    def purge_old(self):
        cutoff = time.time() - self.retain_days * 86400
        cur = self._conn().execute("DELETE FROM alerts WHERE ts_epoch<?", (cutoff,))
        self._conn().commit()
        if cur.rowcount:
            log.info("Purged %d alerts older than %d days", cur.rowcount, self.retain_days)

    def clear_all(self):
        """Delete every alert from the database."""
        cur = self._conn().execute("DELETE FROM alerts")
        self._conn().commit()
        log.info("Database cleared — %d alerts deleted", cur.rowcount)
        return cur.rowcount

    def stats(self):
        c = self._conn()
        total  = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        cutoff = time.time() - self.retain_days * 86400
        recent = c.execute("SELECT COUNT(*) FROM alerts WHERE ts_epoch>=?", (cutoff,)).fetchone()[0]
        oldest = c.execute("SELECT MIN(ts) FROM alerts").fetchone()[0]
        return {"total": total, "recent": recent, "oldest": oldest}

db: AlertDB = None  # initialised in main()

# ── Client registry ───────────────────────────────────────────────────────────

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

    def broadcast(self, payload):
        msg = f"event: alert\ndata: {json.dumps(payload)}\n\n"
        with self._lock:
            dead = []
            for cid, q in self._clients.items():
                try: q.put_nowait(msg)
                except Exception: dead.append(cid)
            for cid in dead: self._clients.pop(cid, None)

    def count(self):
        with self._lock: return len(self._clients)

registry = Registry()

# ── EVE parsing ───────────────────────────────────────────────────────────────

def map_severity(n):
    return {1: "critical", 2: "high", 3: "medium", 4: "low"}.get(n, "info")

def parse_line(raw):
    raw = raw.strip()
    if not raw: return None
    try: evt = json.loads(raw)
    except Exception: return None
    if evt.get("event_type") != "alert": return None
    a = evt.get("alert", {})
    return {
        "id":       f"{evt.get('flow_id',0)}-{int(time.time()*1000)}",
        "ts":       evt.get("timestamp", ""),
        "src_ip":   evt.get("src_ip", ""),
        "src_port": evt.get("src_port", 0),
        "dst_ip":   evt.get("dest_ip", ""),
        "dst_port": evt.get("dest_port", 0),
        "proto":    evt.get("proto", "TCP").upper(),
        "iface":    evt.get("in_iface", ""),
        "flow_id":  evt.get("flow_id", 0),
        "sig_id":   a.get("signature_id", 0),
        "sig_msg":  a.get("signature", ""),
        "category": a.get("category", ""),
        "severity": map_severity(a.get("severity")),
        "action":   a.get("action", "allowed"),
        "raw":      evt,
    }

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
                        alert = parse_line(line)
                        if alert:
                            db.insert(alert)
                            registry.broadcast(alert)
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

# ── HTTP handler ──────────────────────────────────────────────────────────────

DASHBOARD_PATH = Path(__file__).parent / "suricata-dashboard.html"

class Handler(BaseHTTPRequestHandler):

    # Suppress "Server: BaseHTTP/x Python/x" banner that triggers Suricata SID 2034635
    server_version = ""
    sys_version    = ""

    def log_message(self, fmt, *args):
        first = str(args[0]) if args else ""
        if "/events" not in first:
            log.info("%s %s", self.address_string(), fmt % args)

    def do_GET(self):
        p  = urlparse(self.path)
        qs = parse_qs(p.query)
        if p.path in ("/", "/index.html"):
            self._serve_file(DASHBOARD_PATH, "text/html; charset=utf-8")
        elif p.path == "/events":
            self._serve_sse()
        elif p.path == "/alerts":
            self._serve_alerts(qs)
        elif p.path == "/health":
            self._serve_health()
        else:
            self.send_error(404)

    def do_DELETE(self):
        p = urlparse(self.path)
        if p.path == "/alerts":
            self._clear_alerts()
        else:
            self.send_error(404)

    def _serve_file(self, path, ctype):
        if not path.exists():
            self.send_error(404, f"{path.name} not found"); return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _serve_alerts(self, qs):
        """GET /alerts?days=7&limit=2000  — returns stored alerts as JSON array."""
        try:
            days  = int(qs.get("days",  [RETAIN_DAYS])[0])
            limit = int(qs.get("limit", [5000])[0])
            days  = max(1, min(days, RETAIN_DAYS))
            limit = max(1, min(limit, 20000))
        except Exception:
            days, limit = RETAIN_DAYS, 5000
        alerts = db.fetch_recent(days=days, limit=limit)
        body   = json.dumps(alerts).encode()
        self.send_response(200)
        self.send_header("Content-Type",                "application/json")
        self.send_header("Content-Length",              str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control",               "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _serve_health(self):
        body = json.dumps({
            "status": "ok", "clients": registry.count(),
            "db": db.stats(), "time": int(time.time())
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _clear_alerts(self):
        """DELETE /alerts  wipes entire database."""
        deleted = db.clear_all()
        body = json.dumps({"deleted": deleted}).encode()
        self.send_response(200)
        self.send_header("Content-Type",                "application/json")
        self.send_header("Content-Length",              str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _serve_sse(self):
        self.send_response(200)
        self.send_header("Content-Type",                "text/event-stream")
        self.send_header("Cache-Control",               "no-cache")
        self.send_header("Connection",                  "keep-alive")
        self.send_header("X-Accel-Buffering",           "no")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        cid, q = registry.add()
        try:
            self.wfile.write(f"event: ping\ndata: {int(time.time())}\n\n".encode())
            self.wfile.flush()
        except Exception:
            registry.remove(cid); return

        while True:
            try: msg = q.get(timeout=PING_EVERY)
            except Empty: msg = f"event: ping\ndata: {int(time.time())}\n\n"
            try:
                self.wfile.write(msg.encode())
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                break
        registry.remove(cid)

# ── Main ──────────────────────────────────────────────────────────────────────

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

def main():
    parser = argparse.ArgumentParser(description="Suricata dashboard backend")
    parser.add_argument("--eve",          default=DEFAULT_EVE)
    parser.add_argument("--port",         default=DEFAULT_PORT, type=int)
    parser.add_argument("--host",         default=DEFAULT_HOST)
    parser.add_argument("--db",           default=str(DEFAULT_DB))
    parser.add_argument("--retain-days",  default=RETAIN_DAYS, type=int,
                        help="Days to keep alerts in DB (default: 60)")
    args = parser.parse_args()

    global db
    db = AlertDB(path=args.db, retain_days=args.retain_days)
    s  = db.stats()
    log.info("DB: %d total alerts, %d in last %d days, oldest: %s",
             s["total"], s["recent"], args.retain_days, s["oldest"] or "none")

    threading.Thread(target=tail_thread, args=(args.eve,), daemon=True).start()
    threading.Thread(target=purge_thread, daemon=True).start()

    srv = ThreadedHTTPServer((args.host, args.port), Handler)
    srv.allow_reuse_address = True

    log.info("Dashboard  →  http://localhost:%d/",       args.port)
    log.info("History    →  http://localhost:%d/alerts", args.port)
    log.info("Health     →  http://localhost:%d/health", args.port)
    log.info("Ready.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down.")
        srv.server_close()

if __name__ == "__main__":
    main()
