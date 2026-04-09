"""
Heimdall IDS Dashboard — HTTP Request Handler
Handles all HTTP routes: login, logout, dashboard, SSE, REST API.
"""

import json
import logging
import time
from http.cookies import SimpleCookie
from http.server   import BaseHTTPRequestHandler
from pathlib       import Path
from queue         import Empty
from urllib.parse  import urlparse, parse_qs

from config import FRONTEND_DIR, PING_EVERY, RETAIN_DAYS, SESSION_TTL

log = logging.getLogger("heimdall.http")


class Handler(BaseHTTPRequestHandler):
    """
    Single handler class wired to the ThreadedHTTPServer.
    Dependencies (db, auth, registry) are injected as class attributes
    by server.py before the server starts.

    Routes
    ------
    GET  /              → serve frontend/index.html
    GET  /login         → serve frontend/login.html
    POST /login         → verify password, set session cookie
    GET  /logout        → revoke session, redirect to /login
    GET  /events        → SSE stream (requires auth)
    GET  /alerts        → JSON alert history (requires auth)
    DELETE /alerts      → wipe database (requires auth)
    GET  /health        → JSON status (requires auth)
    GET  /frontend/*    → static files: JS, CSS (requires auth)
    """

    # Injected by server.py
    db       = None
    auth     = None
    registry = None

    # Suppress Python's default "Server: BaseHTTP/x Python/x" header
    # which triggers Suricata SID 2034635.
    server_version = ""
    sys_version    = ""

    # ── Logging ───────────────────────────────────────────────────────────────

    def log_message(self, fmt, *args):
        first = str(args[0]) if args else ""
        # Suppress per-request noise for long-lived SSE connections
        if "/events" not in first:
            log.info("%s %s", self.address_string(), fmt % args)

    # ── Session helpers ───────────────────────────────────────────────────────

    def _token(self) -> str:
        """Extract session token from the Cookie header."""
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        try:
            c = SimpleCookie(raw)
            m = c.get("suri_session")
            return m.value if m else ""
        except Exception:
            return ""

    def _authed(self) -> bool:
        return self.auth.validate_session(self._token())

    # Files under /frontend/ that must be publicly accessible
    # (needed by the login page before any session exists)
    _PUBLIC_FRONTEND = {"/frontend/login.js"}

    def _require_auth(self) -> bool:
        """
        Return True if the request is authenticated.
        Otherwise send a 401 (for API/SSE paths) or a 302 redirect to /login,
        then return False so the caller can return immediately.
        """
        if self._authed():
            return True
        p = urlparse(self.path).path
        api_paths = ("/alerts", "/events", "/health")
        if p.startswith("/frontend/") and p not in self._PUBLIC_FRONTEND:
            self._json({"error": "Unauthorized"}, 401)
        elif any(p.startswith(x) for x in api_paths):
            self._json({"error": "Unauthorized"}, 401)
        else:
            self._redirect("/login")
        return False

    # ── Low-level response helpers ────────────────────────────────────────────

    def _redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path, content_type: str, no_cache: bool = True):
        if not path.exists():
            self.send_error(404, f"{path.name} not found")
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if no_cache:
            self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _qs_int(self, qs: dict, key: str, default: int,
                lo: int = 1, hi: int = 20000) -> int:
        try:
            return max(lo, min(int(qs.get(key, [default])[0]), hi))
        except (ValueError, TypeError):
            return default

    # ── Routing ───────────────────────────────────────────────────────────────

    def do_GET(self):
        p  = urlparse(self.path)
        qs = parse_qs(p.query)

        if p.path == "/login":
            self._file(FRONTEND_DIR / "login.html", "text/html; charset=utf-8")
            return
        if p.path == "/frontend/login.js":
            self._file(FRONTEND_DIR / "login.js", "application/javascript")
            return
        if p.path == "/logout":
            self._logout()
            return

        if not self._require_auth():
            return

        # Authenticated routes
        if p.path in ("/", "/index.html"):
            self._file(FRONTEND_DIR / "index.html", "text/html; charset=utf-8")
        elif p.path == "/events":
            self._sse()
        elif p.path == "/alerts":
            self._serve_alerts(qs)
        elif p.path == "/health":
            self._json({
                "status":  "ok",
                "clients": self.registry.count(),
                "db":      self.db.stats(),
                "time":    int(time.time()),
            })
        elif p.path.startswith("/frontend/"):
            self._serve_static(p.path)
        else:
            self.send_error(404)

    def do_POST(self):
        p = urlparse(self.path)
        if p.path == "/login":
            self._do_login()
        else:
            self.send_error(404)

    def do_DELETE(self):
        if not self._require_auth():
            return
        p = urlparse(self.path)
        if p.path == "/alerts":
            self._json({"deleted": self.db.clear_all()})
        else:
            self.send_error(404)

    # ── Static files ──────────────────────────────────────────────────────────

    _MIME = {
        ".html": "text/html; charset=utf-8",
        ".js":   "application/javascript",
        ".jsx":  "application/javascript",
        ".css":  "text/css",
        ".ico":  "image/x-icon",
    }

    def _serve_static(self, url_path: str):
        """Serve files from the frontend/ directory."""
        # Strip leading /frontend/ and resolve safely inside FRONTEND_DIR
        rel = url_path.lstrip("/").removeprefix("frontend/")
        target = (FRONTEND_DIR / rel).resolve()

        # Security: prevent directory traversal
        try:
            target.relative_to(FRONTEND_DIR.resolve())
        except ValueError:
            self.send_error(403)
            return

        suffix  = target.suffix.lower()
        ctype   = self._MIME.get(suffix, "application/octet-stream")
        no_cache = suffix in (".html", ".jsx")
        self._file(target, ctype, no_cache=no_cache)

    # ── Login / logout ────────────────────────────────────────────────────────

    def _do_login(self):
        try:
            n    = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n))
            pw   = body.get("password", "")
        except Exception:
            self._json({"error": "Bad request"}, 400)
            return

        if self.auth.check_password(pw):
            token = self.auth.create_session()
            log.info("Login OK from %s", self.address_string())
            body_bytes = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "Set-Cookie",
                f"suri_session={token}; Path=/; HttpOnly; "
                f"SameSite=Strict; Max-Age={SESSION_TTL}",
            )
            self.send_header("Content-Length", str(len(body_bytes)))
            self.end_headers()
            self.wfile.write(body_bytes)
        else:
            log.warning("Failed login from %s", self.address_string())
            time.sleep(1)   # slow brute-force attempts
            self._json({"error": "Invalid password"}, 401)

    def _logout(self):
        self.auth.revoke_session(self._token())
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header(
            "Set-Cookie",
            "suri_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        )
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ── Data endpoints ────────────────────────────────────────────────────────

    def _serve_alerts(self, qs: dict):
        days  = self._qs_int(qs, "days",  RETAIN_DAYS, 1, RETAIN_DAYS)
        limit = self._qs_int(qs, "limit", 5000,         1, 20000)
        body  = json.dumps(self.db.fetch_recent(days=days, limit=limit)).encode()
        self.send_response(200)
        self.send_header("Content-Type",  "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _sse(self):
        """Long-lived SSE response — blocks until client disconnects."""
        self.send_response(200)
        self.send_header("Content-Type",      "text/event-stream")
        self.send_header("Cache-Control",     "no-cache")
        self.send_header("Connection",        "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        cid, q = self.registry.add()

        # Immediate ping so the browser confirms the connection is alive
        try:
            self.wfile.write(
                f"event: ping\ndata: {int(time.time())}\n\n".encode()
            )
            self.wfile.flush()
        except Exception:
            self.registry.remove(cid)
            return

        # Drain queue, sending alerts and keep-alive pings
        while True:
            try:
                msg = q.get(timeout=PING_EVERY)
            except Empty:
                msg = f"event: ping\ndata: {int(time.time())}\n\n"
            try:
                self.wfile.write(msg.encode())
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                break

        self.registry.remove(cid)
