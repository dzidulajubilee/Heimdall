"""
Heimdall IDS Dashboard — HTTP Request Handler
"""

import json
import logging
import time
from http.cookies import SimpleCookie
from http.server   import BaseHTTPRequestHandler
from pathlib       import Path
from queue         import Empty
from urllib.parse  import urlparse, parse_qs, unquote

from config import FRONTEND_DIR, PING_EVERY, RETAIN_DAYS, SESSION_TTL

log = logging.getLogger("heimdall.http")

VALID_STATUSES  = {"acknowledged", "investigating", "closed"}
_MAX_DELETE_IDS = 500   # mirrors database._MAX_DELETE_IDS


class Handler(BaseHTTPRequestHandler):

    db       = None
    auth     = None
    registry = None
    wdb      = None
    um       = None

    server_version = ""
    sys_version    = ""

    def log_message(self, fmt, *args):
        first = str(args[0]) if args else ""
        if "/events" not in first:
            log.info("%s %s", self.address_string(), fmt % args)

    # ── Session helpers ───────────────────────────────────────────────────────

    def _token(self) -> str:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        try:
            c = SimpleCookie(raw)
            m = c.get("suri_session")
            return m.value if m else ""
        except Exception:
            return ""

    def _session(self) -> dict | None:
        return self.auth.get_session(self._token())

    def _authed(self) -> bool:
        return self._session() is not None

    def _role(self) -> str:
        s = self._session()
        return s["role"] if s else ""

    def _username(self) -> str:
        s = self._session()
        return s["username"] if s else "anonymous"

    def _require_role(self, *roles: str) -> bool:
        if not self._authed():
            self._json({"error": "Unauthorized"}, 401)
            return False
        if roles and self._role() not in roles:
            self._json({"error": "Forbidden", "role": self._role()}, 403)
            return False
        return True

    _PUBLIC_FRONTEND = {"/frontend/login.js"}

    def _require_auth(self) -> bool:
        if self._authed():
            return True
        p = urlparse(self.path).path
        api_paths = ("/alerts", "/flows", "/dns", "/http", "/events",
                     "/health", "/charts", "/webhooks", "/users", "/me")
        if p.startswith("/frontend/") and p not in self._PUBLIC_FRONTEND:
            self._json({"error": "Unauthorized"}, 401)
        elif any(p.startswith(x) for x in api_paths):
            self._json({"error": "Unauthorized"}, 401)
        else:
            self._redirect("/login")
        return False

    # ── Low-level helpers ─────────────────────────────────────────────────────

    def _redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _json(self, data, status: int = 200):
        """Send a JSON response. Used for small API replies and error responses."""
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json_body(self, data):
        """
        Send a JSON response with Cache-Control: no-cache.
        Used for all data endpoints (_serve_alerts, _serve_table, _serve_charts)
        to avoid duplicating the encode / set-headers / write pattern.
        Always responds with HTTP 200.
        """
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control",  "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path, content_type: str, no_cache: bool = True):
        if not path.exists():
            self.send_error(404, f"{path.name} not found")
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type",   content_type)
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

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n)), None
        except Exception:
            self._json({"error": "Bad request"}, 400)
            return None, True

    def _alert_id_from_path(self, path: str, suffix: str):
        prefix = "/alerts/"
        tail   = "/" + suffix
        if path.startswith(prefix) and path.endswith(tail):
            return unquote(path[len(prefix):-len(tail)])
        return None

    # ── Routing ───────────────────────────────────────────────────────────────

    def do_GET(self):
        p  = urlparse(self.path)
        qs = parse_qs(p.query)

        if p.path == "/login":
            self._file(FRONTEND_DIR / "login.html", "text/html; charset=utf-8"); return
        if p.path == "/frontend/login.js":
            self._file(FRONTEND_DIR / "login.js", "application/javascript"); return
        if p.path == "/logout":
            self._logout(); return

        if not self._require_auth():
            return

        if p.path in ("/", "/index.html"):
            self._file(FRONTEND_DIR / "index.html", "text/html; charset=utf-8")
        elif p.path == "/events":
            self._serve_sse()
        elif p.path == "/alerts":
            self._serve_alerts(qs)
        elif p.path.startswith("/alerts/"):
            aid = self._alert_id_from_path(p.path, "meta")
            if aid:
                self._json(self.db.get_alert_meta(aid))
            else:
                self.send_error(404)
        elif p.path == "/flows":
            self._serve_table("flows", qs)
        elif p.path == "/dns":
            self._serve_table("dns", qs)
        elif p.path == "/http":
            self._serve_table("http", qs)
        elif p.path == "/charts":
            self._serve_charts(qs)
        elif p.path == "/webhooks":
            self._json({"webhooks": self.wdb.get_all()})
        elif p.path == "/me":
            s = self._session()
            self._json({"username": s["username"], "role": s["role"]})
        elif p.path == "/users":
            if not self._require_role("admin"): return
            self._json({"users": self.um.get_all()})
        elif p.path == "/health":
            s = self.db.stats()
            s["dns"] = {"total": self.dns_db.count(), "recent": self.dns_db.count_recent()}
            self._json({"status": "ok", "clients": self.registry.count(),
                        "db": s, "time": int(time.time())})
        elif p.path == "/skin":
            self._get_skin()
        elif p.path.startswith("/frontend/"):
            self._serve_static(p.path)
        else:
            self.send_error(404)

    def do_POST(self):
        p = urlparse(self.path)
        if p.path == "/login":
            self._do_login(); return
        if not self._require_auth():
            return

        if p.path == "/users":
            self._user_create()
        elif p.path == "/skin":
            self._set_skin()
        elif p.path == "/webhooks":
            self._webhook_create()
        elif p.path == "/alerts/bulk-status":
            self._bulk_alert_status()
        elif p.path == "/alerts/delete-selected":
            self._delete_selected_alerts()
        elif p.path.startswith("/alerts/"):
            aid_s = self._alert_id_from_path(p.path, "status")
            aid_n = self._alert_id_from_path(p.path, "notes")
            if aid_s:
                self._set_alert_status(aid_s)
            elif aid_n:
                self._add_alert_note(aid_n)
            else:
                self.send_error(404)
        elif p.path.startswith("/webhooks/") and p.path.endswith("/test"):
            try:
                wid = int(p.path.split("/")[2])
                self._webhook_test(wid)
            except (ValueError, IndexError):
                self.send_error(400)
        else:
            self.send_error(404)

    def do_PUT(self):
        if not self._require_auth(): return
        p = urlparse(self.path)
        if p.path.startswith("/users/"):
            try:   self._user_update(int(p.path.split("/")[2]))
            except (ValueError, IndexError): self.send_error(400)
        elif p.path.startswith("/webhooks/"):
            try:   self._webhook_update(int(p.path.split("/")[2]))
            except (ValueError, IndexError): self.send_error(400)
        else:
            self.send_error(404)

    def do_DELETE(self):
        if not self._require_auth(): return
        p = urlparse(self.path)
        if p.path == "/alerts":
            if not self._require_role("admin"): return
            self._json({"deleted": self.db.clear_all()})
        elif p.path == "/flows":
            if not self._require_role("admin"): return
            self._json({"deleted": self.db.clear_flows()})
        elif p.path == "/dns":
            if not self._require_role("admin"): return
            self._json({"deleted": self.dns_db.clear()})
        elif p.path.startswith("/users/"):
            try:   self._user_delete(int(p.path.split("/")[2]))
            except (ValueError, IndexError): self.send_error(400)
        elif p.path.startswith("/webhooks/"):
            try:
                wid = int(p.path.split("/")[2])
                self.wdb.delete(wid)
                self._json({"deleted": wid})
            except (ValueError, IndexError): self.send_error(400)
        else:
            self.send_error(404)

    # ── Static files ──────────────────────────────────────────────────────────

    _MIME = {
        ".html":  "text/html; charset=utf-8",
        ".js":    "application/javascript",
        ".jsx":   "application/javascript",
        ".css":   "text/css",
        ".ico":   "image/x-icon",
        ".woff2": "font/woff2",
        ".woff":  "font/woff",
    }

    def _serve_static(self, url_path: str):
        rel    = url_path.lstrip("/").removeprefix("frontend/")
        target = (FRONTEND_DIR / rel).resolve()
        try:
            target.relative_to(FRONTEND_DIR.resolve())
        except ValueError:
            self.send_error(403); return
        suffix = target.suffix.lower()
        ctype  = self._MIME.get(suffix, "application/octet-stream")
        # Fonts are immutable — cache aggressively; HTML/JSX never cache
        if suffix in (".woff2", ".woff"):
            self._file(target, ctype, cache_forever=True)
        else:
            self._file(target, ctype, no_cache=suffix in (".html", ".jsx"))

    # ── Auth ─────────────────────────────────────────────────────────────────

    def _do_login(self):
        body, err = self._read_json()
        if err: return
        username = body.get("username", "").strip()
        pw       = body.get("password", "")

        user = self.um.authenticate(username, pw) if username else None
        if user is None and not username and self.auth.check_password(pw):
            user = {"username": "admin", "role": "admin"}
        if user is None and username.lower() == "admin" and self.auth.check_password(pw):
            user = {"username": "admin", "role": "admin"}

        if user:
            token = self.auth.create_session(username=user["username"], role=user["role"])
            log.info("Login OK  user=%s role=%s from %s",
                     user["username"], user["role"], self.address_string())
            resp = json.dumps({"ok": True, "role": user["role"],
                               "username": user["username"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie",
                f"suri_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            log.warning("Failed login  user=%r from %s",
                        username or "(no username)", self.address_string())
            time.sleep(1)
            self._json({"error": "Invalid username or password"}, 401)

    def _logout(self):
        self.auth.revoke_session(self._token())
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header("Set-Cookie",
            "suri_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ── Alert endpoints ───────────────────────────────────────────────────────

    def _serve_alerts(self, qs: dict):
        days  = self._qs_int(qs, "days",  RETAIN_DAYS, 1, RETAIN_DAYS)
        limit = self._qs_int(qs, "limit", 5000,         1, 20000)
        self._send_json_body({"alerts": self.db.fetch_recent(days=days, limit=limit)})

    def _set_alert_status(self, alert_id: str):
        if not self._require_role("admin", "analyst"): return
        body, err = self._read_json()
        if err: return
        status = body.get("status")
        if status is not None and status not in VALID_STATUSES:
            self._json({"error": f"status must be one of {sorted(VALID_STATUSES)} or null"}, 400)
            return
        self.db.set_alert_status(alert_id, status, self._username())
        self._json({"ok": True, "status": status})

    def _bulk_alert_status(self):
        if not self._require_role("admin", "analyst"): return
        body, err = self._read_json()
        if err: return
        alert_ids = body.get("alert_ids", [])
        status    = body.get("status")
        if not isinstance(alert_ids, list) or not alert_ids:
            self._json({"error": "alert_ids (list) is required"}, 400); return
        if status not in VALID_STATUSES:
            self._json({"error": f"status must be one of {sorted(VALID_STATUSES)}"}, 400); return
        self.db.bulk_set_status(alert_ids, status, self._username())
        self._json({"ok": True, "count": len(alert_ids), "status": status})

    def _delete_selected_alerts(self):
        """
        POST /alerts/delete-selected
        Body: {"ids": ["id1", "id2", ...]}
        Admin only. Permanently removes alerts and their audit history.
        Enforces a 500-ID cap and validates that all IDs are strings.
        """
        if not self._require_role("admin"): return
        body, err = self._read_json()
        if err: return

        ids = body.get("ids", [])
        if not isinstance(ids, list) or not ids:
            self._json({"error": "ids (non-empty list) is required"}, 400); return

        # Reject non-string IDs — catch accidental integer IDs from the client
        if not all(isinstance(i, str) for i in ids):
            self._json({"error": "all ids must be strings"}, 400); return

        # Enforce cap before hitting the database layer
        if len(ids) > _MAX_DELETE_IDS:
            self._json({
                "error": f"maximum {_MAX_DELETE_IDS} ids per request"
            }, 400); return

        deleted = self.db.delete_by_ids(ids)
        self._json({"deleted": deleted})

    def _add_alert_note(self, alert_id: str):
        if not self._require_role("admin", "analyst"): return
        body, err = self._read_json()
        if err: return
        note = str(body.get("note", "")).strip()
        if not note:
            self._json({"error": "note cannot be empty"}, 400); return
        self._json(self.db.add_note(alert_id, self._username(), note), 201)

    # ── Table endpoints ───────────────────────────────────────────────────────

    def _serve_table(self, table: str, qs: dict):
        days  = self._qs_int(qs, "days",  RETAIN_DAYS, 1, RETAIN_DAYS)
        limit = self._qs_int(qs, "limit", 5000,         1, 20000)
        fetch = {
            "flows": self.db.fetch_flows,
            "dns":   self.dns_db.fetch,
            "http":  self.db.fetch_http,
        }.get(table)
        if fetch is None:
            self.send_error(404); return
        self._send_json_body({table: fetch(days=days, limit=limit)})

    def _serve_charts(self, qs: dict):
        trend_window = self._qs_int(qs, "trend", 24, 24, 2160)
        days_window  = max(1, trend_window // 24)
        data = {
            "top_talkers": self.db.chart_top_talkers(limit=10, days=days_window),
            "trend":       (self.db.chart_alert_trend(hours=trend_window)
                            if trend_window <= 24
                            else self.db.chart_alert_trend_days(days=days_window)),
            "by_category": self.db.chart_by_category(days=days_window),
            "by_severity": self.db.chart_by_severity(days=days_window),
            "window_hours": trend_window,
            "window_days":  days_window,
        }
        self._send_json_body(data)

    # ── Webhooks ─────────────────────────────────────────────────────────────

    def _webhook_create(self):
        body, err = self._read_json()
        if err: return
        name       = str(body.get("name", "")).strip()
        wtype      = str(body.get("type", "generic")).strip()
        url        = str(body.get("url", "")).strip()
        severities = body.get("severities", ["critical", "high", "medium", "low", "info"])
        enabled    = bool(body.get("enabled", True))
        if not name or not url:
            self._json({"error": "name and url are required"}, 400); return
        if wtype not in ("slack", "discord", "generic"):
            self._json({"error": "type must be slack, discord, or generic"}, 400); return
        self._json(self.wdb.create(name, wtype, url, severities, enabled), 201)

    def _webhook_update(self, wid: int):
        if not self.wdb.get(wid):
            self._json({"error": "Not found"}, 404); return
        body, err = self._read_json()
        if err: return
        self._json(self.wdb.update(wid, **body))

    def _webhook_test(self, wid: int):
        wh = self.wdb.get(wid)
        if not wh:
            self._json({"error": "Not found"}, 404); return
        from webhooks import build_payload, deliver
        test_alert = {
            "id": "test-0", "ts": "2026-01-01T00:00:00+0000",
            "src_ip": "10.0.0.1", "src_port": 12345,
            "dst_ip": "8.8.8.8",  "dst_port": 443, "proto": "TCP",
            "iface": "eth0", "flow_id": 0, "sig_id": 9999999,
            "sig_msg": "Heimdall Test Alert", "category": "Test",
            "severity": "medium", "action": "allowed",
        }
        error = deliver(wh["url"], build_payload(wh["type"], test_alert))
        self._json({"ok": error is None, "error": error})

    # ── Users ─────────────────────────────────────────────────────────────────

    def _user_create(self):
        if not self._require_role("admin"): return
        body, err = self._read_json()
        if err: return
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", "")).strip()
        role     = str(body.get("role", "analyst")).strip()
        if not username or not password:
            self._json({"error": "username and password are required"}, 400); return
        if role not in ("admin", "analyst", "viewer"):
            self._json({"error": "role must be admin, analyst, or viewer"}, 400); return
        user = self.um.create(username, password, role)
        if user is None:
            self._json({"error": f"Username '{username}' already exists"}, 409); return
        self._json(user, 201)

    def _user_update(self, uid: int):
        if not self._require_role("admin"): return
        user = self.um.get_by_id(uid)
        if not user:
            self._json({"error": "Not found"}, 404); return
        body, err = self._read_json()
        if err: return
        if "password" in body:
            pw = str(body.pop("password", "")).strip()
            if pw: self.um.set_password(uid, pw)
        if body.get("role") and body["role"] != "admin":
            if user["role"] == "admin" and self.um.count_admins() <= 1:
                self._json({"error": "Cannot demote the last admin"}, 400); return
        if body.get("enabled") is not None:
            if not body["enabled"] and user["role"] == "admin":
                if self.um.count_admins() <= 1:
                    self._json({"error": "Cannot disable the last admin"}, 400); return
        updated = self.um.update(uid, **{k: v for k, v in body.items()
                                         if k in ("role", "enabled", "username")})
        self._json(updated)

    def _user_delete(self, uid: int):
        if not self._require_role("admin"): return
        user = self.um.get_by_id(uid)
        if not user:
            self._json({"error": "Not found"}, 404); return
        if user["role"] == "admin" and self.um.count_admins() <= 1:
            self._json({"error": "Cannot delete the last admin"}, 400); return
        s = self._session()
        if s and s["username"].lower() == user["username"].lower():
            self._json({"error": "Cannot delete your own account"}, 400); return
        self.um.delete(uid)
        self._json({"deleted": uid})

    # ── SSE ──────────────────────────────────────────────────────────────────

    def _serve_sse(self):
        self.send_response(200)
        self.send_header("Content-Type",      "text/event-stream")
        self.send_header("Cache-Control",     "no-cache")
        self.send_header("Connection",        "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        cid, q = self.registry.add()
        try:
            self.wfile.write(f"event: ping\ndata: {int(time.time())}\n\n".encode())
            self.wfile.flush()
        except Exception:
            self.registry.remove(cid); return

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

    # ── Skin preference ───────────────────────────────────────────────────────

    _VALID_SKINS = {"original", "chronicles", "mosaic", "seal"}

    def _get_skin(self):
        """GET /skin — return the server-stored skin preference for this session's user."""
        s = self._session()
        username = s["username"] if s else ""
        key = f"skin:{username}" if username else "skin:default"
        row = self.auth._conn().execute(
            "SELECT value FROM auth WHERE key = ?", (key,)
        ).fetchone()
        skin = row[0] if row else "original"
        self._json({"skin": skin})

    def _set_skin(self):
        """POST /skin {skin: id} — persist skin choice server-side (per user)."""
        body, err = self._read_json()
        if err: return
        skin = str(body.get("skin", "original")).strip()
        if skin not in self._VALID_SKINS:
            self._json({"error": f"skin must be one of {sorted(self._VALID_SKINS)}"}, 400)
            return
        s = self._session()
        username = s["username"] if s else ""
        key = f"skin:{username}" if username else "skin:default"
        c = self.auth._conn()
        c.execute(
            "INSERT OR REPLACE INTO auth (key, value) VALUES (?, ?)", (key, skin)
        )
        c.commit()
        self._json({"skin": skin})
