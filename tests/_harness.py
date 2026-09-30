"""
Heimdall IDS — test harness (stdlib only; nothing here ships in the .deb).

Wires the real backend modules together in-process, exactly as server.main()
does, but against throw-away SQLite files and a temp eve.json. Tests talk to
it over real HTTP so the full handler stack (auth, RBAC, CSRF, routing) runs.

Only one Instance may be live at a time: Handler dependencies are class
attributes, just as in production.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT    = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import handlers                                     # noqa: E402
from auth         import AuthManager                # noqa: E402
from config_db    import ConfigDB                   # noqa: E402
from database     import AlertDB                    # noqa: E402
from dns_db       import DNSDB                      # noqa: E402
from handlers     import Handler                    # noqa: E402
from registry     import Registry                   # noqa: E402
from server       import ThreadedHTTPServer         # noqa: E402
from suppression  import SuppressionDB              # noqa: E402
from tail         import tail_thread                # noqa: E402
from threat_intel import ThreatIntelDB              # noqa: E402
from users        import UserManager                # noqa: E402
from webhooks     import WebhookDB                  # noqa: E402
from audit        import AuditLog                   # noqa: E402

try:                                                # absent in the noai build
    from ai_explain import AIExplainDB              # noqa: E402
except ImportError:                                 # pragma: no cover
    AIExplainDB = None

ADMIN_PW = "Admin-Test-Pass-1"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def alert_line(sig_id=2001219, src="203.0.113.5", flow_id=111,
               ts="2026-09-29T10:00:00.000000+0000", msg="ET SCAN test",
               category="Attempted Information Leak", severity=2) -> str:
    return json.dumps({
        "timestamp": ts, "flow_id": flow_id, "in_iface": "eth0",
        "event_type": "alert", "src_ip": src, "src_port": 4444,
        "dest_ip": "10.0.0.8", "dest_port": 22, "proto": "TCP",
        "alert": {"action": "allowed", "signature_id": sig_id,
                  "signature": msg, "category": category,
                  "severity": severity},
    }) + "\n"


def dns_line(rrname="example.com", flow_id=222,
             ts="2026-09-29T10:00:01.000000+0000") -> str:
    return json.dumps({
        "timestamp": ts, "flow_id": flow_id, "in_iface": "eth0",
        "event_type": "dns", "src_ip": "10.0.0.8", "dest_ip": "8.8.8.8",
        "proto": "UDP",
        "dns": {"type": "query", "rrname": rrname, "rrtype": "A", "tx_id": 0},
    }) + "\n"


def flow_line(flow_id=333, ts="2026-09-29T10:00:02.000000+0000") -> str:
    return json.dumps({
        "timestamp": ts, "flow_id": flow_id, "in_iface": "eth0",
        "event_type": "flow", "src_ip": "10.0.0.8", "src_port": 1234,
        "dest_ip": "1.1.1.1", "dest_port": 443, "proto": "TCP",
        "app_proto": "tls",
        "flow": {"pkts_toserver": 5, "pkts_toclient": 4,
                 "bytes_toserver": 500, "bytes_toclient": 400,
                 "start": "2026-09-29T09:59:00.000000+0000",
                 "end":   "2026-09-29T10:00:02.000000+0000",
                 "state": "closed", "reason": "timeout", "alerted": False},
    }) + "\n"


class Response:
    def __init__(self, status, body, headers):
        self.status  = status
        self.body    = body
        self.headers = headers

    def json(self):
        return json.loads(self.body or "null")


class Instance:
    """A live, isolated Heimdall wired in-process."""

    def __init__(self, retain_days: int = 36500, eve_history=()):
        # retain_days is large so fixed 2026 test timestamps never age out.
        # eve_history lines are written BEFORE the tailer starts, so the live
        # tailer skips them (it starts at EOF) and only replay can see them.
        self.dir  = tempfile.mkdtemp(prefix="heimdall-test-")
        self.eve  = os.path.join(self.dir, "eve.json")
        Path(self.eve).write_text("".join(eve_history))

        self.db     = AlertDB(os.path.join(self.dir, "events.db"), retain_days=retain_days)
        self.dns_db = DNSDB(os.path.join(self.dir, "dns.db"), retain_days=retain_days)
        self.cfg_db = ConfigDB(os.path.join(self.dir, "config.db"))
        self.auth   = AuthManager(conn_fn=self.cfg_db._conn)
        self.um     = UserManager(conn_fn=self.cfg_db._conn)
        self.um.create("admin", ADMIN_PW, role="admin")

        self.registry = Registry()
        self.wdb      = WebhookDB(conn_fn=self.cfg_db._conn)
        self.ti_db    = ThreatIntelDB(conn_fn=self.cfg_db._conn)
        self.sup_db   = SuppressionDB(conn_fn=self.cfg_db._conn)
        self.ai_db    = AIExplainDB(conn_fn=self.cfg_db._conn) if AIExplainDB else None
        self.audit    = AuditLog(conn_fn=self.cfg_db._conn)

        Handler.db, Handler.dns_db, Handler.auth = self.db, self.dns_db, self.auth
        Handler.registry, Handler.wdb, Handler.um = self.registry, self.wdb, self.um
        Handler.ti_db, Handler.sup_db, Handler.ai_db = self.ti_db, self.sup_db, self.ai_db
        Handler._eve_path = self.eve
        Handler.audit, Handler._tls = self.audit, False

        threading.Thread(target=tail_thread,
                         args=(self.eve, self.db, self.dns_db, self.registry, self.wdb),
                         kwargs={"sup_db": self.sup_db}, daemon=True).start()

        self.port = free_port()
        self.srv  = ThreadedHTTPServer(("127.0.0.1", self.port), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.port}"
        time.sleep(0.3)   # let the tailer take its starting offset

    # ── HTTP helpers ─────────────────────────────────────────────────────────
    def req(self, method, path, body=None, token=None, headers=None, raw=None):
        data = raw if raw is not None else (
            json.dumps(body).encode() if body is not None else None)
        r = urllib.request.Request(self.base + path, data=data, method=method)
        r.add_header("Content-Type", "application/json")
        if token:
            r.add_header("Cookie", f"suri_session={token}")
        for k, v in (headers or {}).items():
            r.add_header(k, v)
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(r, timeout=30) as resp:
                return Response(resp.status, resp.read().decode(), dict(resp.headers))
        except urllib.error.HTTPError as e:
            return Response(e.code, e.read().decode(), dict(e.headers))

    def login(self, username, password):
        """Returns (status, token-or-None). Clears the per-IP rate limiter."""
        with handlers._LOGIN_LOCK:
            handlers._LOGIN_FAILS.clear()
        r = self.req("POST", "/login", {"username": username, "password": password})
        cookie = r.headers.get("Set-Cookie", "")
        tok = cookie.split("suri_session=")[1].split(";")[0] if "suri_session=" in cookie else None
        return r.status, tok

    def admin(self):
        status, tok = self.login("admin", ADMIN_PW)
        assert status == 200, status
        return tok

    def make_user(self, username, role, password=None):
        password = password or f"{username}-Pass-1"
        r = self.req("POST", "/users", {"username": username, "password": password,
                                        "role": role}, token=self.admin())
        assert r.status == 201, (r.status, r.body)
        status, tok = self.login(username, password)
        assert status == 200
        return r.json()["id"], tok

    def append(self, *lines, wait=1.0):
        with open(self.eve, "a") as f:
            f.writelines(lines)
        time.sleep(wait)

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
        shutil.rmtree(self.dir, ignore_errors=True)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


# ── Subprocess helpers (CLI / config-file behaviour) ─────────────────────────
def run_server(args, cwd=None, timeout=10.0, port=None, backend=None):
    """Start backend/server.py in a subprocess; wait until the port answers."""
    backend = Path(backend or BACKEND)
    p = subprocess.Popen([sys.executable, str(backend / "server.py"), *args],
                         cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True)
    if port is None:
        return p
    deadline = time.time() + timeout
    while time.time() < deadline:
        if p.poll() is not None:
            break
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            return p
        except OSError:
            time.sleep(0.1)
    out = p.communicate(timeout=5)[0] if p.poll() is not None else ""
    p.kill()
    raise RuntimeError(f"server did not start on {port}: {out}")


def stop(p):
    p.terminate()
    try:
        return p.communicate(timeout=5)[0]
    except subprocess.TimeoutExpired:
        p.kill()
        return p.communicate()[0]
