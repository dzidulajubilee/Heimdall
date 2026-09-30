"""
Tests for the v1.4.5 improvements: HTTPS, admin audit log,
`--password --user`, and input-validation fixes.

Run:  python3 -m unittest discover -s tests -v
"""

import json
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

from _harness import BACKEND, Instance, alert_line, free_port, run_server, stop


def _tmpdir():
    return tempfile.mkdtemp(prefix="heimdall-imp-")


# ─────────────────────────────────────────────────────────────────────────────
class I01_HTTPS(unittest.TestCase):
    """Optional built-in TLS (--tls-cert / --tls-key)."""

    @classmethod
    def setUpClass(cls):
        if not shutil.which("openssl"):
            raise unittest.SkipTest("openssl not installed")
        cls.dir  = _tmpdir()
        cls.cert = os.path.join(cls.dir, "cert.pem")
        cls.key  = os.path.join(cls.dir, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-subj", "/CN=localhost", "-days", "1",
                        "-keyout", cls.key, "-out", cls.cert],
                       check=True, capture_output=True)
        os.chmod(cls.key, 0o600)
        cls.port = free_port()
        cls.base = ["--eve", f"{cls.dir}/eve.json", "--db", f"{cls.dir}/e.db",
                    "--dns-db", f"{cls.dir}/d.db", "--config-db", f"{cls.dir}/c.db"]
        subprocess.run([sys.executable, str(BACKEND / "server.py"), *cls.base,
                        "--password", "Tls-Pass-1"], check=True, capture_output=True)
        cls.p = run_server([*cls.base, "--host", "127.0.0.1", "--port", str(cls.port),
                            "--tls-cert", cls.cert, "--tls-key", cls.key], port=cls.port)
        cls.ctx = ssl.create_default_context(cafile=cls.cert)
        cls.ctx.check_hostname = False              # cert CN is localhost; we dial 127.0.0.1

    @classmethod
    def tearDownClass(cls):
        cls.out = stop(cls.p)
        shutil.rmtree(cls.dir, ignore_errors=True)

    def _https(self, method, path, body=None, timeout=5):
        r = urllib.request.Request(f"https://127.0.0.1:{self.port}{path}", method=method,
                                   data=json.dumps(body).encode() if body else None,
                                   headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(r, context=self.ctx, timeout=timeout) as resp:
                return resp.status, resp.headers
        except urllib.error.HTTPError as e:
            return e.code, e.headers

    def test_https_serves_and_cookie_is_secure(self):
        self.assertEqual(self._https("GET", "/login")[0], 200)
        status, headers = self._https("POST", "/login", {"username": "admin", "password": "Tls-Pass-1"})
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"]
        for attr in ("Secure", "HttpOnly", "SameSite=Strict"):
            self.assertIn(attr, cookie)

    def test_tls_1_2_minimum(self):
        ctx = ssl.create_default_context(cafile=self.cert); ctx.check_hostname = False
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            with socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw:
                ctx.wrap_socket(raw).close()

    def test_tls_1_2_client_accepted(self):                      # positive case for the minimum
        ctx = ssl.create_default_context(cafile=self.cert); ctx.check_hostname = False
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as raw:
            with ctx.wrap_socket(raw) as tls:
                self.assertEqual(tls.version(), "TLSv1.2")

    def test_plain_http_to_tls_port_is_refused_and_server_survives(self):
        with self.assertRaises(Exception):
            urllib.request.urlopen(f"http://127.0.0.1:{self.port}/login", timeout=5)
        self.assertEqual(self._https("GET", "/login")[0], 200)

    def test_stalled_client_does_not_block_others(self):
        stalled = socket.create_connection(("127.0.0.1", self.port))   # never handshakes
        try:
            t0 = time.time()
            self.assertEqual(self._https("GET", "/login", timeout=5)[0], 200)
            self.assertLess(time.time() - t0, 3)
        finally:
            stalled.close()

    def test_fails_closed_on_bad_tls_config(self):
        cases = [["--tls-cert", self.cert],                                   # key missing
                 ["--tls-cert", self.cert, "--tls-key", self.dir + "/nope.pem"],
                 ["--tls-cert", self.key, "--tls-key", self.key]]             # not a certificate
        for extra in cases:
            r = subprocess.run([sys.executable, str(BACKEND / "server.py"), *self.base,
                                "--host", "127.0.0.1", "--port", str(free_port()), *extra],
                               capture_output=True, text=True, timeout=20)
            self.assertEqual(r.returncode, 2, extra)
            self.assertIn("not starting", r.stderr + r.stdout)

    def test_plain_http_default_has_no_secure_flag(self):
        h = Instance()
        try:
            r = h.req("POST", "/login", {"username": "admin", "password": "Admin-Test-Pass-1"})
            self.assertNotIn("Secure", r.headers["Set-Cookie"])
        finally:
            h.close()


# ─────────────────────────────────────────────────────────────────────────────
class I02_AuditLog(unittest.TestCase):

    def setUp(self):
        self.h = Instance()
        self.admin = self.h.admin()

    def tearDown(self):
        self.h.close()

    def _entries(self, **q):
        qs = "&".join(f"{k}={v}" for k, v in q.items())
        r = self.h.req("GET", f"/audit?{qs}", token=self.admin)
        self.assertEqual(r.status, 200, r.body)
        return r.json()["entries"]

    def _last(self, action):
        e = [x for x in self._entries(limit=500) if x["action"] == action]
        self.assertTrue(e, f"no {action} entry")
        return e[0]

    def test_admin_only(self):
        for role in ("viewer", "analyst"):
            _, tok = self.h.make_user(f"au_{role}", role)
            self.assertEqual(self.h.req("GET", "/audit", token=tok).status, 403)
        self.assertEqual(self.h.req("GET", "/audit").status, 401)

    def test_sign_ins_and_user_changes_without_secrets(self):
        self.h.login("admin", "wrong-guess")
        e = self._last("login.failure")
        self.assertEqual((e["username"], e["ip"]), ("admin", "127.0.0.1"))
        self.assertEqual(self._last("login.success")["username"], "admin")
        uid, _ = self.h.make_user("bob", "viewer", password="Bob-Secret-Pass-1")
        self.assertEqual(self._last("user.create")["detail"], "role=viewer")
        self.h.req("PUT", f"/users/{uid}", {"role": "analyst", "password": "Bob-New-Secret-2"},
                   token=self.admin)
        e = self._last("user.update")
        self.assertEqual((e["username"], e["target"], e["detail"]),
                         ("admin", "bob", "role viewer→analyst; password reset"))
        self.h.req("DELETE", f"/users/{uid}", token=self.admin)
        self.assertEqual(self._last("user.delete")["target"], "bob")
        dump = json.dumps(self._entries(limit=500))
        for secret in ("Bob-Secret-Pass-1", "Bob-New-Secret-2", "wrong-guess"):
            self.assertNotIn(secret, dump)

    def test_webhooks_logged_by_host_only(self):
        url = "https://hooks.slack.com/services/T000/B000/SECRETTOKEN"
        wid = self.h.req("POST", "/webhooks", {"name": "soc", "type": "slack", "url": url},
                         token=self.admin).json()["id"]
        self.h.req("PUT", f"/webhooks/{wid}", {"url": url + "2", "enabled": False}, token=self.admin)
        self.h.req("DELETE", f"/webhooks/{wid}", token=self.admin)
        self.assertEqual(self._last("webhook.create")["detail"],
                         "type=slack host=hooks.slack.com allow_local=False")
        self.assertEqual(self._last("webhook.update")["detail"],
                         "url host=hooks.slack.com; enabled=False")
        self.assertEqual(self._last("webhook.delete")["target"], "soc")
        self.assertNotIn("SECRETTOKEN", json.dumps(self._entries(limit=500)))

    def test_data_suppression_threat_intel_and_ai(self):
        self.h.req("POST", "/suppression", {"name": "noisy", "sig_id": 5}, token=self.admin)
        self.h.req("DELETE", "/dns", token=self.admin)
        self.h.req("POST", "/flush", token=self.admin)
        self.h.req("POST", "/threat-intel/import",
                   {"content": "[entry]\nsig_id: 77\nexplanation: x\n---\n"}, token=self.admin)
        self.h.req("PUT", "/ai-config", {"provider": "anthropic", "api_key": "sk-ant-SECRET"},
                   token=self.admin)
        self.assertEqual(self._last("suppression.create")["detail"], "sig_id=5")
        self.assertEqual(self._last("data.clear")["target"], "dns")
        self.assertIn("alerts", self._last("data.flush")["detail"])
        self.assertIn("imported=1", self._last("threat_intel.import")["detail"])
        ai = self._last("ai.config")["detail"]
        self.assertIn("API key changed", ai)
        self.assertNotIn("sk-ant-SECRET", json.dumps(self._entries(limit=500)))

    def test_filters_paging_and_cap(self):
        import audit
        for _ in range(3):
            self.h.login("ghost", "x")
        self.assertEqual({e["action"] for e in self._entries(action="login.failure")}, {"login.failure"})
        self.assertEqual(len(self._entries(user="ghost", limit=2)), 2)
        for i in range(12):                                 # more rows than the cap below
            self.h.audit.record("test.fill", target=str(i))
        old = audit.MAX_ROWS
        audit.MAX_ROWS = 5
        try:
            self.h.audit.prune()
            kept = self._entries(limit=500)
            self.assertEqual([e["target"] for e in kept], ["11", "10", "9", "8", "7"])  # newest kept
        finally:
            audit.MAX_ROWS = old

    def test_audit_failure_never_blocks_the_action(self):
        self.h.cfg_db._conn().execute("DROP TABLE audit_log")
        r = self.h.req("POST", "/suppression", {"name": "still-works", "sig_id": 9}, token=self.admin)
        self.assertEqual(r.status, 201)


# ─────────────────────────────────────────────────────────────────────────────
class I09_PasswordUserFlag(unittest.TestCase):
    """`heimdall --password <pw> --user <name>` resets any account."""

    def setUp(self):
        self.dir = _tmpdir()
        self.base = ["--eve", f"{self.dir}/eve.json", "--db", f"{self.dir}/e.db",
                     "--dns-db", f"{self.dir}/d.db", "--config-db", f"{self.dir}/c.db"]
        self._cli("--password", "Admin-Pass-1")
        from config_db import ConfigDB
        from users import UserManager
        from auth import AuthManager
        conn = ConfigDB(f"{self.dir}/c.db")._conn
        self.um, self.auth = UserManager(conn), AuthManager(conn)
        bob = self.um.create("bob", "Bob-Old-Pass-1", role="analyst")
        self.um.update(bob["id"], enabled=False)
        self.bob_token = self.auth.create_session("bob", "analyst")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _cli(self, *extra):
        return subprocess.run([sys.executable, str(BACKEND / "server.py"), *self.base, *extra],
                              capture_output=True, text=True, timeout=30)

    def test_reset_other_user(self):
        from password_utils import verify_password
        r = self._cli("--password", "Bob-New-Pass-2", "--user", "BOB")   # case-insensitive
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIsNotNone(self.um.authenticate("bob", "Bob-New-Pass-2"))   # works + re-enabled
        self.assertEqual(self.um.get_by_username("bob")["role"], "analyst")   # role unchanged
        self.assertIsNone(self.auth.get_session(self.bob_token))              # old session ended
        self.assertIsNotNone(self.um.authenticate("admin", "Admin-Pass-1"))   # admin untouched
        row = sqlite3.connect(f"{self.dir}/c.db").execute(
            "SELECT username, target, detail FROM audit_log WHERE action='cli.password_reset' "
            "ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row, ("(command line)", "bob", "password reset; sessions ended; re-enabled"))

    def test_unknown_user_fails_and_lists_accounts(self):
        r = self._cli("--password", "X-Pass-1", "--user", "ghost")
        self.assertEqual(r.returncode, 1)
        self.assertIn("No user named 'ghost'", r.stderr)
        self.assertIn("admin, bob", r.stderr)
        self.assertIsNone(self.um.get_by_username("ghost"))               # nothing created

    def test_default_is_still_admin(self):
        r = self._cli("--password", "Admin-Pass-2")
        self.assertEqual(r.returncode, 0)
        self.assertIsNotNone(self.um.authenticate("admin", "Admin-Pass-2"))
        self.assertIsNone(self.um.authenticate("bob", "Admin-Pass-2"))

    def test_user_in_config_file_is_ignored(self):
        conf = f"{self.dir}/h.conf"
        with open(conf, "w") as f:
            f.write("--user bob\n")
        r = self._cli("--config", conf, "--password", "Admin-Pass-3")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--user is not allowed in the config file", r.stderr)
        self.assertIsNotNone(self.um.authenticate("admin", "Admin-Pass-3"))
        self.assertIsNone(self.um.authenticate("bob", "Admin-Pass-3"))


# ─────────────────────────────────────────────────────────────────────────────
class I08_ValidationBugs(unittest.TestCase):

    def setUp(self):
        self.h = Instance()
        self.admin = self.h.admin()

    def tearDown(self):
        self.h.close()

    def test_rejected_user_edit_changes_nothing(self):
        aid = self.h.um.get_by_username("admin")["id"]
        r = self.h.req("PUT", f"/users/{aid}", {"role": "viewer", "password": "Sneaky-Pass-9"},
                       token=self.admin)
        self.assertEqual(r.status, 400)                                    # last admin
        self.assertEqual(self.h.login("admin", "Admin-Test-Pass-1")[0], 200)  # password unchanged
        self.assertEqual(self.h.login("admin", "Sneaky-Pass-9")[0], 401)

    def test_rename_conflicts_and_empty_names(self):
        uid, _ = self.h.make_user("carol", "viewer")
        self.h.make_user("dave", "viewer")
        r = self.h.req("PUT", f"/users/{uid}", {"username": "DAVE", "password": "Whatever-1"},
                       token=self.admin)
        self.assertEqual((r.status, r.json()["error"]), (409, "Username 'DAVE' already exists"))
        self.assertEqual(self.h.login("carol", "carol-Pass-1")[0], 200)   # untouched
        self.assertEqual(self.h.req("PUT", f"/users/{uid}", {"username": "  "}, token=self.admin).status, 400)
        self.assertEqual(self.h.req("PUT", f"/users/{uid}", {"username": "Carol"},  # case-only rename ok
                                    token=self.admin).json()["username"], "Carol")

    def test_null_fields_leave_user_unchanged(self):
        uid, tok = self.h.make_user("erin", "analyst")
        r = self.h.req("PUT", f"/users/{uid}", {"enabled": None, "role": None}, token=self.admin)
        self.assertEqual((r.status, r.json()["enabled"], r.json()["role"]), (200, 1, "analyst"))
        self.assertEqual(self.h.req("GET", "/alerts", token=tok).status, 200)

    def test_non_numeric_ids_are_400_not_500(self):
        cases = [("GET",  "/threat-intel/lookup?sig_id=abc", None),
                 ("POST", "/threat-intel", {"sig_id": "abc", "explanation": "x"}),
                 ("POST", "/suppression",  {"name": "x", "sig_id": "abc"}),
                 ("POST", "/suppression",  {"name": "x", "sig_id": 5, "expires_at": "tomorrow"})]
        for method, path, body in cases:
            self.assertEqual(self.h.req(method, path, body, token=self.admin).status, 400, (path, body))
        self.assertEqual(self.h.req("GET", "/threat-intel/lookup?sig_id=5", token=self.admin).status, 200)


# ─────────────────────────────────────────────────────────────────────────────
class I03_BehindProxy(unittest.TestCase):
    """--behind-proxy: trust X-Real-IP / X-Forwarded-Proto from a loopback proxy only."""

    def setUp(self):
        import handlers
        self.handlers = handlers
        self.h = Instance()
        self.admin = self.h.admin()

    def tearDown(self):
        self.handlers.Handler._behind_proxy = False
        with self.handlers._LOGIN_LOCK:
            self.handlers._LOGIN_FAILS.clear()
        self.h.close()

    def _login(self, pw, ip=None, proto=None):
        hdr = {}
        if ip:    hdr["X-Real-IP"] = ip
        if proto: hdr["X-Forwarded-Proto"] = proto
        return self.h.req("POST", "/login", {"username": "admin", "password": pw}, headers=hdr)

    def _last_failure_ip(self):
        e = self.h.req("GET", "/audit?action=login.failure&limit=1", token=self.admin).json()["entries"]
        return e[0]["ip"]

    def test_headers_ignored_by_default(self):
        self._login("wrong", ip="203.0.113.9", proto="https")
        self.assertEqual(self._last_failure_ip(), "127.0.0.1")
        r = self._login("Admin-Test-Pass-1", proto="https")
        self.assertNotIn("Secure", r.headers["Set-Cookie"])

    def test_real_client_ip_and_https_from_local_proxy(self):
        self.handlers.Handler._behind_proxy = True
        self._login("wrong", ip="203.0.113.9")
        self.assertEqual(self._last_failure_ip(), "203.0.113.9")
        self._login("wrong", ip="not-an-ip")                               # bogus → peer address
        self.assertEqual(self._last_failure_ip(), "127.0.0.1")
        self.assertIn("Secure", self._login("Admin-Test-Pass-1", proto="https").headers["Set-Cookie"])
        self.assertNotIn("Secure", self._login("Admin-Test-Pass-1", proto="http").headers["Set-Cookie"])

    def test_lockout_is_per_real_client(self):
        self.handlers.Handler._behind_proxy = True
        with self.handlers._LOGIN_LOCK:
            self.handlers._LOGIN_FAILS.clear()
        for _ in range(10):
            self._login("wrong", ip="198.51.100.66")                       # attacker
        self.assertEqual(self._login("Admin-Test-Pass-1", ip="198.51.100.66").status, 429)
        self.assertEqual(self._login("Admin-Test-Pass-1", ip="192.0.2.10").status, 200)   # colleague

    def test_remote_peer_cannot_claim_an_ip(self):
        H = self.handlers.Handler
        H._behind_proxy = True
        fake = H.__new__(H)
        fake.client_address = ("10.20.30.40", 5555)
        fake.headers = {"X-Real-IP": "1.2.3.4", "X-Forwarded-Proto": "https"}
        self.assertEqual(fake.address_string(), "10.20.30.40")
        self.assertFalse(fake._https())


# ─────────────────────────────────────────────────────────────────────────────
class _FakeSystem:
    """Fake command runner for nginx_setup: records calls, simulates apt/nginx/
    systemctl, and runs the real openssl so certificates actually exist."""

    def __init__(self, root, nginx_installed=True, fail=None, ss_out=""):
        self.root, self.installed, self.fail, self.ss_out = Path(root), nginx_installed, fail, ss_out
        self.calls = []

    def __call__(self, cmd, env=None):
        self.calls.append(list(cmd))
        line = " ".join(cmd)
        if self.fail and line.startswith(self.fail):
            return 1, "simulated failure"
        if cmd[:2] == ["nginx", "-v"]:
            return (0, "nginx version: nginx/1.24") if self.installed else (127, "not found")
        if cmd[:2] == ["apt-get", "install"]:
            self.installed = True                      # a fresh install enables the stock site
            (self.root / "etc/nginx/sites-available").mkdir(parents=True, exist_ok=True)
            (self.root / "etc/nginx/sites-enabled").mkdir(parents=True, exist_ok=True)
            stock = self.root / "etc/nginx/sites-available/default"
            stock.write_text("server {\n    listen 80 default_server;\n}\n")
            (self.root / "etc/nginx/sites-enabled/default").symlink_to(stock)
            return 0, ""
        if cmd[0] == "ss":
            return 0, self.ss_out
        if cmd[:2] == ["hostname", "-f"]:
            return 0, "sensor1.example.net\n"
        if cmd[:2] == ["hostname", "-I"]:
            return 0, "10.1.2.3 fe80::1 \n"
        if cmd[0] == "openssl":
            r = subprocess.run(cmd, capture_output=True, text=True)
            return r.returncode, r.stdout + r.stderr
        return 0, ""

    def ran(self, prefix):
        return [c for c in self.calls if " ".join(c).startswith(prefix)]


from pathlib import Path   # noqa: E402  (used by the NGINX tests below)


class I04_NginxSetup(unittest.TestCase):
    """sudo heimdall --setup-nginx / --remove-nginx (fake root + fake commands)."""

    @classmethod
    def setUpClass(cls):
        if not shutil.which("openssl"):
            raise unittest.SkipTest("openssl not installed")
        import nginx_setup
        cls.ns = nginx_setup

    def setUp(self):
        self.root = Path(_tmpdir())
        (self.root / "etc/heimdall").mkdir(parents=True)
        self.conf = self.root / "etc/heimdall/heimdall.conf"
        self.conf.write_text("# my settings\n--retain-days 30\n")
        self.out = []

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _env(self, sysm, is_root=True):
        return self.ns.Env(root=self.root, runner=sysm, is_root=is_root, out=self.out.append)

    def _debian_layout(self):
        for d in ("etc/nginx/sites-available", "etc/nginx/sites-enabled"):
            (self.root / d).mkdir(parents=True, exist_ok=True)

    def _snapshot(self):
        return {str(p.relative_to(self.root)): (os.readlink(p) if p.is_symlink() else
                                                 p.read_text() if p.is_file() else "<dir>")
                for p in sorted(self.root.rglob("*"))}

    def test_fresh_host_installs_nginx_and_configures_everything(self):
        sysm = _FakeSystem(self.root, nginx_installed=False)
        self.assertEqual(self.ns.setup(self._env(sysm), port=8765), 0)
        self.assertTrue(sysm.ran("apt-get install -y nginx"))
        site = (self.root / "etc/nginx/sites-available/heimdall").read_text()
        self.assertIn(self.ns.MARKER, site)
        self.assertIn("proxy_pass         http://127.0.0.1:8765;", site)
        self.assertIn("location = /events", site)
        self.assertIn("proxy_buffering    off;", site)
        self.assertIn("return 301 https://$host$request_uri;", site)
        self.assertIn("listen 80 default_server;", site)            # replaced the stock site
        self.assertFalse((self.root / "etc/nginx/sites-enabled/default").exists())
        self.assertTrue((self.root / "etc/nginx/sites-enabled/heimdall").is_symlink())
        key = self.root / "etc/heimdall/tls/heimdall.key"
        self.assertEqual(oct(key.stat().st_mode & 0o777), "0o600")
        san = next(c for c in sysm.calls if c[0] == "openssl")[-1]
        self.assertIn("IP:10.1.2.3", san); self.assertNotIn("fe80", san)
        conf = self.conf.read_text()
        self.assertIn("--retain-days 30", conf)                     # user settings kept
        self.assertTrue(conf.rstrip().endswith(self.ns.BLOCK_END))  # block last → wins
        self.assertIn("--host 127.0.0.1\n--behind-proxy", conf)
        self.assertEqual(len(list((self.root / "etc/heimdall").glob("heimdall.conf.bak-*"))), 1)
        order = [" ".join(c[:3]) for c in sysm.calls if c[0] in ("nginx", "systemctl") and c[1] != "-v"]
        self.assertEqual(order, ["nginx -t", "systemctl enable --now",
                                 "systemctl reload nginx", "systemctl restart heimdall"])
        self.assertTrue(any("SHA-256 fingerprint" in o for o in self.out))

    def test_rerun_is_idempotent_and_reuses_certificate(self):
        self._debian_layout()
        sysm = _FakeSystem(self.root)
        self.ns.setup(self._env(sysm), port=8765)
        self.ns.setup(self._env(sysm), port=9000)
        self.assertEqual(len(sysm.ran("openssl")), 1)                # generated once
        conf = self.conf.read_text()
        self.assertEqual(conf.count(self.ns.BLOCK_START), 1)
        self.assertIn("127.0.0.1:9000", (self.root / "etc/nginx/sites-available/heimdall").read_text())

    def test_own_certificate_used_and_bad_pair_rejected(self):
        self._debian_layout()
        d = self.root / "certs"; d.mkdir()
        for n in ("a", "b"):
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj",
                            f"/CN={n}", "-days", "1", "-keyout", str(d / f"{n}.key"),
                            "-out", str(d / f"{n}.crt")], check=True, capture_output=True)
        sysm = _FakeSystem(self.root)
        before = self._snapshot()
        with self.assertRaises(self.ns.SetupError):                   # mismatched cert/key
            self.ns.setup(self._env(sysm), 8765, cert="/certs/a.crt", key="/certs/b.key")
        self.assertEqual(self._snapshot(), before)
        self.ns.setup(self._env(sysm), 8765, cert="/certs/a.crt", key="/certs/a.key")
        site = (self.root / "etc/nginx/sites-available/heimdall").read_text()
        self.assertIn("ssl_certificate      /certs/a.crt;", site)     # system path, as nginx sees it
        self.assertFalse(sysm.ran("openssl"))

    def test_port_443_conflicts_stop_without_changes(self):
        self._debian_layout()
        other = self.root / "etc/nginx/sites-enabled/shop"
        other.write_text("server {\n    listen 443 ssl; # shop\n}\n")
        before = self._snapshot()
        with self.assertRaises(self.ns.SetupError) as cm:
            self.ns.setup(self._env(_FakeSystem(self.root)), 8765)
        self.assertIn("already listens on 443", str(cm.exception))
        self.assertEqual(self._snapshot(), before)
        other.unlink()
        before = self._snapshot()
        ss = 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("apache2",pid=9,fd=4))'
        with self.assertRaises(self.ns.SetupError) as cm:
            self.ns.setup(self._env(_FakeSystem(self.root, ss_out=ss)), 8765)
        self.assertIn("apache2", str(cm.exception))
        self.assertEqual(self._snapshot(), before)

    def test_existing_nginx_sites_are_left_alone(self):
        self._debian_layout()
        stock = self.root / "etc/nginx/sites-available/default"
        stock.write_text("server {\n    listen 80 default_server;\n}\n")
        (self.root / "etc/nginx/sites-enabled/default").symlink_to(stock)
        self.ns.setup(self._env(_FakeSystem(self.root)), 8765)       # nginx pre-installed
        self.assertTrue((self.root / "etc/nginx/sites-enabled/default").is_symlink())
        site = (self.root / "etc/nginx/sites-available/heimdall").read_text()
        self.assertIn("listen 80;", site); self.assertNotIn("default_server", site)

    def test_failures_roll_everything_back(self):
        for failing in ("nginx -t", "systemctl reload nginx", "systemctl restart heimdall"):
            with self.subTest(failing=failing):
                shutil.rmtree(self.root); self.setUp()
                sysm = _FakeSystem(self.root, nginx_installed=False, fail=failing)
                with self.assertRaises(self.ns.SetupError):
                    self.ns.setup(self._env(sysm), 8765)
                self.assertFalse((self.root / "etc/nginx/sites-available/heimdall").exists())
                self.assertFalse((self.root / "etc/nginx/sites-enabled/heimdall").exists())
                self.assertTrue((self.root / "etc/nginx/sites-enabled/default").is_symlink())
                self.assertEqual(self.conf.read_text(), "# my settings\n--retain-days 30\n")
                self.assertIn("  All changes were rolled back.", self.out)

    def test_refusals(self):
        self._debian_layout()
        with self.assertRaises(self.ns.SetupError):
            self.ns.setup(self._env(_FakeSystem(self.root), is_root=False), 8765)
        with self.assertRaises(self.ns.SetupError) as cm:
            self.ns.setup(self._env(_FakeSystem(self.root)), 8765, builtin_tls=True)
        self.assertIn("Built-in HTTPS", str(cm.exception))
        (self.root / "etc/nginx/sites-available/heimdall").write_text("server { }  # someone else's\n")
        with self.assertRaises(self.ns.SetupError) as cm:
            self.ns.setup(self._env(_FakeSystem(self.root)), 8765)
        self.assertIn("not created by Heimdall", str(cm.exception))

    def test_remove_restores_direct_access(self):
        self._debian_layout()
        sysm = _FakeSystem(self.root)
        self.ns.setup(self._env(sysm), 8765)
        self.assertEqual(self.ns.remove(self._env(sysm)), 0)
        self.assertFalse((self.root / "etc/nginx/sites-available/heimdall").exists())
        self.assertFalse((self.root / "etc/nginx/sites-enabled/heimdall").exists())
        self.assertEqual(self.conf.read_text(), "# my settings\n--retain-days 30\n")
        self.assertTrue((self.root / "etc/heimdall/tls/heimdall.crt").exists())    # kept
        self.assertTrue(sysm.ran("systemctl restart heimdall"))
        self.assertEqual(self.ns.remove(self._env(sysm)), 0)                        # nothing left
        self.assertIn("Nothing to remove", self.out[-1])

    def test_one_shot_commands_refused_in_config_file(self):
        import server
        cfg = self.root / "h.conf"
        cfg.write_text("--setup-nginx\n--remove-nginx\n--behind-proxy\n")
        args = server.parse_args(["--config", str(cfg)])
        self.assertEqual((args.setup_nginx, args.remove_nginx, args.behind_proxy), (False, False, True))


if __name__ == "__main__":
    unittest.main()
