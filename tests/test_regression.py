"""
Regression suite — pins EXISTING Heimdall behaviour that must not change.
Every test here passes against the unmodified v1.4.3 code as well.

Run:  python3 -m unittest discover -s tests -v
"""

import json
import time
import unittest
import urllib.request

from _harness import Instance, alert_line, dns_line, flow_line


class RegressionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.h = Instance()

    @classmethod
    def tearDownClass(cls):
        cls.h.close()

    # ── Auth & perimeter ─────────────────────────────────────────────────────
    def test_unauthenticated_page_redirects_to_login(self):
        r = self.h.req("GET", "/")
        self.assertEqual(r.status, 302)
        self.assertEqual(r.headers.get("Location"), "/login")

    def test_unauthenticated_api_is_401(self):
        for path in ("/alerts", "/flows", "/dns", "/health", "/users", "/webhooks"):
            self.assertEqual(self.h.req("GET", path).status, 401, path)

    def test_login_success_sets_hardened_cookie(self):
        r = self.h.req("POST", "/login", {"username": "admin", "password": "Admin-Test-Pass-1"})
        self.assertEqual(r.status, 200)
        cookie = r.headers["Set-Cookie"]
        for attr in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(attr, cookie)

    def test_login_failure_is_401(self):
        s, tok = self.h.login("admin", "wrong-password")
        self.assertEqual((s, tok), (401, None))

    def test_security_headers_on_json_and_static(self):
        tok = self.h.admin()
        for path in ("/health", "/frontend/skin-loader.js"):
            r = self.h.req("GET", path, token=tok)
            self.assertEqual(r.status, 200, path)
            self.assertEqual(r.headers.get("X-Frame-Options"), "DENY")
            self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff")
        csp = self.h.req("GET", "/frontend/skin-loader.js", token=tok).headers.get(
            "Content-Security-Policy", "")
        self.assertIn("default-src 'self'", csp)

    def test_source_and_traversal_blocked(self):
        tok = self.h.admin()
        self.assertEqual(self.h.req("GET", "/frontend/skins/original/app.jsx", token=tok).status, 403)
        self.assertEqual(self.h.req("GET", "/frontend/../LICENSE", token=tok).status, 403)

    def test_csrf_cross_origin_write_blocked(self):
        tok = self.h.admin()
        r = self.h.req("POST", "/skin", {"skin": "seal"}, token=tok,
                       headers={"Origin": "http://evil.example"})
        self.assertEqual(r.status, 403)

    def test_me(self):
        r = self.h.req("GET", "/me", token=self.h.admin())
        self.assertEqual(r.json(), {"username": "admin", "role": "admin"})

    # ── Ingestion ────────────────────────────────────────────────────────────
    def test_ingests_alert_dns_flow(self):
        tok = self.h.admin()
        self.h.append(alert_line(sig_id=1000001, src="198.51.100.1", flow_id=5001),
                      dns_line(rrname="ingest.test", flow_id=5002),
                      flow_line(flow_id=5003))
        alerts = self.h.req("GET", "/alerts", token=tok).json()["alerts"]
        self.assertTrue(any(a["sig_id"] == 1000001 for a in alerts))
        dns = self.h.req("GET", "/dns", token=tok).json()["dns"]
        self.assertTrue(any(d["rrname"] == "ingest.test" for d in dns))
        flows = self.h.req("GET", "/flows", token=tok).json()["flows"]
        self.assertTrue(any(f["flow_id"] == 5003 for f in flows))

    def test_suppressed_alert_not_ingested_live(self):
        tok = self.h.admin()
        r = self.h.req("POST", "/suppression", {"name": "live", "sig_id": 1000002}, token=tok)
        self.assertEqual(r.status, 201)
        self.h.append(alert_line(sig_id=1000002, flow_id=5004))
        alerts = self.h.req("GET", "/alerts", token=tok).json()["alerts"]
        self.assertFalse(any(a["sig_id"] == 1000002 for a in alerts))

    def test_sse_stream_opens_with_ping(self):
        tok = self.h.admin()
        r = urllib.request.Request(self.h.base + "/events")
        r.add_header("Cookie", f"suri_session={tok}")
        with urllib.request.urlopen(r, timeout=5) as resp:
            self.assertEqual(resp.headers["Content-Type"], "text/event-stream")
            self.assertEqual(resp.readline().decode().strip(), "event: ping")

    # ── Triage ───────────────────────────────────────────────────────────────
    def test_triage_status_notes_and_rbac(self):
        _, analyst = self.h.make_user("tri_analyst", "analyst")
        _, viewer  = self.h.make_user("tri_viewer", "viewer")
        aid = "triage-test-1"
        self.assertEqual(self.h.req("POST", f"/alerts/{aid}/status",
                                    {"status": "investigating"}, token=analyst).status, 200)
        self.assertEqual(self.h.req("POST", f"/alerts/{aid}/status",
                                    {"status": "closed"}, token=viewer).status, 403)
        self.assertEqual(self.h.req("POST", f"/alerts/{aid}/status",
                                    {"status": "bogus"}, token=analyst).status, 400)
        self.assertEqual(self.h.req("POST", f"/alerts/{aid}/notes",
                                    {"note": "looks benign"}, token=analyst).status, 201)
        meta = self.h.req("GET", f"/alerts/{aid}/meta", token=viewer).json()
        self.assertEqual(meta["status"], "investigating")
        self.assertEqual(meta["notes"][0]["note"], "looks benign")
        self.assertEqual(meta["activity"][0]["action"], "Marked as investigating")

    def test_bulk_status_and_delete_selected(self):
        tok = self.h.admin()
        r = self.h.req("POST", "/alerts/bulk-status",
                       {"alert_ids": ["b1", "b2"], "status": "acknowledged"}, token=tok)
        self.assertEqual(r.json()["count"], 2)
        _, analyst = self.h.make_user("del_analyst", "analyst")
        self.assertEqual(self.h.req("POST", "/alerts/delete-selected",
                                    {"ids": ["b1"]}, token=analyst).status, 403)
        self.assertEqual(self.h.req("POST", "/alerts/delete-selected",
                                    {"ids": ["b1"]}, token=tok).status, 200)

    # ── Threat intel ─────────────────────────────────────────────────────────
    def test_threat_intel_crud_and_htf_roundtrip(self):
        tok = self.h.admin()
        r = self.h.req("POST", "/threat-intel",
                       {"sig_id": 424242, "explanation": "Line one\nLine two",
                        "tags": ["scan"], "refs": ["CVE-2024-0001"]}, token=tok)
        self.assertEqual(r.status, 201)
        tid = r.json()["id"]
        self.assertEqual(self.h.req("PUT", f"/threat-intel/{tid}",
                                    {"explanation": "Updated"}, token=tok).json()["explanation"],
                         "Updated")
        look = self.h.req("GET", "/threat-intel/lookup?sig_id=424242", token=tok).json()
        self.assertEqual(look["id"], tid)
        exported = self.h.req("GET", "/threat-intel/export", token=tok).body
        self.assertIn("sig_id: 424242", exported)
        imp = self.h.req("POST", "/threat-intel/import",
                         {"content": exported, "overwrite": True}, token=tok).json()
        self.assertGreaterEqual(imp.get("overwritten", 0) + imp.get("imported", 0), 1)
        self.assertEqual(self.h.req("DELETE", f"/threat-intel/{tid}", token=tok).status, 200)

    # ── Users ────────────────────────────────────────────────────────────────
    def test_last_admin_and_self_protection(self):
        tok = self.h.admin()
        admin_id = next(u["id"] for u in self.h.req("GET", "/users", token=tok).json()["users"]
                        if u["username"] == "admin")
        self.assertEqual(self.h.req("PUT", f"/users/{admin_id}", {"role": "viewer"},
                                    token=tok).status, 400)
        self.assertEqual(self.h.req("PUT", f"/users/{admin_id}", {"enabled": False},
                                    token=tok).status, 400)
        self.assertEqual(self.h.req("DELETE", f"/users/{admin_id}", token=tok).status, 400)

    def test_non_admin_cannot_manage_users(self):
        _, analyst = self.h.make_user("um_analyst", "analyst")
        self.assertEqual(self.h.req("GET", "/users", token=analyst).status, 403)
        self.assertEqual(self.h.req("POST", "/users", {"username": "x", "password": "y"},
                                    token=analyst).status, 403)

    # ── Admin-only data management ───────────────────────────────────────────
    def test_clear_endpoints_admin_only(self):
        _, analyst = self.h.make_user("clr_analyst", "analyst")
        for path in ("/alerts", "/flows", "/dns"):
            self.assertEqual(self.h.req("DELETE", path, token=analyst).status, 403, path)

    # ── Webhooks: the admin path keeps working ───────────────────────────────
    def test_admin_webhook_lifecycle(self):
        tok = self.h.admin()
        r = self.h.req("POST", "/webhooks", {"name": "slack", "type": "slack",
                                             "url": "https://hooks.example.com/T/B/x"}, token=tok)
        self.assertEqual(r.status, 201)
        wid = r.json()["id"]
        self.assertTrue(any(w["id"] == wid for w in
                            self.h.req("GET", "/webhooks", token=tok).json()["webhooks"]))
        self.assertFalse(self.h.req("PUT", f"/webhooks/{wid}", {"enabled": False},
                                    token=tok).json()["enabled"])
        self.assertEqual(self.h.req("DELETE", f"/webhooks/{wid}", token=tok).status, 200)

    def test_webhook_blocks_loopback_by_default(self):
        tok = self.h.admin()
        wid = self.h.req("POST", "/webhooks", {"name": "lo", "type": "generic",
                                               "url": "http://127.0.0.1:9/x"}, token=tok).json()["id"]
        res = self.h.req("POST", f"/webhooks/{wid}/test", token=tok).json()
        self.assertFalse(res["ok"])
        self.assertIn("Blocked", res["error"])

    # ── Misc read endpoints ──────────────────────────────────────────────────
    def test_health_charts_skin(self):
        tok = self.h.admin()
        self.assertEqual(self.h.req("GET", "/health", token=tok).json()["status"], "ok")
        charts = self.h.req("GET", "/charts?trend=168", token=tok).json()
        self.assertEqual(len(charts["trend"]), 7)
        self.assertEqual(self.h.req("POST", "/skin", {"skin": "mosaic"}, token=tok).status, 200)
        self.assertEqual(self.h.req("GET", "/skin", token=tok).json()["skin"], "mosaic")
        self.assertEqual(self.h.req("POST", "/skin", {"skin": "nope"}, token=tok).status, 400)


if __name__ == "__main__":
    unittest.main()
