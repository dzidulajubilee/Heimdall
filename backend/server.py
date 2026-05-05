#!/usr/bin/env python3
"""
Heimdall IDS Dashboard — Entry Point
Wires all modules together and starts the HTTP server.

Usage
-----
    python3 server.py
    python3 server.py --eve /var/log/suricata/eve.json --port 8765
    python3 server.py --password mysecretpassword      # set/change password
    python3 server.py --db /var/lib/heimdall/events.db --retain-days 90

Dual-database layout
---------------------
  events.db  — high-volume writes: alerts, flows, http_events
  dns.db     — dedicated DNS event store
  config.db  — low-write config:   auth, sessions, users, webhooks

Keeping them separate means each write-heavy workload has its own WAL lock.

First run
---------
If no password has been set a random one is generated, printed to the
console, and saved (hashed) in the config database.  Change it any time:
    python3 server.py --password <new-password>
"""

import argparse
import logging
import secrets
import socketserver
import threading
from http.server import HTTPServer

import config
from auth      import AuthManager
from config_db import ConfigDB
from database  import AlertDB
from dns_db    import DNSDB
from handlers  import Handler
from registry  import Registry
from tail      import purge_thread, tail_thread
from users     import UserManager
from webhooks      import WebhookDB, delivery_worker
from threat_intel  import ThreatIntelDB
from suppression   import SuppressionDB
from ai_explain    import AIExplainDB

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("heimdall")


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """Each request (including long-lived SSE connections) runs in its own thread."""
    daemon_threads = True


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Heimdall IDS Dashboard",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--eve",          default=config.DEFAULT_EVE,
                   help="Path to Suricata eve.json")
    p.add_argument("--port",         default=config.DEFAULT_PORT, type=int,
                   help="TCP port to listen on")
    p.add_argument("--host",         default=config.DEFAULT_HOST,
                   help="Bind address")
    p.add_argument("--db",           default=str(config.DEFAULT_DB),
                   help="Path to events SQLite database (alerts, flows, dns, http)")
    p.add_argument("--config-db",    default=str(config.DEFAULT_CONFIG_DB),
                   help="Path to config SQLite database (auth, sessions, users, webhooks)")
    p.add_argument("--dns-db",       default=str(config.DEFAULT_DNS_DB),
                   help="Path to DNS SQLite database")
    p.add_argument("--retain-days",  default=config.RETAIN_DAYS, type=int,
                   help="Days to keep alerts in the database")
    p.add_argument("--password",     default=None,
                   help="Set or change the dashboard password, then exit")
    return p


def main():
    args = build_arg_parser().parse_args()

    # ── Databases ─────────────────────────────────────────────────────────────
    # events.db: high-volume alert/flow/http writes
    db = AlertDB(path=args.db, retain_days=args.retain_days)

    # dns.db: dedicated DNS event store
    dns_db = DNSDB(path=args.dns_db, retain_days=args.retain_days)

    # config.db: low-write auth, session, user, and webhook tables
    cfg_db = ConfigDB(path=args.config_db)

    # ── Auth (uses config db) ─────────────────────────────────────────────────
    auth = AuthManager(conn_fn=cfg_db._conn)

    # Password management mode: set password and exit
    if args.password:
        auth.set_password(args.password)
        log.info("Password updated. Restart the server without --password.")
        return

    # First-run: auto-generate a password if none exists
    if not auth.get_hash():
        pw = secrets.token_urlsafe(14)
        auth.set_password(pw)
        log.info("=" * 60)
        log.info("  HEIMDALL INITIAL CREDENTIALS")
        log.info("  Username : admin")
        log.info("  PASSWORD : %s", pw)
        log.info("  URL      : http://localhost:8765/")
        log.info("  Change password via: heimdall --password <new>")
        log.info("=" * 60)

    # ── Registry ──────────────────────────────────────────────────────────────
    registry = Registry()

    # ── Webhook DB (uses config db) ───────────────────────────────────────────
    wdb = WebhookDB(conn_fn=cfg_db._conn)
    ti_db  = ThreatIntelDB(conn_fn=cfg_db._conn)
    sup_db = SuppressionDB(conn_fn=cfg_db._conn)
    ai_db  = AIExplainDB(conn_fn=cfg_db._conn)

    # ── User manager (RBAC, uses config db) ──────────────────────────────────
    um = UserManager(conn_fn=cfg_db._conn)

    # Bootstrap: if no users exist, create first admin account
    um.bootstrap_admin(auth.get_hash() or "")

    # Invalidate stale sessions that pre-date the RBAC username/role columns
    cfg_db._conn().execute(
        "DELETE FROM sessions WHERE username = '' OR username IS NULL"
    )
    cfg_db._conn().commit()

    # ── Wire dependencies into the handler ────────────────────────────────────
    Handler.db       = db
    Handler.dns_db   = dns_db
    Handler.auth     = auth
    Handler.registry = registry
    Handler.wdb      = wdb
    Handler.um       = um
    Handler.ti_db    = ti_db
    Handler.sup_db   = sup_db
    Handler.ai_db    = ai_db

    # ── Log DB state ──────────────────────────────────────────────────────────
    s = db.stats()
    log.info(
        "Events DB: alerts=%d  flows=%d  oldest: %s",
        s["alerts"]["total"], s["flows"]["total"], s["oldest"] or "none",
    )
    log.info("DNS    DB: %s records — %s", dns_db.count(), args.dns_db)
    log.info("Config DB: %s", args.config_db)

    # ── Background threads ────────────────────────────────────────────────────
    threading.Thread(
        target=tail_thread,
        args=(args.eve, db, dns_db, registry, wdb),
        daemon=True,
        name="tail",
    ).start()

    threading.Thread(
        target=purge_thread,
        args=(db, dns_db, auth),
        daemon=True,
        name="purge",
    ).start()

    threading.Thread(
        target=delivery_worker,
        args=(wdb,),
        daemon=True,
        name="webhooks",
    ).start()

    # ── HTTP server ───────────────────────────────────────────────────────────
    srv = ThreadedHTTPServer((args.host, args.port), Handler)
    srv.allow_reuse_address = True

    log.info("Login      →  http://localhost:%d/login",  args.port)
    log.info("Dashboard  →  http://localhost:%d/",       args.port)
    log.info("Health     →  http://localhost:%d/health", args.port)
    log.info("Ready — waiting for connections.")

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down.")
        srv.server_close()


if __name__ == "__main__":
    main()
