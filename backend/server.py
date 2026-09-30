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

Config file
-----------
    python3 server.py --config /etc/heimdall/heimdall.conf
One option per line exactly as on the command line (e.g. "--port 8765"),
"#" starts a comment. Options given on the command line override the file.
The installed /usr/bin/heimdall wrapper always passes
--config /etc/heimdall/heimdall.conf.

First run
---------
If no password has been set a random one is generated, printed to the
console, and saved (hashed) in the config database.  Change it any time:
    python3 server.py --password <new-password>
"""

import argparse
import logging
import shlex
import socketserver
import sys
import threading
from http.server import HTTPServer
from pathlib import Path

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
    p.add_argument("--config",       default=None,
                   help="Read options from this file (one per line, '#' comments); "
                        "command-line options override it")
    p.add_argument("--skin",         default="original", choices=sorted(Handler._VALID_SKINS),
                   help="Default skin for users who have not chosen one")
    p.add_argument("--ai-provider", default=None, choices=["openai", "anthropic", "deepseek"], help="AI provider until one is chosen in the UI")
    p.add_argument("--ai-key", default=None, help="AI API key, used when none is set in the UI (prefer the config file: argv is visible in ps)")
    return p


def load_config_file(path: str, parser: argparse.ArgumentParser) -> list[str]:
    """
    Read a Heimdall config file into argv-style tokens.

    Each non-comment line is one option exactly as on the command line.
    Unknown options, --password and --config are ignored with a warning; an
    invalid value for a known option stops startup (naming file:line).
    Option VALUES are never logged — the file may contain --ai-key.
    A missing/unreadable file logs a warning and yields no options.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        log.warning("Config file %s not found — using defaults.", path)
        return []
    except OSError as exc:
        log.warning("Cannot read config file %s (%s) — using defaults.", path, exc.strerror)
        return []

    tokens, applied = [], []
    for lineno, line in enumerate(text.splitlines(), 1):
        where = f"{path}:{lineno}"
        try:
            parts = shlex.split(line, comments=True)
        except ValueError:
            log.warning("%s: unparseable line ignored.", where)
            continue
        if not parts:
            continue
        opt = parts[0].split("=", 1)[0]
        try:
            ns, unknown = parser.parse_known_args(parts)
        except SystemExit:
            log.error("%s: invalid value for %s — fix the config file.", where, opt)
            raise
        if unknown:
            names = [u.split("=", 1)[0] for u in unknown if u.startswith("-")] or ["(stray value)"]
            log.warning("%s: unrecognised option %s ignored.", where, " ".join(names))
            continue
        if ns.password is not None or ns.config is not None:
            log.warning("%s: %s is not allowed in the config file — ignored.", where, opt)
            continue
        tokens.extend(parts)
        applied.append(opt)
    if applied:
        log.info("Config file %s: %s", path, ", ".join(applied))
    return tokens


def parse_args(argv=None) -> argparse.Namespace:
    """Config file first, then the command line (later options win)."""
    parser = build_arg_parser()
    cli    = list(sys.argv[1:] if argv is None else argv)
    pre, _ = parser.parse_known_args(cli)
    file_tokens = load_config_file(pre.config, parser) if pre.config else []
    return parser.parse_args(file_tokens + cli)


def main():
    args = parse_args()

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
        # Legacy auth-table hash: still written so a rollback to <= 1.4.3
        # has a known password, but since 1.4.4 it is never accepted at login.
        auth.set_password(args.password)
        # Recovery guarantee: after this command, 'admin' / <password> logs in
        # with the admin role. Create the user if missing; otherwise reset its
        # password and, if it was disabled or demoted, restore it.
        um = UserManager(conn_fn=cfg_db._conn)
        # End every existing 'admin' session (including any left behind by a
        # deleted 'admin' account) — this command is the lock-out/compromise path.
        auth.revoke_user_sessions("admin")
        admin = um.get_by_username("admin")
        if admin is None:
            um.create("admin", args.password, role="admin")
            log.info("Admin user created with provided password.")
        else:
            um.set_password(admin["id"], args.password)
            if admin["role"] != "admin" or not admin["enabled"]:
                um.update(admin["id"], role="admin", enabled=True)
                log.info("Admin user re-enabled with the admin role.")
            log.info("Admin password updated in user table.")
        log.info("Password updated. Restart the server without --password.")
        return

    # First run without the installer: UserManager.bootstrap_admin() (below)
    # creates the 'admin' user and logs its password once. The former legacy
    # block here logged a second, different password that only the removed
    # single-password fallback accepted.

    # ── Registry ──────────────────────────────────────────────────────────────
    registry = Registry()

    # ── Webhook DB (uses config db) ───────────────────────────────────────────
    wdb = WebhookDB(conn_fn=cfg_db._conn)
    ti_db  = ThreatIntelDB(conn_fn=cfg_db._conn)
    sup_db = SuppressionDB(conn_fn=cfg_db._conn)
    ai_db  = AIExplainDB(conn_fn=cfg_db._conn, fallback_provider=args.ai_provider, fallback_key=args.ai_key)

    # ── User manager (RBAC, uses config db) ──────────────────────────────────
    um = UserManager(conn_fn=cfg_db._conn)

    # Bootstrap: if no users exist, create first admin account
    um.bootstrap_admin(auth.get_hash() or "")

    # Invalidate stale sessions that pre-date the RBAC username/role columns
    cfg_db._conn().execute(
        "DELETE FROM sessions WHERE username = '' OR username IS NULL"
    )
    cfg_db._conn().commit()
    # Drop sessions of deleted or disabled users (never revoked before 1.4.4)
    auth.purge_orphaned()

    # ── Wire dependencies into the handler ────────────────────────────────────
    Handler.db        = db
    Handler.dns_db    = dns_db
    Handler.auth      = auth
    Handler.registry  = registry
    Handler.wdb       = wdb
    Handler.um        = um
    Handler.ti_db     = ti_db
    Handler.sup_db    = sup_db
    Handler.ai_db     = ai_db
    Handler._eve_path = args.eve        # needed by replay
    Handler._default_skin = args.skin   # --skin: default for users with no saved choice

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
        kwargs={"sup_db": sup_db},
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
