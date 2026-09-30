"""
Heimdall IDS Dashboard — Admin audit log
Records who changed what, in config.db table audit_log: sign-ins, user and
role changes, webhooks, suppression rules, threat intel, data clears / flush /
replay, AI settings and command-line password resets.

Never stores secrets: passwords and API keys are recorded only as "changed",
webhook URLs only by host (their paths carry tokens).

Bounded: only the newest MAX_ROWS entries are kept, so a flood of failed
sign-ins cannot grow the table without limit.
"""

import logging
import threading
import time

log = logging.getLogger("heimdall.audit")

MAX_ROWS     = 100_000
_PRUNE_EVERY = 500      # check the cap every N writes


class AuditLog:
    def __init__(self, conn_fn):
        self._conn        = conn_fn
        self._lock        = threading.Lock()
        self._since_prune = 0
        c = conn_fn()
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       REAL    NOT NULL,
                username TEXT    NOT NULL DEFAULT '',
                role     TEXT    NOT NULL DEFAULT '',
                ip       TEXT    NOT NULL DEFAULT '',
                action   TEXT    NOT NULL,
                target   TEXT    NOT NULL DEFAULT '',
                detail   TEXT    NOT NULL DEFAULT ''
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts)")
        c.commit()

    def record(self, action: str, username: str = "", role: str = "",
               ip: str = "", target: str = "", detail: str = ""):
        """Append one entry. Never raises: a failed audit write is logged to
        the journal and does not block the action being audited."""
        try:
            c = self._conn()
            c.execute(
                "INSERT INTO audit_log (ts, username, role, ip, action, target, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), str(username)[:64], str(role)[:16], str(ip)[:64],
                 str(action)[:64], str(target)[:200], str(detail)[:500]))
            c.commit()
            log.info("AUDIT %s by %s — %s %s", action, username or "-", target, detail)
            with self._lock:
                self._since_prune += 1
                prune = self._since_prune >= _PRUNE_EVERY
                if prune:
                    self._since_prune = 0
            if prune:
                self.prune(c)
        except Exception as exc:
            log.warning("Audit write failed (%s): %s", action, exc)

    def prune(self, c=None):
        c = c or self._conn()
        c.execute("DELETE FROM audit_log WHERE id <= "
                  "(SELECT id FROM audit_log ORDER BY id DESC LIMIT 1 OFFSET ?)", (MAX_ROWS,))
        c.commit()

    def fetch(self, limit: int = 100, offset: int = 0,
              action: str = None, username: str = None) -> tuple[list, int]:
        """Newest first. action filters by prefix (e.g. 'user.' or 'login.')."""
        where, args = [], []
        if action:
            where.append("action LIKE ?"); args.append(action + "%")
        if username:
            where.append("username = ? COLLATE NOCASE"); args.append(username)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        c = self._conn()
        total = c.execute(f"SELECT COUNT(*) FROM audit_log {w}", args).fetchone()[0]
        rows  = c.execute(
            f"SELECT id, ts, username, role, ip, action, target, detail FROM audit_log {w} "
            "ORDER BY id DESC LIMIT ? OFFSET ?", args + [limit, offset]).fetchall()
        return [dict(r) for r in rows], total
