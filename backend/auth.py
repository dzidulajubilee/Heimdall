"""
Heimdall IDS Dashboard — Authentication (RBAC-aware)
Single-password emergency fallback + full user/session management.
Sessions carry username and role, checked on every protected request.
"""

import logging
import secrets
import sqlite3
import time

from config         import SESSION_TTL
from password_utils import hash_password, verify_password

log = logging.getLogger("heimdall.auth")


class AuthManager:
    """
    Manages the legacy single-password (emergency fallback) and the
    RBAC session table.

    Session tokens store username + role so the handler can enforce
    per-role permissions without a DB lookup on every request.

    Migration:
      Old sessions (no username/role columns) are invalidated on startup
      so everyone re-authenticates with username + password.
    """

    def __init__(self, conn_fn):
        self._conn = conn_fn
        self._setup()

    # ── Schema ────────────────────────────────────────────────────────────────

    def _setup(self):
        c = self._conn()
        c.execute("PRAGMA journal_mode = WAL")
        c.execute("PRAGMA synchronous  = NORMAL")
        c.execute("PRAGMA cache_size   = -2000")
        c.execute("""
            CREATE TABLE IF NOT EXISTS auth (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                username   TEXT NOT NULL DEFAULT '',
                role       TEXT NOT NULL DEFAULT 'admin'
            )
        """)
        # Upgrade: add columns to existing sessions table if absent
        cols = {r[1] for r in c.execute("PRAGMA table_info(sessions)").fetchall()}
        if "username" not in cols:
            c.execute("ALTER TABLE sessions ADD COLUMN username TEXT DEFAULT ''")
        if "role" not in cols:
            c.execute("ALTER TABLE sessions ADD COLUMN role TEXT DEFAULT 'admin'")
        c.execute("CREATE INDEX IF NOT EXISTS idx_sess_exp ON sessions (expires_at)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_sess_tok ON sessions (token)")
        c.commit()

    # ── Single-password (legacy / emergency fallback) ─────────────────────────

    def set_password(self, password: str):
        c = self._conn()
        c.execute(
            "INSERT OR REPLACE INTO auth (key, value) VALUES ('pw_hash', ?)",
            (hash_password(password),),
        )
        c.commit()
        log.info("Single-password updated.")

    def get_hash(self) -> str | None:
        row = self._conn().execute(
            "SELECT value FROM auth WHERE key = 'pw_hash'"
        ).fetchone()
        return row[0] if row else None

    def check_password(self, password: str) -> bool:
        """Check against the legacy single stored password.
        Not used for login since 1.4.4 (see Handler._do_login)."""
        stored = self.get_hash()
        return bool(stored and verify_password(password, stored))

    # ── Sessions ──────────────────────────────────────────────────────────────

    def create_session(self, username: str = "", role: str = "admin") -> str:
        """Create a session token carrying username and role."""
        token = secrets.token_hex(32)
        now   = time.time()
        c     = self._conn()
        c.execute(
            """INSERT INTO sessions
               (token, created_at, expires_at, username, role)
               VALUES (?, ?, ?, ?, ?)""",
            (token, now, now + SESSION_TTL, username, role),
        )
        c.commit()
        return token

    def validate_session(self, token: str) -> bool:
        """Return True if token exists and has not expired."""
        return self.get_session(token) is not None

    def get_session(self, token: str) -> dict | None:
        """
        Return session dict {token, username, role} if valid,
        or None if missing / expired / its user is gone or disabled.

        Since 1.4.4 the session is checked against the users table on every
        call, and username/role come from the user's CURRENT row — so disabling,
        deleting or demoting a user takes effect on their next request instead
        of when the 7-day session expires. Fails closed if the lookup errors.
        """
        if not token:
            return None
        c   = self._conn()
        row = c.execute(
            "SELECT token, expires_at, username, role "
            "FROM sessions WHERE token = ?",
            (token,),
        ).fetchone()
        if not row:
            return None
        if time.time() > row["expires_at"]:
            c.execute("DELETE FROM sessions WHERE token = ?", (token,))
            c.commit()
            return None
        try:
            user = c.execute(
                "SELECT username, role, enabled FROM users "
                "WHERE username = ? COLLATE NOCASE",
                (row["username"],),
            ).fetchone()
        except sqlite3.Error as e:
            log.warning("Session user lookup failed (denying): %s", e)
            return None
        if not user or not user["enabled"]:
            c.execute("DELETE FROM sessions WHERE token = ?", (token,))
            c.commit()
            return None
        return {"token": row["token"], "username": user["username"],
                "role": user["role"]}

    def revoke_session(self, token: str):
        self._conn().execute(
            "DELETE FROM sessions WHERE token = ?", (token,)
        )
        self._conn().commit()

    def revoke_user_sessions(self, username: str,
                             keep_token: str | None = None) -> int:
        """Delete every session belonging to username (case-insensitive),
        optionally keeping one token (the caller's own browser)."""
        c = self._conn()
        if keep_token:
            cur = c.execute(
                "DELETE FROM sessions WHERE username = ? COLLATE NOCASE "
                "AND token != ?", (username, keep_token))
        else:
            cur = c.execute(
                "DELETE FROM sessions WHERE username = ? COLLATE NOCASE",
                (username,))
        c.commit()
        if cur.rowcount:
            log.info("Revoked %d session(s) for user %r.", cur.rowcount, username)
        return cur.rowcount

    def rename_user_sessions(self, old: str, new: str):
        """Keep a renamed user's sessions attached to that user."""
        c = self._conn()
        c.execute("UPDATE sessions SET username = ? "
                  "WHERE username = ? COLLATE NOCASE", (new, old))
        c.commit()

    def purge_orphaned(self) -> int:
        """Startup hygiene: delete sessions whose user no longer exists or is
        disabled. Sessions are keyed by username, so without this a later
        account created with the same name (or re-enabling the account) could
        revive tokens issued before 1.4.4, which never revoked them."""
        c = self._conn()
        try:
            cur = c.execute(
                "DELETE FROM sessions WHERE NOT EXISTS ("
                "  SELECT 1 FROM users u WHERE u.username = sessions.username "
                "  COLLATE NOCASE AND u.enabled = 1)")
        except sqlite3.Error as e:
            log.warning("Orphaned-session purge skipped: %s", e)
            return 0
        c.commit()
        if cur.rowcount:
            log.info("Removed %d session(s) of deleted or disabled users.", cur.rowcount)
        return cur.rowcount

    def purge_expired(self):
        cur = self._conn().execute(
            "DELETE FROM sessions WHERE expires_at < ?", (time.time(),)
        )
        self._conn().commit()
        if cur.rowcount:
            log.info("Purged %d expired sessions.", cur.rowcount)
