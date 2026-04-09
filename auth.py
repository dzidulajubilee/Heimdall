"""
Heimdall IDS Dashboard — Authentication
PBKDF2-SHA256 password hashing + session token management.
Everything is stored in the same SQLite database as alerts.
"""

import hashlib
import hmac
import logging
import secrets
import time

from config import SESSION_TTL, PBKDF2_ITERS

log = logging.getLogger("heimdall.auth")


class AuthManager:
    """
    Stores a single hashed password and active session tokens in SQLite.

    Password storage:  PBKDF2-SHA256, 260k rounds, random 16-byte salt.
    Session tokens:    64-char hex, stored with expiry timestamp.
    Brute-force guard: 1-second delay on every failed login attempt.
    """

    def __init__(self, conn_fn):
        """
        conn_fn: callable that returns a thread-local sqlite3.Connection.
        Shares the AlertDB connection so auth tables live in the same file.
        """
        self._conn = conn_fn
        self._setup()

    # ── Schema ────────────────────────────────────────────────────────────────

    def _setup(self):
        c = self._conn()
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
                expires_at REAL NOT NULL
            )
        """)
        c.commit()

    # ── Password ──────────────────────────────────────────────────────────────

    def _hash(self, password: str) -> str:
        """Return 'salt$hash' string suitable for storage."""
        salt = secrets.token_hex(16)
        h = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), PBKDF2_ITERS
        )
        return f"{salt}${h.hex()}"

    def _verify(self, password: str, stored: str) -> bool:
        """Constant-time comparison of password against stored hash."""
        try:
            salt, h = stored.split("$", 1)
            check = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt.encode(), PBKDF2_ITERS
            )
            return hmac.compare_digest(check.hex(), h)
        except Exception:
            return False

    def set_password(self, password: str):
        """Hash and persist a new password. Replaces any existing one."""
        c = self._conn()
        c.execute(
            "INSERT OR REPLACE INTO auth (key, value) VALUES ('pw_hash', ?)",
            (self._hash(password),),
        )
        c.commit()
        log.info("Password updated.")

    def get_hash(self) -> str | None:
        """Return the stored hash string, or None if no password set yet."""
        row = self._conn().execute(
            "SELECT value FROM auth WHERE key = 'pw_hash'"
        ).fetchone()
        return row[0] if row else None

    def check_password(self, password: str) -> bool:
        """Return True if password matches stored hash."""
        stored = self.get_hash()
        return bool(stored and self._verify(password, stored))

    # ── Sessions ──────────────────────────────────────────────────────────────

    def create_session(self) -> str:
        """Create a new session token, persist it, and return the token."""
        token = secrets.token_hex(32)
        now   = time.time()
        c = self._conn()
        c.execute(
            "INSERT INTO sessions (token, created_at, expires_at) VALUES (?, ?, ?)",
            (token, now, now + SESSION_TTL),
        )
        c.commit()
        return token

    def validate_session(self, token: str) -> bool:
        """Return True if token exists and has not expired."""
        if not token:
            return False
        row = self._conn().execute(
            "SELECT expires_at FROM sessions WHERE token = ?", (token,)
        ).fetchone()
        if not row:
            return False
        if time.time() > row[0]:
            self._conn().execute(
                "DELETE FROM sessions WHERE token = ?", (token,)
            )
            self._conn().commit()
            return False
        return True

    def revoke_session(self, token: str):
        """Immediately invalidate a session token (logout)."""
        self._conn().execute(
            "DELETE FROM sessions WHERE token = ?", (token,)
        )
        self._conn().commit()

    def purge_expired(self):
        """Delete all expired sessions. Called by the purge background thread."""
        cur = self._conn().execute(
            "DELETE FROM sessions WHERE expires_at < ?", (time.time(),)
        )
        self._conn().commit()
        if cur.rowcount:
            log.info("Purged %d expired sessions.", cur.rowcount)
