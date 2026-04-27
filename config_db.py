"""
Heimdall IDS Dashboard — Config Database
Dedicated SQLite connection pool for low-write configuration tables:
  auth, sessions, users, webhooks

Follows the same threading.local pattern as AlertDB so each handler
thread gets its own connection, avoiding cross-thread lock contention.

Keeping config separate from events.db means high-volume alert writes
never contend with auth or settings reads.
"""

import logging
import sqlite3
import threading

log = logging.getLogger("heimdall.config_db")


class ConfigDB:
    """
    Thread-safe SQLite wrapper for configuration tables.
    Schema creation is delegated to the individual managers
    (AuthManager, UserManager, WebhookDB) that own each table —
    ConfigDB just provides and owns the connection.
    """

    def __init__(self, path: str):
        self.path   = str(path)
        self._local = threading.local()
        self._conn()          # open + configure connection on the main thread
        log.info("Config database: %s", self.path)

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            c = sqlite3.connect(self.path, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode = WAL")
            c.execute("PRAGMA synchronous  = NORMAL")
            c.commit()
            self._local.conn = c
        return self._local.conn
