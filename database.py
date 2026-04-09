"""
Heimdall IDS Dashboard — Database
Thread-safe SQLite wrapper for alert storage and retrieval.
Each thread gets its own connection via threading.local().
"""

import json
import logging
import sqlite3
import threading
import time

from config import RETAIN_DAYS

log = logging.getLogger("heimdall.db")


class AlertDB:
    """
    Manages the alerts table in SQLite.

    Design notes:
    - WAL journal mode for concurrent read/write without blocking.
    - threading.local() ensures each thread has its own connection,
      avoiding sqlite3's check_same_thread restriction safely.
    - INSERT OR IGNORE deduplicates alerts by their generated ID.
    """

    def __init__(self, path: str, retain_days: int = RETAIN_DAYS):
        self.path        = str(path)
        self.retain_days = retain_days
        self._local      = threading.local()
        self._conn()   # create schema on the main thread at startup
        log.info("Database: %s  (retain %d days)", self.path, self.retain_days)

    # ── Connection / schema ───────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        """Return the thread-local connection, creating it if needed."""
        if not hasattr(self._local, "conn"):
            c = sqlite3.connect(self.path, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode = WAL")
            c.execute("PRAGMA synchronous  = NORMAL")
            c.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id        TEXT PRIMARY KEY,
                    ts        TEXT    NOT NULL,
                    ts_epoch  REAL    NOT NULL,
                    src_ip    TEXT,
                    src_port  INTEGER,
                    dst_ip    TEXT,
                    dst_port  INTEGER,
                    proto     TEXT,
                    iface     TEXT,
                    flow_id   INTEGER,
                    sig_id    INTEGER,
                    sig_msg   TEXT,
                    category  TEXT,
                    severity  TEXT,
                    action    TEXT,
                    raw_json  TEXT
                )
            """)
            c.execute(
                "CREATE INDEX IF NOT EXISTS idx_ts  ON alerts (ts_epoch)"
            )
            c.execute(
                "CREATE INDEX IF NOT EXISTS idx_sev ON alerts (severity)"
            )
            c.commit()
            self._local.conn = c
        return self._local.conn

    # ── Timestamp helper ──────────────────────────────────────────────────────

    def _to_epoch(self, ts: str) -> float:
        """Parse a Suricata ISO-8601 timestamp into a Unix epoch float."""
        from datetime import datetime
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(ts, fmt).timestamp()
            except ValueError:
                pass
        return time.time()

    # ── Write ─────────────────────────────────────────────────────────────────

    def insert(self, alert: dict):
        """Persist a single alert dict. Silently ignores duplicates."""
        try:
            self._conn().execute(
                """
                INSERT OR IGNORE INTO alerts
                    (id, ts, ts_epoch, src_ip, src_port, dst_ip, dst_port,
                     proto, iface, flow_id, sig_id, sig_msg, category,
                     severity, action, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["id"],
                    alert.get("ts", ""),
                    self._to_epoch(alert.get("ts", "")),
                    alert.get("src_ip", ""),
                    alert.get("src_port", 0),
                    alert.get("dst_ip", ""),
                    alert.get("dst_port", 0),
                    alert.get("proto", ""),
                    alert.get("iface", ""),
                    alert.get("flow_id", 0),
                    alert.get("sig_id", 0),
                    alert.get("sig_msg", ""),
                    alert.get("category", ""),
                    alert.get("severity", "info"),
                    alert.get("action", "allowed"),
                    json.dumps(alert.get("raw", {})),
                ),
            )
            self._conn().commit()
        except sqlite3.Error as e:
            log.warning("DB insert failed: %s", e)

    # ── Read ──────────────────────────────────────────────────────────────────

    def fetch_recent(self, days: int | None = None, limit: int = 5000) -> list[dict]:
        """Return up to `limit` alerts from the last `days` days, newest first."""
        cutoff = time.time() - (days or self.retain_days) * 86400
        rows = self._conn().execute(
            """
            SELECT id, ts, src_ip, src_port, dst_ip, dst_port,
                   proto, iface, flow_id, sig_id, sig_msg,
                   category, severity, action, raw_json
            FROM   alerts
            WHERE  ts_epoch >= ?
            ORDER  BY ts_epoch DESC
            LIMIT  ?
            """,
            (cutoff, limit),
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:
                d["raw"] = json.loads(d.pop("raw_json", "{}"))
            except Exception:
                d["raw"] = {}
            result.append(d)
        return result

    # ── Maintenance ───────────────────────────────────────────────────────────

    def purge_old(self):
        """Delete alerts older than retain_days. Called hourly by purge_thread."""
        cutoff = time.time() - self.retain_days * 86400
        cur = self._conn().execute(
            "DELETE FROM alerts WHERE ts_epoch < ?", (cutoff,)
        )
        self._conn().commit()
        if cur.rowcount:
            log.info(
                "Purged %d alerts older than %d days.",
                cur.rowcount, self.retain_days,
            )

    def clear_all(self) -> int:
        """Delete every alert from the database. Returns the count deleted."""
        cur = self._conn().execute("DELETE FROM alerts")
        self._conn().commit()
        log.info("Database cleared — %d alerts deleted.", cur.rowcount)
        return cur.rowcount

    def stats(self) -> dict:
        """Return summary counts for the health endpoint."""
        c      = self._conn()
        total  = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        cutoff = time.time() - self.retain_days * 86400
        recent = c.execute(
            "SELECT COUNT(*) FROM alerts WHERE ts_epoch >= ?", (cutoff,)
        ).fetchone()[0]
        oldest = c.execute("SELECT MIN(ts) FROM alerts").fetchone()[0]
        return {"total": total, "recent": recent, "oldest": oldest}
