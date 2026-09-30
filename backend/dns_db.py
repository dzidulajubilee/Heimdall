"""
Heimdall IDS Dashboard — DNS Database
Dedicated SQLite store for DNS events, kept separate from the main
events.db so high-frequency DNS traffic never contends with alert writes.

Thread-safety follows the same threading.local pattern as AlertDB and
ConfigDB: each handler thread opens its own connection on first use.

Schema
------
  dns_events — one row per Suricata dns event_type record
"""

import json
import logging
import re
import sqlite3
import threading
import time
from datetime import datetime

from config import RETAIN_DAYS

log = logging.getLogger("heimdall.dns_db")

# Pre-compiled timestamp normalisation — mirrors AlertDB._to_epoch
_RE_USEC = re.compile(r"\.\d+")
_RE_TZ   = re.compile(r"([+-]\d{2})(\d{2})$|Z$")   # ±HHMM → ±HH:MM (Python 3.10)


class DNSDB:
    """
    Thread-safe SQLite wrapper for the dns_events table.

    All methods are safe to call from multiple handler threads
    simultaneously; each thread gets its own sqlite3.Connection
    via threading.local so there is no cross-thread locking.
    """

    def __init__(self, path: str, retain_days: int = RETAIN_DAYS):
        self.path        = str(path)
        self.retain_days = retain_days
        self._local      = threading.local()
        self._conn()   # initialise schema on the main thread
        log.info("DNS database: %s", self.path)

    # ── Connection / schema ───────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            c = sqlite3.connect(self.path, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode = WAL")
            c.execute("PRAGMA synchronous  = NORMAL")
            c.execute("PRAGMA cache_size   = -4000")
            c.execute("PRAGMA temp_store   = MEMORY")

            c.execute("""CREATE TABLE IF NOT EXISTS dns_events (
                id        TEXT PRIMARY KEY,
                ts        TEXT NOT NULL,
                ts_epoch  REAL NOT NULL,
                src_ip    TEXT,
                src_port  INTEGER,
                dst_ip    TEXT,
                dst_port  INTEGER,
                iface     TEXT,
                flow_id   INTEGER,
                tx_id     INTEGER,
                dns_type  TEXT,
                rrname    TEXT,
                rrtype    TEXT,
                rcode     TEXT,
                ttl       INTEGER,
                answers   TEXT
            )""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_d_ts     ON dns_events (ts_epoch)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_d_rrname ON dns_events (rrname)")
            c.commit()
            self._local.conn = c
        return self._local.conn

    # ── Timestamp helper ──────────────────────────────────────────────────────

    def _to_epoch(self, ts: str) -> float:
        try:
            ts = _RE_USEC.sub("", ts)
            ts = _RE_TZ.sub(lambda m: f"{m.group(1)}:{m.group(2)}" if m.group(1) else "+00:00", ts)
            return datetime.fromisoformat(ts).timestamp()
        except (ValueError, TypeError):
            return time.time()

    # ── Write ─────────────────────────────────────────────────────────────────

    def insert(self, evt: dict):
        """Insert one raw Suricata dns event. Silently ignores duplicates."""
        d            = evt.get("dns", {})
        ts           = evt.get("timestamp", "")
        uid          = f"{evt.get('flow_id', 0)}-{d.get('tx_id', 0)}-{d.get('type', '')}"
        answers_json = json.dumps(d.get("answers", d.get("grouped", {})) or [])
        try:
            c = self._conn()
            c.execute(
                """INSERT OR IGNORE INTO dns_events
                   (id, ts, ts_epoch, src_ip, src_port, dst_ip, dst_port,
                    iface, flow_id, tx_id, dns_type, rrname, rrtype, rcode, ttl, answers)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (uid, ts, self._to_epoch(ts),
                 evt.get("src_ip", ""),    evt.get("src_port", 0),
                 evt.get("dest_ip", ""),   evt.get("dest_port", 0),
                 evt.get("in_iface", ""),  evt.get("flow_id", 0),
                 d.get("tx_id", 0),        d.get("type", ""),
                 d.get("rrname", ""),      d.get("rrtype", ""),
                 d.get("rcode", ""),       d.get("ttl", 0),
                 answers_json),
            )
            c.commit()
        except sqlite3.Error as e:
            log.warning("DNS insert error: %s", e)

    # ── Read ──────────────────────────────────────────────────────────────────

    def fetch(self, days: int | None = None, limit: int = 5000) -> list[dict]:
        """Return recent DNS records, newest first."""
        cutoff = time.time() - (days or self.retain_days) * 86400
        rows = self._conn().execute(
            """SELECT id, ts, src_ip, src_port, dst_ip, dst_port,
                      flow_id, tx_id, dns_type, rrname, rrtype, rcode, ttl, answers
               FROM dns_events
               WHERE ts_epoch >= ?
               ORDER BY ts_epoch DESC
               LIMIT ?""",
            (cutoff, limit),
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:    d["answers"] = json.loads(d.get("answers") or "[]")
            except: d["answers"] = []
            result.append(d)
        return result

    def count(self) -> int:
        return self._conn().execute(
            "SELECT COUNT(*) FROM dns_events"
        ).fetchone()[0]

    def count_recent(self) -> int:
        cutoff = time.time() - self.retain_days * 86400
        return self._conn().execute(
            "SELECT COUNT(*) FROM dns_events WHERE ts_epoch >= ?", (cutoff,)
        ).fetchone()[0]

    # ── Delete ────────────────────────────────────────────────────────────────

    def clear(self) -> int:
        """Delete all DNS records. Returns count of deleted rows."""
        c   = self._conn()
        cur = c.execute("DELETE FROM dns_events")
        c.commit()
        log.info("DNS events cleared — %d rows deleted.", cur.rowcount)
        return cur.rowcount

    def purge_old(self):
        """Delete records older than retain_days. Called by the purge thread."""
        cutoff = time.time() - self.retain_days * 86400
        c      = self._conn()
        cur    = c.execute(
            "DELETE FROM dns_events WHERE ts_epoch < ?", (cutoff,)
        )
        c.commit()
        if cur.rowcount:
            log.info("DNS: purged %d rows older than %d days.",
                     cur.rowcount, self.retain_days)
