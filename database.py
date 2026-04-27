"""
Heimdall IDS Dashboard — Database (Version 2)
Thread-safe SQLite wrapper for all event types:
  alerts, flows, dns_events, http_events, alert_meta, alert_notes.
Each thread gets its own connection via threading.local().
"""

import json
import logging
import re
import sqlite3
import threading
import time
from datetime import datetime

from config import RETAIN_DAYS

log = logging.getLogger("heimdall.db")

# ── Pre-compiled timestamp normalisation patterns ─────────────────────────────
# Used in _to_epoch() on every event ingested — compiling once at module load
# avoids repeated re.compile() overhead on the hottest path in the codebase.
_RE_USEC = re.compile(r"\.\d+")           # strip fractional seconds
_RE_TZ   = re.compile(r"\+0000$|Z$")     # normalise +0000 / Z → +00:00

# Tables that are allowed to appear in dynamically-built SQL statements.
# Prevents any future caller from accidentally injecting an untrusted string.
_ALLOWED_TABLES = frozenset({
    "alerts", "flows", "dns_events", "http_events",
    "alert_meta", "alert_notes", "alert_activity",
})

# Maximum IDs accepted in a single delete_by_ids() call.
# SQLite's default SQLITE_MAX_VARIABLE_NUMBER is 999; staying well under
# it prevents OperationalError on large batches.
_MAX_DELETE_IDS = 500


def _safe_table(name: str) -> str:
    """Return `name` unchanged if it is a known table, raise ValueError otherwise."""
    if name not in _ALLOWED_TABLES:
        raise ValueError(f"Disallowed table name: {name!r}")
    return name


class AlertDB:
    def __init__(self, path: str, retain_days: int = RETAIN_DAYS):
        self.path        = str(path)
        self.retain_days = retain_days
        self._local      = threading.local()
        self._conn()
        log.info("Database: %s  (retain %d days)", self.path, self.retain_days)

    # ── Connection / schema ───────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            c = sqlite3.connect(self.path, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode = WAL")
            c.execute("PRAGMA synchronous  = NORMAL")

            c.execute("""CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY, ts TEXT NOT NULL, ts_epoch REAL NOT NULL,
                src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
                proto TEXT, iface TEXT, flow_id INTEGER, sig_id INTEGER,
                sig_msg TEXT, category TEXT, severity TEXT, action TEXT, raw_json TEXT)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_a_ts     ON alerts (ts_epoch)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_a_sev    ON alerts (severity)")
            # Composite index — accelerates the common pattern of time-range
            # filtering combined with severity grouping (charts, filtered views).
            c.execute("CREATE INDEX IF NOT EXISTS idx_a_ts_sev ON alerts (ts_epoch, severity)")

            c.execute("""CREATE TABLE IF NOT EXISTS flows (
                flow_id INTEGER PRIMARY KEY, ts TEXT NOT NULL, ts_epoch REAL NOT NULL,
                src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
                proto TEXT, app_proto TEXT, iface TEXT,
                pkts_toserver INTEGER DEFAULT 0, pkts_toclient INTEGER DEFAULT 0,
                bytes_toserver INTEGER DEFAULT 0, bytes_toclient INTEGER DEFAULT 0,
                duration_s REAL DEFAULT 0, state TEXT, reason TEXT, alerted INTEGER DEFAULT 0)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_f_ts ON flows (ts_epoch)")

            c.execute("""CREATE TABLE IF NOT EXISTS dns_events (
                id TEXT PRIMARY KEY, ts TEXT NOT NULL, ts_epoch REAL NOT NULL,
                src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
                iface TEXT, flow_id INTEGER, tx_id INTEGER, dns_type TEXT,
                rrname TEXT, rrtype TEXT, rcode TEXT, ttl INTEGER, answers TEXT)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_d_ts     ON dns_events (ts_epoch)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_d_rrname ON dns_events (rrname)")

            c.execute("""CREATE TABLE IF NOT EXISTS http_events (
                id TEXT PRIMARY KEY, ts TEXT NOT NULL, ts_epoch REAL NOT NULL,
                src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
                iface TEXT, flow_id INTEGER, hostname TEXT, url TEXT,
                method TEXT, status INTEGER, user_agent TEXT, content_type TEXT,
                req_bytes INTEGER DEFAULT 0, resp_bytes INTEGER DEFAULT 0, protocol TEXT)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_h_ts       ON http_events (ts_epoch)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_h_hostname ON http_events (hostname)")

            # ── Alert metadata: per-alert triage status
            c.execute("""CREATE TABLE IF NOT EXISTS alert_meta (
                alert_id   TEXT PRIMARY KEY,
                status     TEXT,
                updated_by TEXT NOT NULL DEFAULT '',
                updated_at REAL NOT NULL DEFAULT 0
            )""")

            # ── Alert notes: timestamped analyst notes
            c.execute("""CREATE TABLE IF NOT EXISTS alert_notes (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id   TEXT NOT NULL,
                username   TEXT NOT NULL DEFAULT '',
                note       TEXT NOT NULL,
                created_at REAL NOT NULL
            )""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_an_alert ON alert_notes (alert_id)")

            # ── Alert activity: full audit log of every status change
            c.execute("""CREATE TABLE IF NOT EXISTS alert_activity (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id   TEXT NOT NULL,
                username   TEXT NOT NULL DEFAULT '',
                action     TEXT NOT NULL,
                created_at REAL NOT NULL
            )""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_act_alert ON alert_activity (alert_id)")

            c.commit()
            self._local.conn = c
        return self._local.conn

    def _to_epoch(self, ts: str) -> float:
        """
        Convert a Suricata ISO-8601 timestamp to a Unix epoch float.
        Uses pre-compiled regexes (_RE_USEC, _RE_TZ) to normalise the
        string before a single datetime.fromisoformat() call, avoiding
        the try-two-formats loop that was in place previously.
        """
        try:
            ts = _RE_USEC.sub("", ts)             # drop microseconds
            ts = _RE_TZ.sub("+00:00", ts)          # normalise timezone
            return datetime.fromisoformat(ts).timestamp()
        except (ValueError, TypeError):
            return time.time()

    # ── Alerts ────────────────────────────────────────────────────────────────

    def insert(self, alert: dict):
        try:
            c = self._conn()
            c.execute(
                """INSERT OR IGNORE INTO alerts
                   (id,ts,ts_epoch,src_ip,src_port,dst_ip,dst_port,
                    proto,iface,flow_id,sig_id,sig_msg,category,severity,action,raw_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (alert["id"], alert.get("ts", ""), self._to_epoch(alert.get("ts", "")),
                 alert.get("src_ip", ""), alert.get("src_port", 0),
                 alert.get("dst_ip", ""), alert.get("dst_port", 0),
                 alert.get("proto", ""), alert.get("iface", ""), alert.get("flow_id", 0),
                 alert.get("sig_id", 0), alert.get("sig_msg", ""), alert.get("category", ""),
                 alert.get("severity", "info"), alert.get("action", "allowed"),
                 json.dumps(alert.get("raw", {}))))
            c.commit()
        except sqlite3.Error as e:
            log.warning("DB insert (alert): %s", e)

    def fetch_recent(self, days=None, limit=5000):
        cutoff = time.time() - (days or self.retain_days) * 86400
        rows = self._conn().execute(
            """SELECT a.id,a.ts,a.src_ip,a.src_port,a.dst_ip,a.dst_port,a.proto,a.iface,
                      a.flow_id,a.sig_id,a.sig_msg,a.category,a.severity,a.action,a.raw_json,
                      m.status, m.updated_by, m.updated_at
               FROM alerts a
               LEFT JOIN alert_meta m ON m.alert_id = a.id
               WHERE a.ts_epoch>=? ORDER BY a.ts_epoch DESC LIMIT ?""",
            (cutoff, limit)).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:    d["raw"] = json.loads(d.pop("raw_json", "{}"))
            except: d["raw"] = {}
            result.append(d)
        return result

    # ── Alert meta: status + notes ────────────────────────────────────────────

    def get_alert_meta(self, alert_id: str) -> dict:
        """Return status, notes, and full activity log for one alert."""
        status_row = self._conn().execute(
            "SELECT status, updated_by, updated_at FROM alert_meta WHERE alert_id = ?",
            (alert_id,)
        ).fetchone()
        notes_rows = self._conn().execute(
            "SELECT username, note, created_at FROM alert_notes "
            "WHERE alert_id = ? ORDER BY created_at ASC",
            (alert_id,)
        ).fetchall()
        activity_rows = self._conn().execute(
            "SELECT username, action, created_at FROM alert_activity "
            "WHERE alert_id = ? ORDER BY created_at ASC",
            (alert_id,)
        ).fetchall()
        return {
            "status":     status_row["status"]     if status_row else None,
            "updated_by": status_row["updated_by"] if status_row else "",
            "updated_at": status_row["updated_at"] if status_row else 0,
            "notes":      [dict(r) for r in notes_rows],
            "activity":   [dict(r) for r in activity_rows],
        }

    def set_alert_status(self, alert_id: str, status, username: str):
        """Set (or clear) the triage status on an alert, and log the change."""
        now = time.time()
        c   = self._conn()
        c.execute(
            """INSERT INTO alert_meta (alert_id, status, updated_by, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(alert_id) DO UPDATE SET
                 status     = excluded.status,
                 updated_by = excluded.updated_by,
                 updated_at = excluded.updated_at""",
            (alert_id, status, username, now)
        )
        action = "Status cleared" if status is None else f"Marked as {status}"
        c.execute(
            "INSERT INTO alert_activity (alert_id, username, action, created_at) VALUES (?,?,?,?)",
            (alert_id, username, action, now)
        )
        c.commit()

    def bulk_set_status(self, alert_ids: list, status: str, username: str):
        """
        Bulk-set triage status on many alerts at once.
        Uses executemany() for both the upsert and activity rows —
        O(1) round-trips regardless of batch size, with a single commit.
        """
        now    = time.time()
        action = f"Marked as {status}"
        c      = self._conn()
        c.executemany(
            """INSERT INTO alert_meta (alert_id, status, updated_by, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(alert_id) DO UPDATE SET
                 status     = excluded.status,
                 updated_by = excluded.updated_by,
                 updated_at = excluded.updated_at""",
            [(aid, status, username, now) for aid in alert_ids],
        )
        c.executemany(
            "INSERT INTO alert_activity (alert_id, username, action, created_at) "
            "VALUES (?,?,?,?)",
            [(aid, username, action, now) for aid in alert_ids],
        )
        c.commit()

    def add_note(self, alert_id: str, username: str, note: str) -> dict:
        """Append a timestamped note to an alert."""
        now = time.time()
        c   = self._conn()
        c.execute(
            "INSERT INTO alert_notes (alert_id, username, note, created_at) VALUES (?,?,?,?)",
            (alert_id, username, note, now)
        )
        c.commit()
        return {"alert_id": alert_id, "username": username, "note": note, "created_at": now}

    def delete_by_ids(self, ids: list) -> int:
        """
        Permanently delete specific alerts and all associated metadata
        (alert_meta, alert_notes, alert_activity) in a single transaction.

        Safety measures:
          - Coerces all IDs to str before use.
          - Caps at _MAX_DELETE_IDS (500) to stay under SQLite's
            SQLITE_MAX_VARIABLE_NUMBER limit (default 999).

        Returns the number of alert rows deleted.
        """
        if not ids:
            return 0
        ids  = [str(i) for i in ids][:_MAX_DELETE_IDS]
        ph   = ",".join("?" * len(ids))
        c    = self._conn()
        c.execute(f"DELETE FROM alert_meta     WHERE alert_id IN ({ph})", ids)
        c.execute(f"DELETE FROM alert_notes    WHERE alert_id IN ({ph})", ids)
        c.execute(f"DELETE FROM alert_activity WHERE alert_id IN ({ph})", ids)
        cur = c.execute(f"DELETE FROM alerts WHERE id IN ({ph})", ids)
        c.commit()
        log.info("Deleted %d alerts by ID.", cur.rowcount)
        return cur.rowcount

    # ── Flows ─────────────────────────────────────────────────────────────────

    def insert_flow(self, evt: dict):
        f   = evt.get("flow", {})
        ts  = evt.get("timestamp", "")
        dur = 0.0
        try:
            # datetime is now imported at module level
            t1  = datetime.fromisoformat(f.get("start", "").replace("+0000", "+00:00"))
            t2  = datetime.fromisoformat(f.get("end",   "").replace("+0000", "+00:00"))
            dur = (t2 - t1).total_seconds()
        except Exception:
            pass
        try:
            c = self._conn()
            c.execute(
                """INSERT OR IGNORE INTO flows
                   (flow_id,ts,ts_epoch,src_ip,src_port,dst_ip,dst_port,
                    proto,app_proto,iface,pkts_toserver,pkts_toclient,
                    bytes_toserver,bytes_toclient,duration_s,state,reason,alerted)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (evt.get("flow_id", 0), ts, self._to_epoch(ts),
                 evt.get("src_ip", ""), evt.get("src_port", 0),
                 evt.get("dest_ip", ""), evt.get("dest_port", 0),
                 evt.get("proto", "").upper(), evt.get("app_proto", ""),
                 evt.get("in_iface", ""),
                 f.get("pkts_toserver", 0), f.get("pkts_toclient", 0),
                 f.get("bytes_toserver", 0), f.get("bytes_toclient", 0),
                 dur, f.get("state", ""), f.get("reason", ""),
                 1 if f.get("alerted") else 0))
            c.commit()
        except sqlite3.Error as e:
            log.warning("DB insert (flow): %s", e)

    def fetch_flows(self, days=None, limit=5000):
        cutoff = time.time() - (days or self.retain_days) * 86400
        rows = self._conn().execute(
            """SELECT flow_id,ts,src_ip,src_port,dst_ip,dst_port,proto,app_proto,
                      pkts_toserver,pkts_toclient,bytes_toserver,bytes_toclient,
                      duration_s,state,reason,alerted
               FROM flows WHERE ts_epoch>=? ORDER BY ts_epoch DESC LIMIT ?""",
            (cutoff, limit)).fetchall()
        return [dict(r) for r in rows]

    # ── DNS ───────────────────────────────────────────────────────────────────

    def insert_dns(self, evt: dict):
        d            = evt.get("dns", {})
        ts           = evt.get("timestamp", "")
        uid          = f"{evt.get('flow_id',0)}-{d.get('tx_id',0)}-{d.get('type','')}"
        answers_json = json.dumps(d.get("answers", d.get("grouped", {})) or [])
        try:
            c = self._conn()
            c.execute(
                """INSERT OR IGNORE INTO dns_events
                   (id,ts,ts_epoch,src_ip,src_port,dst_ip,dst_port,
                    iface,flow_id,tx_id,dns_type,rrname,rrtype,rcode,ttl,answers)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (uid, ts, self._to_epoch(ts),
                 evt.get("src_ip", ""), evt.get("src_port", 0),
                 evt.get("dest_ip", ""), evt.get("dest_port", 0),
                 evt.get("in_iface", ""), evt.get("flow_id", 0),
                 d.get("tx_id", 0), d.get("type", ""),
                 d.get("rrname", ""), d.get("rrtype", ""),
                 d.get("rcode", ""), d.get("ttl", 0), answers_json))
            c.commit()
        except sqlite3.Error as e:
            log.warning("DB insert (dns): %s", e)

    def fetch_dns(self, days=None, limit=5000):
        cutoff = time.time() - (days or self.retain_days) * 86400
        rows = self._conn().execute(
            """SELECT id,ts,src_ip,src_port,dst_ip,dst_port,
                      flow_id,tx_id,dns_type,rrname,rrtype,rcode,ttl,answers
               FROM dns_events WHERE ts_epoch>=? ORDER BY ts_epoch DESC LIMIT ?""",
            (cutoff, limit)).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:    d["answers"] = json.loads(d.get("answers") or "[]")
            except: d["answers"] = []
            result.append(d)
        return result

    def clear_dns(self) -> int:
        c   = self._conn()
        cur = c.execute("DELETE FROM dns_events")
        c.commit()
        log.info("DNS events cleared — %d rows deleted.", cur.rowcount)
        return cur.rowcount

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def insert_http(self, evt: dict):
        h   = evt.get("http", {})
        ts  = evt.get("timestamp", "")
        uid = f"{evt.get('flow_id',0)}-{evt.get('tx_id',0)}-http"
        try:
            c = self._conn()
            c.execute(
                """INSERT OR IGNORE INTO http_events
                   (id,ts,ts_epoch,src_ip,src_port,dst_ip,dst_port,
                    iface,flow_id,hostname,url,method,status,
                    user_agent,content_type,req_bytes,resp_bytes,protocol)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (uid, ts, self._to_epoch(ts),
                 evt.get("src_ip", ""), evt.get("src_port", 0),
                 evt.get("dest_ip", ""), evt.get("dest_port", 0),
                 evt.get("in_iface", ""), evt.get("flow_id", 0),
                 h.get("hostname", ""), h.get("url", ""),
                 h.get("http_method", ""), h.get("status", 0),
                 h.get("http_user_agent", ""), h.get("http_content_type", ""),
                 h.get("request_headers_raw_len", h.get("length", 0)),
                 h.get("response_headers_raw_len", h.get("response_len", 0)),
                 h.get("protocol", "")))
            c.commit()
        except sqlite3.Error as e:
            log.warning("DB insert (http): %s", e)

    def fetch_http(self, days=None, limit=5000):
        cutoff = time.time() - (days or self.retain_days) * 86400
        rows = self._conn().execute(
            """SELECT id,ts,src_ip,src_port,dst_ip,dst_port,flow_id,
                      hostname,url,method,status,user_agent,content_type,
                      req_bytes,resp_bytes,protocol
               FROM http_events WHERE ts_epoch>=? ORDER BY ts_epoch DESC LIMIT ?""",
            (cutoff, limit)).fetchall()
        return [dict(r) for r in rows]

    # ── Maintenance ───────────────────────────────────────────────────────────

    def purge_old(self):
        cutoff = time.time() - self.retain_days * 86400
        total  = 0
        c      = self._conn()
        for table in ("alerts", "flows", "dns_events", "http_events"):
            cur    = c.execute(
                f"DELETE FROM {_safe_table(table)} WHERE ts_epoch<?", (cutoff,)
            )
            total += cur.rowcount
        c.commit()
        if total:
            log.info("Purged %d total rows older than %d days.", total, self.retain_days)

    def clear_all(self) -> int:
        c   = self._conn()
        cur = c.execute("DELETE FROM alerts")
        c.execute("DELETE FROM alert_meta")
        c.execute("DELETE FROM alert_notes")
        c.execute("DELETE FROM alert_activity")
        c.commit()
        log.info("Alerts cleared — %d rows deleted.", cur.rowcount)
        return cur.rowcount

    def clear_flows(self) -> int:
        c   = self._conn()
        cur = c.execute("DELETE FROM flows")
        c.commit()
        log.info("Flows cleared — %d rows deleted.", cur.rowcount)
        return cur.rowcount

    # ── Chart data ────────────────────────────────────────────────────────────

    def chart_top_talkers(self, limit: int = 10, days: int = 1) -> list[dict]:
        cutoff = time.time() - days * 86400
        rows = self._conn().execute(
            """SELECT src_ip, COUNT(*) as cnt
               FROM alerts WHERE ts_epoch >= ? AND src_ip != ''
               GROUP BY src_ip ORDER BY cnt DESC LIMIT ?""",
            (cutoff, limit)
        ).fetchall()
        return [{"ip": r["src_ip"], "count": r["cnt"]} for r in rows]

    def chart_alert_trend(self, hours: int = 24) -> list[dict]:
        now    = time.time()
        cutoff = now - hours * 3600
        rows   = self._conn().execute(
            """SELECT CAST((ts_epoch - ?) / 3600 AS INTEGER) AS bucket,
                      COUNT(*) AS cnt
               FROM   alerts
               WHERE  ts_epoch >= ?
               GROUP  BY bucket
               ORDER  BY bucket ASC""",
            (cutoff, cutoff)
        ).fetchall()
        buckets = {r["bucket"]: r["cnt"] for r in rows}
        result  = []
        for h in range(hours):
            slot_epoch = cutoff + h * 3600
            result.append({
                "ts":    time.strftime("%H:%M", time.localtime(slot_epoch)),
                "epoch": int(slot_epoch),
                "count": buckets.get(h, 0),
            })
        return result

    def chart_alert_trend_days(self, days: int = 7) -> list[dict]:
        now    = time.time()
        cutoff = now - days * 86400
        rows   = self._conn().execute(
            """SELECT CAST((ts_epoch - ?) / 86400 AS INTEGER) AS bucket,
                      COUNT(*) AS cnt
               FROM   alerts
               WHERE  ts_epoch >= ?
               GROUP  BY bucket
               ORDER  BY bucket ASC""",
            (cutoff, cutoff)
        ).fetchall()
        buckets = {r["bucket"]: r["cnt"] for r in rows}
        result  = []
        for d in range(days):
            slot_epoch = cutoff + d * 86400
            result.append({
                "ts":    time.strftime("%b %d", time.localtime(slot_epoch)),
                "epoch": int(slot_epoch),
                "count": buckets.get(d, 0),
            })
        return result

    def chart_by_category(self, days: int = 1) -> list[dict]:
        cutoff = time.time() - days * 86400
        rows = self._conn().execute(
            """SELECT COALESCE(NULLIF(category,''), 'Uncategorized') as cat,
                      COUNT(*) as cnt
               FROM alerts WHERE ts_epoch >= ?
               GROUP BY cat ORDER BY cnt DESC LIMIT 12""",
            (cutoff,)
        ).fetchall()
        return [{"category": r["cat"], "count": r["cnt"]} for r in rows]

    def chart_by_severity(self, days: int = 1) -> list[dict]:
        cutoff = time.time() - days * 86400
        rows = self._conn().execute(
            """SELECT severity, COUNT(*) as cnt
               FROM alerts WHERE ts_epoch >= ?
               GROUP BY severity ORDER BY cnt DESC""",
            (cutoff,)
        ).fetchall()
        return [{"severity": r["severity"], "count": r["cnt"]} for r in rows]

    def stats(self) -> dict:
        c      = self._conn()
        cutoff = time.time() - self.retain_days * 86400
        def _cnt(t):    return c.execute(f"SELECT COUNT(*) FROM {_safe_table(t)}").fetchone()[0]
        def _recent(t): return c.execute(
            f"SELECT COUNT(*) FROM {_safe_table(t)} WHERE ts_epoch>=?", (cutoff,)
        ).fetchone()[0]
        oldest = c.execute("SELECT MIN(ts) FROM alerts").fetchone()[0]
        return {
            "alerts": {"total": _cnt("alerts"),      "recent": _recent("alerts")},
            "flows":  {"total": _cnt("flows"),        "recent": _recent("flows")},
            "dns":    {"total": _cnt("dns_events"),   "recent": _recent("dns_events")},
            "http":   {"total": _cnt("http_events"),  "recent": _recent("http_events")},
            "oldest": oldest,
        }
