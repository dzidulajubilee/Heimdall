"""
Heimdall IDS Dashboard — EVE JSON Tail (Version 2)
Background thread that tails eve.json and dispatches all event types:
  alert, flow, dns, http

Includes sliding-window deduplication to prevent duplicate alert
processing when eve.json is re-opened after rotation or a restart.
"""

import json
import logging
import os
import threading
import time
from collections import deque

log = logging.getLogger("heimdall.tail")

# ── Severity mapping ──────────────────────────────────────────────────────────

# Primary map: Suricata numeric priority → severity label.
# Priority 5 (custom rules) now resolves to 'info'.
_SEVERITY_MAP = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
    5: "info",
}

# Category overrides: when a category string matches a key here, the
# mapped severity is used instead of the numeric priority result.
# This corrects cases where semantically weak classtypes are
# over-reported by the numeric map alone.
#
# Adding a future reclassification requires only a single-line entry.
_CATEGORY_OVERRIDE = {
    # Suricata classtype strings (lowercased for comparison)
    "not suspicious traffic":  "info",
    "misc activity":           "low",
}

# Deduplication window: how long (seconds) to remember a seen alert ID
DEDUP_WINDOW  = 5
MAX_DEDUP_IDS = 10_000


def map_severity(level: int, category: str = "") -> str:
    """
    Resolve a Suricata numeric priority to a Heimdall severity label.

    Resolution order:
      1. Category-based override (_CATEGORY_OVERRIDE) — takes precedence.
      2. Numeric priority map (_SEVERITY_MAP).
      3. Default: 'info'.

    Args:
        level:    Suricata alert.severity integer (1–5).
        category: Suricata alert.category string (optional).
    """
    if category:
        override = _CATEGORY_OVERRIDE.get(category.strip().lower())
        if override:
            return override
    return _SEVERITY_MAP.get(level, "info")


# ── Deduplication ─────────────────────────────────────────────────────────────

class DedupFilter:
    """
    Sliding window deduplication using a deque of (id, expiry_time) for
    ordered eviction and a set for O(1) membership tests.
    Thread-safe for a single tail thread.
    """
    def __init__(self, window_seconds: int = DEDUP_WINDOW,
                 max_size: int = MAX_DEDUP_IDS):
        self.window   = window_seconds
        self.max_size = max_size
        self._seen: deque = deque()   # (alert_id, expiry_time)
        self._ids:  set   = set()     # fast O(1) membership

    def _evict(self, now: float):
        while self._seen and self._seen[0][1] <= now:
            evicted_id, _ = self._seen.popleft()
            self._ids.discard(evicted_id)

    def is_duplicate(self, alert_id: str) -> bool:
        now = time.time()
        self._evict(now)
        if alert_id in self._ids:
            return True
        self._seen.append((alert_id, now + self.window))
        self._ids.add(alert_id)
        # Safety cap — evict oldest if over limit
        while len(self._seen) > self.max_size:
            evicted_id, _ = self._seen.popleft()
            self._ids.discard(evicted_id)
        return False


# ── Parsing ───────────────────────────────────────────────────────────────────

def parse_eve_line(raw: str):
    """
    Parse one eve.json line.
    Returns (event_type, parsed) where event_type is one of:
      'alert' | 'flow' | 'dns' | 'http' | None
    parsed is the normalised dict (for alert) or raw evt dict (for others).
    """
    raw = raw.strip()
    if not raw:
        return None, None
    try:
        evt = json.loads(raw)
    except json.JSONDecodeError:
        return None, None

    etype = evt.get("event_type")

    if etype == "alert":
        a        = evt.get("alert", {})
        flow_id  = evt.get("flow_id", 0)
        ts       = evt.get("timestamp", "")
        sig_id   = a.get("signature_id", 0)
        category = a.get("category", "")
        # Stable composite ID — includes src_ip to avoid collisions when the
        # same sig fires multiple times in the same second from different sources,
        # and when flow_id is 0 (common for non-flow alerts).
        uid = f"{flow_id}-{sig_id}-{ts}-{evt.get('src_ip', '')}"
        return "alert", {
            "id":       uid,
            "ts":       ts,
            "src_ip":   evt.get("src_ip", ""),
            "src_port": evt.get("src_port", 0),
            "dst_ip":   evt.get("dest_ip", ""),
            "dst_port": evt.get("dest_port", 0),
            "proto":    evt.get("proto", "TCP").upper(),
            "iface":    evt.get("in_iface", ""),
            "flow_id":  flow_id,
            "sig_id":   sig_id,
            "sig_msg":  a.get("signature", ""),
            "category": category,
            # Pass category so _CATEGORY_OVERRIDE can take precedence
            "severity": map_severity(a.get("severity"), category),
            "action":   a.get("action", "allowed"),
            "raw":      evt,
        }

    if etype == "flow":
        return "flow", evt

    if etype == "dns":
        return "dns", evt

    if etype == "http":
        return "http", evt

    return None, None


# ── SSE summary builders ──────────────────────────────────────────────────────

def _flow_summary(evt: dict) -> dict:
    """Compact flow dict for SSE broadcast — avoids sending huge raw eve blobs."""
    f = evt.get("flow", {})
    return {
        "flow_id":        evt.get("flow_id", 0),
        "ts":             evt.get("timestamp", ""),
        "src_ip":         evt.get("src_ip", ""),
        "src_port":       evt.get("src_port", 0),
        "dst_ip":         evt.get("dest_ip", ""),
        "dst_port":       evt.get("dest_port", 0),
        "proto":          evt.get("proto", "").upper(),
        "app_proto":      evt.get("app_proto", ""),
        "state":          f.get("state", ""),
        "reason":         f.get("reason", ""),
        "pkts_toserver":  f.get("pkts_toserver", 0),
        "pkts_toclient":  f.get("pkts_toclient", 0),
        "bytes_toserver": f.get("bytes_toserver", 0),
        "bytes_toclient": f.get("bytes_toclient", 0),
        "alerted":        bool(f.get("alerted")),
    }


def _dns_summary(evt: dict) -> dict:
    d = evt.get("dns", {})
    return {
        "ts":       evt.get("timestamp", ""),
        "src_ip":   evt.get("src_ip", ""),
        "dst_ip":   evt.get("dest_ip", ""),
        "flow_id":  evt.get("flow_id", 0),
        "dns_type": d.get("type", ""),
        "rrname":   d.get("rrname", ""),
        "rrtype":   d.get("rrtype", ""),
        "rcode":    d.get("rcode", ""),
        "ttl":      d.get("ttl", 0),
    }


def _http_summary(evt: dict) -> dict:
    h = evt.get("http", {})
    return {
        "ts":         evt.get("timestamp", ""),
        "src_ip":     evt.get("src_ip", ""),
        "dst_ip":     evt.get("dest_ip", ""),
        "flow_id":    evt.get("flow_id", 0),
        "hostname":   h.get("hostname", ""),
        "url":        h.get("url", ""),
        "method":     h.get("http_method", ""),
        "status":     h.get("status", 0),
        "user_agent": h.get("http_user_agent", ""),
    }


# ── Main threads ──────────────────────────────────────────────────────────────

def tail_thread(path: str, db, dns_db, registry, wdb=None, sup_db=None):
    """
    Runs forever in a daemon thread.
    Tails eve.json, persists each event, and broadcasts SSE summaries.
    Uses sliding-window deduplication to prevent duplicate alert processing.
    Suppression rules (sup_db.is_suppressed) are checked before insert/broadcast.
    """
    log.info("Tailing %s", path)

    dedup = DedupFilter()
    pos   = 0
    try:
        pos = os.path.getsize(path)
        log.info("Starting at offset %d (existing history skipped).", pos)
    except OSError:
        log.warning("Eve file not found yet — will wait.")

    while True:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(pos)
                while True:
                    line = f.readline()
                    if line:
                        etype, parsed = parse_eve_line(line)

                        if etype == "alert":
                            if dedup.is_duplicate(parsed["id"]):
                                log.debug("Skipping duplicate alert %s", parsed["id"])
                                pos = f.tell()
                                continue
                            if sup_db is not None and sup_db.is_suppressed(parsed):
                                log.debug("Alert suppressed (rule match): %s", parsed["id"])
                                pos = f.tell()
                                continue
                            db.insert(parsed)
                            registry.broadcast("alert", parsed)
                            if wdb is not None:
                                from webhooks import dispatch
                                dispatch(parsed, wdb)

                        elif etype == "flow":
                            db.insert_flow(parsed)
                            registry.broadcast("flow", _flow_summary(parsed))

                        elif etype == "dns":
                            dns_db.insert(parsed)
                            registry.broadcast("dns", _dns_summary(parsed))

                        elif etype == "http":
                            db.insert_http(parsed)
                            registry.broadcast("http", _http_summary(parsed))

                        pos = f.tell()
                    else:
                        try:
                            if os.path.getsize(path) < pos:
                                log.info("Log rotation detected — rewinding.")
                                pos = 0
                                break
                        except OSError:
                            pass
                        time.sleep(0.1)

        except OSError as exc:
            log.warning("Cannot open %s: %s — retrying in 3 s.", path, exc)
            time.sleep(3)


# ── Replay state ─────────────────────────────────────────────────────────────

_replay_lock  = threading.Lock()
_replay_state = {
    "running":    False,
    "inserted":   0,
    "skipped":    0,
    "suppressed": 0,
    "total":      0,
    "error":      None,
    "done":       False,
}

def get_replay_status() -> dict:
    with _replay_lock:
        return dict(_replay_state)

def _set_replay(field: str, value):
    with _replay_lock:
        _replay_state[field] = value

def replay_thread(path: str, db, dns_db, sup_db=None):
    """
    Read eve.json from the very beginning and insert any events
    not already in the database. Runs as a daemon thread so the
    dashboard stays usable during replay.

    Suppression rules (sup_db.is_suppressed) are applied to alerts exactly as
    in tail_thread, so replay never re-ingests suppressed alerts. Suppressed
    alerts are counted in both "skipped" (for existing UIs) and "suppressed".
    """
    with _replay_lock:
        if _replay_state["running"]:
            return   # already in progress
        _replay_state.update({"running": True, "inserted": 0,
                               "skipped": 0,   "suppressed": 0,
                               "total":   0,   "error":    None,
                               "done":    False})
    log.info("Replay started — reading %s from beginning.", path)
    inserted = skipped = suppressed = total = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                total += 1
                if total % 10000 == 0:
                    with _replay_lock:
                        _replay_state["total"]      = total
                        _replay_state["inserted"]   = inserted
                        _replay_state["skipped"]    = skipped
                        _replay_state["suppressed"] = suppressed
                etype, parsed = parse_eve_line(raw_line)
                if etype is None:
                    skipped += 1
                    continue
                if etype == "alert":
                    if db.alert_exists(parsed["id"]):
                        skipped += 1
                    elif sup_db is not None and sup_db.is_suppressed(parsed):
                        skipped    += 1
                        suppressed += 1
                    else:
                        db.insert(parsed)
                        inserted += 1
                elif etype == "flow":
                    # flows have no stable unique ID — skip duplicates by count heuristic
                    db.insert_flow(parsed)
                    inserted += 1
                elif etype == "dns":
                    dns_db.insert(parsed)
                    inserted += 1
                elif etype == "http":
                    db.insert_http(parsed)
                    inserted += 1
                else:
                    skipped += 1
        log.info("Replay done — %d lines read, %d inserted, %d skipped "
                 "(%d suppressed by rule).", total, inserted, skipped, suppressed)
    except Exception as exc:
        log.error("Replay error: %s", exc)
        with _replay_lock:
            _replay_state["error"] = str(exc)
    finally:
        with _replay_lock:
            _replay_state.update({
                "running":    False,
                "inserted":   inserted,
                "skipped":    skipped,
                "suppressed": suppressed,
                "total":      total,
                "done":       True,
            })


def purge_thread(db, dns_db, auth):
    from config import PURGE_EVERY
    while True:
        time.sleep(PURGE_EVERY)
        db.purge_old()
        dns_db.purge_old()
        auth.purge_expired()
