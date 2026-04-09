"""
Heimdall IDS Dashboard — EVE JSON Tail
Background thread that tails /var/log/suricata/eve.json,
parses alert events, writes them to the database, and
broadcasts them to connected SSE clients.
"""

import json
import logging
import os
import time

log = logging.getLogger("heimdall.tail")

# Severity mapping: Suricata uses 1 (highest) → 4 (lowest)
_SEVERITY_MAP = {1: "critical", 2: "high", 3: "medium", 4: "low"}


def map_severity(level: int | None) -> str:
    return _SEVERITY_MAP.get(level, "info")


def parse_eve_line(raw: str) -> dict | None:
    """
    Parse one line from eve.json.
    Returns a normalised alert dict if the line is an alert event,
    otherwise returns None (flows, DNS, stats, etc. are silently skipped).
    """
    raw = raw.strip()
    if not raw:
        return None
    try:
        evt = json.loads(raw)
    except json.JSONDecodeError:
        return None

    if evt.get("event_type") != "alert":
        return None

    alert = evt.get("alert", {})
    return {
        # Unique ID: flow_id + millisecond timestamp avoids collisions
        "id":       f"{evt.get('flow_id', 0)}-{int(time.time() * 1000)}",
        "ts":       evt.get("timestamp", ""),
        "src_ip":   evt.get("src_ip", ""),
        "src_port": evt.get("src_port", 0),
        "dst_ip":   evt.get("dest_ip", ""),
        "dst_port": evt.get("dest_port", 0),
        "proto":    evt.get("proto", "TCP").upper(),
        "iface":    evt.get("in_iface", ""),
        "flow_id":  evt.get("flow_id", 0),
        "sig_id":   alert.get("signature_id", 0),
        "sig_msg":  alert.get("signature", ""),
        "category": alert.get("category", ""),
        "severity": map_severity(alert.get("severity")),
        "action":   alert.get("action", "allowed"),
        "raw":      evt,
    }


def tail_thread(path: str, db, registry):
    """
    Runs forever in a daemon thread.

    Behaviour:
    - On startup: seeks to the end of the file so existing history is
      not re-broadcast (it is served via GET /alerts instead).
    - Poll interval: 100 ms when idle — keeps CPU usage negligible.
    - Log rotation: if the file shrinks, the position is rewound to 0
      so the new file is tailed from the beginning.
    - Missing file: retries every 3 seconds with a warning.

    Args:
        path:     Absolute path to eve.json.
        db:       AlertDB instance — receives insert() calls.
        registry: Registry instance — receives broadcast() calls.
    """
    log.info("Tailing %s", path)

    # Seek to end on first open — skip history that's already in the DB
    pos = 0
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
                        alert = parse_eve_line(line)
                        if alert:
                            db.insert(alert)
                            registry.broadcast(alert)
                        pos = f.tell()
                    else:
                        # No new data — check for log rotation
                        try:
                            if os.path.getsize(path) < pos:
                                log.info("Log rotation detected — rewinding.")
                                pos = 0
                                break   # reopen the (new) file
                        except OSError:
                            pass
                        time.sleep(0.1)
        except OSError as exc:
            log.warning("Cannot open %s: %s — retrying in 3 s.", path, exc)
            time.sleep(3)


def purge_thread(db, auth):
    """
    Runs forever in a daemon thread.
    Purges old alerts and expired sessions once per hour.
    """
    from config import PURGE_EVERY
    while True:
        time.sleep(PURGE_EVERY)
        db.purge_old()
        auth.purge_expired()
