"""
Heimdall IDS Dashboard — Webhook Engine
Stores webhook configurations in SQLite and delivers alert notifications
via HTTP POST to Slack, Discord, or any generic JSON endpoint.

Delivery is async (background thread + queue) so it never blocks the
tail thread or SSE broadcasts.
"""

import json
import logging
import time
import urllib.request
import urllib.error
import ipaddress
import socket as _socket
from queue import Queue, Empty

log = logging.getLogger("heimdall.webhooks")

ALL_SEVERITIES   = ["critical", "high", "medium", "low", "info"]
MAX_RETRIES      = 3
RETRY_DELAY      = 5       # seconds between retries
QUEUE_MAX        = 1000    # max pending deliveries
DELIVERY_TIMEOUT = 10      # seconds per HTTP request


# ── Storage ───────────────────────────────────────────────────────────────────

class WebhookDB:
    """
    Stores webhook configurations in the same SQLite database as alerts.
    Each webhook has:
      id, name, type (slack|discord|generic), url, enabled,
      severities (JSON list), created_at, last_fired, fire_count, last_error
    """

    def __init__(self, conn_fn):
        self._conn = conn_fn
        self._setup()

    def _setup(self):
        c = self._conn()
        c.execute("""
            CREATE TABLE IF NOT EXISTS webhooks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL,
                type        TEXT    NOT NULL DEFAULT 'generic',
                url         TEXT    NOT NULL,
                enabled     INTEGER NOT NULL DEFAULT 1,
                severities  TEXT    NOT NULL DEFAULT '["critical","high","medium","low","info"]',
                allow_local INTEGER NOT NULL DEFAULT 0,
                created_at  REAL    NOT NULL,
                last_fired  REAL,
                fire_count  INTEGER NOT NULL DEFAULT 0,
                last_error  TEXT
            )
        """)
        # Migration: add allow_local for existing installs
        cols = [r[1] for r in c.execute("PRAGMA table_info(webhooks)").fetchall()]
        if "allow_local" not in cols:
            c.execute("ALTER TABLE webhooks ADD COLUMN allow_local INTEGER NOT NULL DEFAULT 0")
        c.commit()

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def get_all(self) -> list[dict]:
        rows = self._conn().execute("""
            SELECT id, name, type, url, enabled, severities, allow_local,
                   created_at, last_fired, fire_count, last_error
            FROM webhooks ORDER BY id
        """).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get(self, wid: int) -> dict | None:
        row = self._conn().execute(
            "SELECT id, name, type, url, enabled, severities, allow_local, "
            "created_at, last_fired, fire_count, last_error "
            "FROM webhooks WHERE id = ?", (wid,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def create(self, name: str, wtype: str, url: str,
               severities: list, enabled: bool = True,
               allow_local: bool = False) -> dict:
        now = time.time()
        c   = self._conn()
        cur = c.execute("""
            INSERT INTO webhooks (name, type, url, enabled, severities, allow_local, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (name, wtype, url, 1 if enabled else 0,
              json.dumps(severities), 1 if allow_local else 0, now))
        c.commit()
        return self.get(cur.lastrowid)

    def update(self, wid: int, **fields) -> dict | None:
        allowed = {"name", "type", "url", "enabled", "severities", "allow_local"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get(wid)
        if "severities" in updates and isinstance(updates["severities"], list):
            updates["severities"] = json.dumps(updates["severities"])
        if "enabled" in updates:
            updates["enabled"] = 1 if updates["enabled"] else 0
        if "allow_local" in updates:
            updates["allow_local"] = 1 if updates["allow_local"] else 0
        cols = ", ".join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [wid]
        c = self._conn()
        c.execute(f"UPDATE webhooks SET {cols} WHERE id = ?", vals)
        c.commit()
        return self.get(wid)

    def delete(self, wid: int):
        c = self._conn()
        c.execute("DELETE FROM webhooks WHERE id = ?", (wid,))
        c.commit()

    def _mark_fired(self, wid: int, error: str | None = None):
        c = self._conn()
        if error:
            c.execute("""
                UPDATE webhooks
                SET last_fired = ?, fire_count = fire_count + 1, last_error = ?
                WHERE id = ?
            """, (time.time(), error[:500], wid))
        else:
            c.execute("""
                UPDATE webhooks
                SET last_fired = ?, fire_count = fire_count + 1, last_error = NULL
                WHERE id = ?
            """, (time.time(), wid))
        c.commit()

    @staticmethod
    def _row_to_dict(row) -> dict:
        d = dict(row)
        try:
            d["severities"] = json.loads(d.get("severities", "[]"))
        except Exception:
            d["severities"] = ALL_SEVERITIES
        d["enabled"]     = bool(d.get("enabled", 1))
        d["allow_local"] = bool(d.get("allow_local", 0))
        return d


# ── Payload formatters ────────────────────────────────────────────────────────

SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵",
}

SEV_COLOR = {
    "critical": 15158332,   # red
    "high":     16744272,   # orange
    "medium":   16766720,   # yellow
    "low":      5025616,    # green
    "info":     5267393,    # blue
}


def format_slack(alert: dict) -> dict:
    """Slack Block Kit payload."""
    sev   = alert.get("severity", "info")
    emoji = SEV_EMOJI.get(sev, "⚪")
    ts    = alert.get("ts", "")[:19].replace("T", " ")
    return {
        "text": f"{emoji} *Heimdall Alert* — {alert.get('sig_msg', '')}",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} Heimdall IDS Alert"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn",
                         "text": f"*{alert.get('sig_msg', 'Unknown signature')}*"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity*\n{sev.upper()}"},
                    {"type": "mrkdwn", "text": f"*Category*\n{alert.get('category', '—')}"},
                    {"type": "mrkdwn",
                     "text": f"*Source*\n`{alert.get('src_ip','?')}:{alert.get('src_port','?')}`"},
                    {"type": "mrkdwn",
                     "text": f"*Destination*\n`{alert.get('dst_ip','?')}:{alert.get('dst_port','?')}`"},
                    {"type": "mrkdwn", "text": f"*Protocol*\n{alert.get('proto', '?')}"},
                    {"type": "mrkdwn", "text": f"*SID*\n{alert.get('sig_id', '?')}"},
                ],
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn",
                     "text": f"🕐 {ts}  |  Interface: {alert.get('iface', 'eth0')}"}
                ],
            },
        ],
    }


def format_discord(alert: dict) -> dict:
    """Discord webhook payload using embeds."""
    sev   = alert.get("severity", "info")
    emoji = SEV_EMOJI.get(sev, "⚪")
    ts    = alert.get("ts", "")[:19].replace("T", " ")
    return {
        "username":   "Heimdall IDS",
        "avatar_url": "",
        "embeds": [
            {
                "title": f"{emoji} {alert.get('sig_msg', 'Unknown signature')}",
                "color": SEV_COLOR.get(sev, 5267393),
                "fields": [
                    {"name": "Severity",    "value": sev.upper(),
                     "inline": True},
                    {"name": "Category",    "value": alert.get("category", "—"),
                     "inline": True},
                    {"name": "Protocol",    "value": alert.get("proto", "?"),
                     "inline": True},
                    {"name": "Source",
                     "value": f"`{alert.get('src_ip','?')}:{alert.get('src_port','?')}`",
                     "inline": True},
                    {"name": "Destination",
                     "value": f"`{alert.get('dst_ip','?')}:{alert.get('dst_port','?')}`",
                     "inline": True},
                    {"name": "SID",         "value": str(alert.get("sig_id", "?")),
                     "inline": True},
                ],
                "footer": {"text": f"Heimdall IDS  •  {ts}"},
            }
        ],
    }


def format_generic(alert: dict) -> dict:
    """Plain JSON payload for Teams, Mattermost, n8n, etc."""
    return {
        "source":    "Heimdall IDS",
        "timestamp": alert.get("ts", ""),
        "severity":  alert.get("severity", "info"),
        "signature": alert.get("sig_msg", ""),
        "category":  alert.get("category", ""),
        "sig_id":    alert.get("sig_id", 0),
        "src_ip":    alert.get("src_ip", ""),
        "src_port":  alert.get("src_port", 0),
        "dst_ip":    alert.get("dst_ip", ""),
        "dst_port":  alert.get("dst_port", 0),
        "proto":     alert.get("proto", ""),
        "iface":     alert.get("iface", ""),
        "action":    alert.get("action", "allowed"),
    }


def build_payload(wtype: str, alert: dict) -> dict:
    if wtype == "slack":
        return format_slack(alert)
    if wtype == "discord":
        return format_discord(alert)
    return format_generic(alert)


# ── HTTP delivery ─────────────────────────────────────────────────────────────

_SSRF_BLOCKED_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def _ssrf_safe(url: str, allow_local: bool = False) -> bool:
    """
    Return True if url is safe to deliver to.
    - Always requires http:// or https:// scheme.
    - When allow_local=False (default) blocks RFC-1918/loopback destinations
      to prevent SSRF against infrastructure.
    - When allow_local=True (admin-opted-in per webhook) private/loopback
      destinations are allowed — intended for tools like n8n, Home Assistant,
      Mattermost, etc. running on the same LAN or host.
    """
    if not url.lower().startswith(("http://", "https://")):
        return False
    if allow_local:
        return True   # admin explicitly permitted private destination
    # External-only: block private/loopback ranges
    try:
        from urllib.parse import urlparse as _up
        host = _up(url).hostname or ""
        for addr in _socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(addr[4][0])
            if any(ip in net for net in _SSRF_BLOCKED_NETS):
                return False
    except Exception:
        return False
    return True


def deliver(url: str, payload: dict, allow_local: bool = False) -> str | None:
    """
    POST payload as JSON to url.
    allow_local: if True, permits private/loopback destinations (e.g. n8n).
    Returns None on success, or an error string on failure.
    """
    if not _ssrf_safe(url, allow_local=allow_local):
        return "Blocked: URL resolves to a private/loopback address or is not HTTP(S). "\
               "Enable \"Allow local/private URLs\" on this webhook to permit it."
    body = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent":   "Heimdall-IDS/0.3",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=DELIVERY_TIMEOUT) as resp:
            if 200 <= resp.status < 300:
                return None
            return f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return f"URLError: {e.reason}"
    except Exception as e:
        return f"Error: {e}"


# ── Delivery queue + worker ────────────────────────────────────────────────────

_queue: Queue = Queue(maxsize=QUEUE_MAX)


def enqueue(webhook: dict, alert: dict):
    """Non-blocking enqueue. Drops silently if the queue is full."""
    try:
        _queue.put_nowait((webhook, alert))
    except Exception:
        pass


def delivery_worker(wdb: WebhookDB):
    """
    Runs forever in a daemon thread.
    Drains the delivery queue, retrying failed deliveries.
    """
    while True:
        try:
            webhook, alert = _queue.get(timeout=5)
        except Empty:
            continue

        wid     = webhook["id"]
        wtype   = webhook.get("type", "generic")
        url     = webhook.get("url", "")
        payload = build_payload(wtype, alert)

        allow_local = webhook.get("allow_local", False)
        error = None
        for attempt in range(1, MAX_RETRIES + 1):
            error = deliver(url, payload, allow_local=allow_local)
            if error is None:
                log.info("Webhook %d (%s) fired OK for alert %s",
                         wid, webhook.get("name", "?"), alert.get("sig_id", "?"))
                break
            log.warning("Webhook %d attempt %d/%d failed: %s",
                        wid, attempt, MAX_RETRIES, error)
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)

        wdb._mark_fired(wid, error)


# ── Main dispatcher ────────────────────────────────────────────────────────────

def dispatch(alert: dict, wdb: WebhookDB):
    """
    Called by tail_thread for each new alert.
    Checks every enabled webhook and enqueues delivery if the alert's
    severity matches the webhook's configured filter.
    """
    sev = alert.get("severity", "info")
    for wh in wdb.get_all():
        if not wh.get("enabled"):
            continue
        if sev not in wh.get("severities", ALL_SEVERITIES):
            continue
        enqueue(wh, alert)
