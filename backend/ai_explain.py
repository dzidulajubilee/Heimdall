"""
Heimdall IDS Dashboard — AI Explanation Module
Supports OpenAI, Anthropic (Claude), and DeepSeek via stdlib urllib only.
No third-party packages required — fully airgapped-safe.
"""

import json
import logging
import sqlite3
import threading
import time
import urllib.request
import urllib.error

log = logging.getLogger("heimdall.ai")

EXECUTIVE_PROMPT = """\
You are a senior SOC analyst reviewing a Suricata IDS alert.
Write a concise executive summary (3-5 sentences maximum) that is:
1. What triggered this alert and why it fired
2. The likely threat type or root cause
3. The recommended immediate action for the analyst

Be direct, specific, and actionable. No bullet points — plain prose only.
Do NOT start with "This alert" or repeat the signature name verbatim.
"""


class AIExplainDB:
    """Manages ai_settings table inside config.db."""

    def __init__(self, conn_fn):
        self._conn_fn = conn_fn
        self._init_schema()

    def _init_schema(self):
        c = self._conn_fn()
        c.execute("""
            CREATE TABLE IF NOT EXISTS ai_settings (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                provider    TEXT    NOT NULL DEFAULT 'openai',
                api_key     TEXT    NOT NULL DEFAULT '',
                enabled     INTEGER NOT NULL DEFAULT 0,
                updated_at  INTEGER NOT NULL DEFAULT 0
            )
        """)
        # Ensure exactly one row exists
        c.execute("""
            INSERT OR IGNORE INTO ai_settings (id, provider, api_key, enabled, updated_at)
            VALUES (1, 'openai', '', 0, 0)
        """)
        c.commit()

    def get_settings(self) -> dict:
        c = self._conn_fn()
        row = c.execute(
            "SELECT provider, api_key, enabled FROM ai_settings WHERE id=1"
        ).fetchone()
        if not row:
            return {"provider": "openai", "api_key": "", "enabled": False, "api_key_set": False}
        return {
            "provider":    row["provider"],
            "api_key":     row["api_key"],
            "enabled":     bool(row["enabled"]),
            "api_key_set": bool(row["api_key"]),
        }

    def update_settings(self, provider: str = None, api_key: str = None,
                        enabled: bool = None) -> dict:
        c    = self._conn_fn()
        cur  = self.get_settings()
        prov = provider if provider is not None else cur["provider"]
        key  = api_key  if api_key  is not None else cur["api_key"]
        enab = enabled  if enabled  is not None else cur["enabled"]
        if prov not in ("openai", "anthropic", "deepseek"):
            prov = "openai"
        c.execute("""
            UPDATE ai_settings
               SET provider=?, api_key=?, enabled=?, updated_at=?
             WHERE id=1
        """, (prov, key, int(enab), int(time.time())))
        c.commit()
        return {
            "provider":    prov,
            "enabled":     bool(enab),
            "api_key_set": bool(key),
        }


def _build_alert_context(alert: dict) -> str:
    """Format alert fields into a human-readable context block."""
    lines = []
    if alert.get("sig_msg"):   lines.append(f"Signature  : {alert['sig_msg']}")
    if alert.get("sig_id"):    lines.append(f"SID        : {alert['sig_id']}")
    if alert.get("severity"):  lines.append(f"Severity   : {alert['severity'].upper()}")
    if alert.get("category"):  lines.append(f"Category   : {alert['category']}")
    if alert.get("src_ip"):
        src = alert["src_ip"]
        if alert.get("src_port"): src += f":{alert['src_port']}"
        lines.append(f"Source     : {src}")
    if alert.get("dst_ip"):
        dst = alert["dst_ip"]
        if alert.get("dst_port"): dst += f":{alert['dst_port']}"
        lines.append(f"Destination: {dst}")
    if alert.get("proto"):     lines.append(f"Protocol   : {alert['proto'].upper()}")
    if alert.get("ts"):
        try:
            ts = time.strftime("%Y-%m-%d %H:%M:%S UTC",
                               time.gmtime(float(alert["ts"])))
            lines.append(f"Timestamp  : {ts}")
        except Exception:
            pass
    return "\n".join(lines)


def _call_openai(api_key: str, context: str, model: str = "gpt-4o-mini") -> str:
    payload = json.dumps({
        "model": model,
        "max_tokens": 300,
        "messages": [
            {"role": "system", "content": EXECUTIVE_PROMPT},
            {"role": "user",   "content": f"Alert details:\n{context}"},
        ],
    }).encode()
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"].strip()


def _call_anthropic(api_key: str, context: str) -> str:
    payload = json.dumps({
        "model":      "claude-3-5-haiku-20241022",
        "max_tokens": 300,
        "system":     EXECUTIVE_PROMPT,
        "messages": [
            {"role": "user", "content": f"Alert details:\n{context}"},
        ],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type":      "application/json",
            "x-api-key":         api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    return data["content"][0]["text"].strip()


def _call_deepseek(api_key: str, context: str) -> str:
    payload = json.dumps({
        "model":      "deepseek-chat",
        "max_tokens": 300,
        "messages": [
            {"role": "system", "content": EXECUTIVE_PROMPT},
            {"role": "user",   "content": f"Alert details:\n{context}"},
        ],
    }).encode()
    req = urllib.request.Request(
        "https://api.deepseek.com/chat/completions",
        data=payload,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"].strip()


def fetch_explanation(alert: dict, provider: str, api_key: str) -> str:
    """
    Call the configured AI provider and return an executive-summary string.
    Raises on error — caller should catch and handle.
    """
    context  = _build_alert_context(alert)
    provider = provider.lower()
    if provider == "openai":
        return _call_openai(api_key, context)
    elif provider == "anthropic":
        return _call_anthropic(api_key, context)
    elif provider == "deepseek":
        return _call_deepseek(api_key, context)
    else:
        raise ValueError(f"Unknown provider: {provider}")
