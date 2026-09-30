"""
Heimdall IDS Dashboard — AI Explanation Module
Supports OpenAI, Anthropic (Claude), and DeepSeek via stdlib urllib only.
No third-party packages required — fully airgapped-safe.
"""

import base64
import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
import urllib.request
import urllib.error
from collections import OrderedDict

# ── API key obfuscation (XOR + b64) ─────────────────────────────────────────
# This is mild obfuscation to prevent accidental exposure of API keys in
# backups or log snapshots.  It is NOT encryption — the key is fully
# recoverable from the source.  For stronger protection, run Heimdall behind
# a secrets manager or use OS-level filesystem encryption.
_OBF_SEED = b"heimdall-ids-ai-key-v1"

def _derive_mask(length: int) -> bytes:
    """Derive a repeating XOR mask from the fixed seed."""
    h = hashlib.sha256(_OBF_SEED).digest()
    mask = (h * ((length // 32) + 1))[:length]
    return mask

def _obfuscate(plaintext: str) -> str:
    """XOR + base64 encode an API key for DB storage."""
    if not plaintext:
        return ""
    raw  = plaintext.encode()
    mask = _derive_mask(len(raw))
    obf  = bytes(a ^ b for a, b in zip(raw, mask))
    return "obf1:" + base64.b64encode(obf).decode()

def _deobfuscate(stored: str) -> str:
    """Reverse _obfuscate."""
    if not stored:
        return ""
    if not stored.startswith("obf1:"):
        return stored   # legacy plaintext
    try:
        obf  = base64.b64decode(stored[5:])
        mask = _derive_mask(len(obf))
        raw  = bytes(a ^ b for a, b in zip(obf, mask))
        return raw.decode()
    except Exception:
        return ""

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
    """Manages ai_settings table inside config.db.

    fallback_provider / fallback_key come from --ai-provider / --ai-key
    (heimdall.conf). The UI takes precedence: the key is used only while no key
    is stored in the database, the provider only until the settings have been
    saved from the UI. The fallback key is never written to the database.
    """

    def __init__(self, conn_fn, fallback_provider: str = None, fallback_key: str = None):
        self._conn_fn           = conn_fn
        self._fallback_provider = fallback_provider
        self._fallback_key      = fallback_key or ""
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
        # Migration (1.4.4, additive): per-provider model choice as a JSON map
        # {"anthropic": "claude-...", ...}. Missing entries use DEFAULT_MODELS.
        # Older versions ignore the column.
        cols = {r[1] for r in c.execute("PRAGMA table_info(ai_settings)").fetchall()}
        if "models" not in cols:
            c.execute("ALTER TABLE ai_settings ADD COLUMN models TEXT NOT NULL DEFAULT '{}'")
        c.commit()

    def get_settings(self) -> dict:
        c = self._conn_fn()
        row = c.execute(
            "SELECT provider, api_key, enabled, updated_at, models FROM ai_settings WHERE id=1"
        ).fetchone()
        if not row:
            key      = self._fallback_key
            provider = self._fallback_provider or "openai"
            return {"provider": provider, "api_key": key,
                    "enabled": False, "api_key_set": bool(key), "_stored_key": "",
                    "model": DEFAULT_MODELS.get(provider, ""), "models": {},
                    "default_models": dict(DEFAULT_MODELS)}
        key      = _deobfuscate(row["api_key"]) or self._fallback_key
        provider = row["provider"]
        if not row["updated_at"] and self._fallback_provider:
            provider = self._fallback_provider      # never saved from the UI yet
        models = _load_models(row["models"])
        return {
            "provider":       provider,
            "api_key":        key,
            "enabled":        bool(row["enabled"]),
            "api_key_set":    bool(key),
            "_stored_key":    row["api_key"],   # obfuscated form, internal only
            "model":          models.get(provider) or DEFAULT_MODELS.get(provider, ""),
            "models":         models,           # explicit choices only
            "default_models": dict(DEFAULT_MODELS),
        }

    def update_settings(self, provider: str = None, api_key: str = None,
                        enabled: bool = None, model: str = None) -> dict:
        """model: a model ID for the provider being saved; "" reverts to that
        provider's default; None leaves it unchanged. Raises ValueError for an
        invalid ID (nothing is written)."""
        c    = self._conn_fn()
        cur  = self.get_settings()
        prov = provider if provider is not None else cur["provider"]
        enab = enabled  if enabled  is not None else cur["enabled"]
        if prov not in ("openai", "anthropic", "deepseek"):
            prov = "openai"
        models = dict(cur["models"])
        if model is not None:
            m = str(model).strip()
            if not m:
                models.pop(prov, None)
            elif not valid_model_id(m):
                raise ValueError("Invalid model ID — use the exact ID shown by the provider "
                                 "(letters, digits and . _ : / @ + -, no spaces)")
            else:
                models[prov] = m
        # Only a key typed into the UI is stored; an empty/absent key keeps the
        # stored one. (cur["api_key"] may be the config-file fallback, which
        # must never be copied into the database.)
        stored_key = _obfuscate(api_key) if api_key else cur["_stored_key"]
        c.execute("""
            UPDATE ai_settings
               SET provider=?, api_key=?, enabled=?, updated_at=?, models=?
             WHERE id=1
        """, (prov, stored_key, int(enab), int(time.time()), json.dumps(models)))
        c.commit()
        s = self.get_settings()
        return {k: s[k] for k in ("provider", "enabled", "api_key_set",
                                  "model", "models", "default_models")}


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
        ts = alert["ts"]
        try:
            ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(float(ts)))
        except (TypeError, ValueError):
            ts = str(ts)   # Suricata ISO-8601 string — the usual case; was silently dropped
        lines.append(f"Timestamp  : {ts}")
    return "\n".join(lines)


# ── Providers & models ──────────────────────────────────────────────────────
PROVIDERS = {"openai": "OpenAI", "anthropic": "Anthropic", "deepseek": "DeepSeek"}

# Used when no model has been chosen for a provider. Any model the provider
# offers can be chosen in the UI (AI Explain → Model) — including models
# released after this build, via list_models().
DEFAULT_MODELS = {
    "openai":    "gpt-4o-mini",
    # claude-3-5-haiku-20241022 was retired by Anthropic in Feb 2026; this is
    # Anthropic's documented successor.
    "anthropic": "claude-haiku-4-5-20251001",
    "deepseek":  "deepseek-chat",
}

_API_BASE = {
    "openai":    "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
    "deepseek":  "https://api.deepseek.com",
}
_ANTHROPIC_VERSION = "2023-06-01"

# Output cap. A 3–5 sentence summary is ~150 tokens, so ordinary models stop far
# below this; the headroom is for reasoning models (e.g. OpenAI o-series,
# deepseek-reasoner), whose hidden reasoning counts against the cap and could
# otherwise use it all and return no text.
MAX_OUTPUT_TOKENS = 1024

_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$")

# OpenAI's /models list includes non-chat models; hide the obvious ones from the
# picker (any ID can still be typed in).
_OPENAI_NON_CHAT = re.compile(
    r"embedding|whisper|tts|dall-e|davinci|babbage|moderation|transcribe|audio|"
    r"realtime|image|search|computer-use|codex|sora", re.I)


def valid_model_id(model) -> bool:
    return isinstance(model, str) and bool(_MODEL_ID_RE.match(model))


def _load_models(raw) -> dict:
    try:
        d = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    if not isinstance(d, dict):
        return {}
    return {p: m for p, m in d.items() if p in PROVIDERS and valid_model_id(m)}


def _headers(provider: str, api_key: str) -> dict:
    if provider == "anthropic":
        return {"x-api-key": api_key, "anthropic-version": _ANTHROPIC_VERSION}
    return {"Authorization": f"Bearer {api_key}"}


def _provider_error(provider: str, exc: urllib.error.HTTPError) -> RuntimeError:
    """Readable error. The provider's message is included except for auth
    failures, whose messages can echo part of the key."""
    label = PROVIDERS.get(provider, provider)
    if exc.code in (401, 403):
        return RuntimeError(f"{label} rejected the API key (HTTP {exc.code})")
    detail = ""
    try:
        err = json.loads(exc.read(8192) or b"{}").get("error")
        detail = err.get("message", "") if isinstance(err, dict) else (err or "")
    except Exception:
        pass
    msg = f"{label} returned HTTP {exc.code}"
    return RuntimeError(f"{msg}: {str(detail)[:200]}" if detail else msg)


def _request(provider: str, url: str, api_key: str, payload: dict = None,
             timeout: float = 30):
    data = json.dumps(payload).encode() if payload is not None else None
    req  = urllib.request.Request(
        url, data=data, method="POST" if payload is not None else "GET",
        headers={"Content-Type": "application/json", **_headers(provider, api_key)})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise _provider_error(provider, exc) from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach {PROVIDERS.get(provider, provider)}: {exc.reason}") from None


def _no_text() -> RuntimeError:
    return RuntimeError("The model returned no text — try a different model")


def _chat_completions_text(data) -> str:
    try:
        content = data["choices"][0]["message"].get("content")
    except (KeyError, IndexError, TypeError, AttributeError):
        raise RuntimeError("Unexpected response from the AI provider") from None
    text = content.strip() if isinstance(content, str) else ""
    if not text:
        raise _no_text()
    return text


def _call_openai(api_key: str, context: str, model: str = DEFAULT_MODELS["openai"]) -> str:
    data = _request("openai", f"{_API_BASE['openai']}/chat/completions", api_key, {
        "model": model,
        # max_completion_tokens replaces the deprecated max_tokens and is the
        # only form OpenAI reasoning models accept.
        "max_completion_tokens": MAX_OUTPUT_TOKENS,
        "messages": [
            {"role": "system", "content": EXECUTIVE_PROMPT},
            {"role": "user",   "content": f"Alert details:\n{context}"},
        ],
    })
    return _chat_completions_text(data)


def _call_anthropic(api_key: str, context: str, model: str = DEFAULT_MODELS["anthropic"]) -> str:
    data = _request("anthropic", f"{_API_BASE['anthropic']}/messages", api_key, {
        "model":      model,
        "max_tokens": MAX_OUTPUT_TOKENS,
        "system":     EXECUTIVE_PROMPT,
        "messages":   [{"role": "user", "content": f"Alert details:\n{context}"}],
    })
    blocks = data.get("content") if isinstance(data, dict) else None
    text = "".join(b.get("text", "") for b in (blocks or [])
                   if isinstance(b, dict) and b.get("type") == "text").strip()
    if not text:
        raise _no_text()
    return text


def _call_deepseek(api_key: str, context: str, model: str = DEFAULT_MODELS["deepseek"]) -> str:
    data = _request("deepseek", f"{_API_BASE['deepseek']}/chat/completions", api_key, {
        "model":      model,
        "max_tokens": MAX_OUTPUT_TOKENS,
        "messages": [
            {"role": "system", "content": EXECUTIVE_PROMPT},
            {"role": "user",   "content": f"Alert details:\n{context}"},
        ],
    })
    return _chat_completions_text(data)


def fetch_explanation(alert: dict, provider: str, api_key: str, model: str = None) -> str:
    """
    Call the configured AI provider and return an executive-summary string.
    model: any model ID the provider accepts; None → DEFAULT_MODELS[provider].
    Raises on error — caller should catch and handle.
    """
    context  = _build_alert_context(alert)
    provider = provider.lower()
    model    = model or DEFAULT_MODELS.get(provider)
    if provider == "openai":
        return _call_openai(api_key, context, model)
    elif provider == "anthropic":
        return _call_anthropic(api_key, context, model)
    elif provider == "deepseek":
        return _call_deepseek(api_key, context, model)
    else:
        raise ValueError(f"Unknown provider: {provider}")


def list_models(provider: str, api_key: str, timeout: float = 15) -> list[dict]:
    """
    Ask the provider which models this key can use: [{"id", "name"}, ...],
    newest first where the provider reports release dates. This is what makes
    newly released models selectable without a Heimdall update.
    """
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown provider: {provider}")
    url  = f"{_API_BASE[provider]}/models"
    if provider == "anthropic":
        url += "?limit=1000"          # API default page size is 20
    data  = _request(provider, url, api_key, timeout=timeout)
    items = data.get("data") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise RuntimeError(f"Unexpected response from {PROVIDERS[provider]}")
    out, seen = [], set()
    for m in items:
        mid = m.get("id") if isinstance(m, dict) else None
        if not valid_model_id(mid) or mid in seen:
            continue
        if provider == "openai" and _OPENAI_NON_CHAT.search(mid):
            continue
        name    = m.get("display_name")
        created = m.get("created")
        out.append({"id": mid, "name": name if isinstance(name, str) and name else mid,
                    "_created": created if isinstance(created, (int, float)) else 0})
        seen.add(mid)
        if len(out) >= 500:
            break
    if provider == "openai":          # Anthropic already lists newest first
        out.sort(key=lambda x: x["_created"], reverse=True)
    for x in out:
        x.pop("_created")
    return out


# ── Server-side explanation cache ────────────────────────────────────────────
class _Pending:
    __slots__ = ("event", "text", "error")

    def __init__(self):
        self.event = threading.Event()
        self.text  = None
        self.error = None


class ExplanationCache:
    """
    One AI summary per alert id, shared by every user and browser tab.

    Before 1.4.4 each open tab requested a summary for every live alert, so
    provider calls (and cost) scaled with the number of open tabs. Concurrent
    requests for the same id now wait for a single in-flight call and share its
    result (or its error). Successful summaries are kept in a bounded LRU in
    memory — no schema change; the cache is empty after a restart. Failures are
    not cached, so a later request retries.
    """

    def __init__(self, max_entries: int = 2000, wait_timeout: float = 45.0):
        self.max_entries  = max_entries
        self.wait_timeout = wait_timeout
        self._lock     = threading.Lock()
        self._done     = OrderedDict()   # alert_id -> text
        self._inflight = {}              # alert_id -> _Pending

    def get_or_fetch(self, key: str, fetch) -> str:
        with self._lock:
            if key in self._done:
                self._done.move_to_end(key)
                return self._done[key]
            pending = self._inflight.get(key)
            owner   = pending is None
            if owner:
                pending = self._inflight[key] = _Pending()

        if not owner:
            if not pending.event.wait(self.wait_timeout):
                raise TimeoutError("AI explanation is still being generated — try again shortly")
            if pending.error is not None:
                raise pending.error
            return pending.text

        try:
            pending.text = fetch()
            with self._lock:
                self._done[key] = pending.text
                self._done.move_to_end(key)
                while len(self._done) > self.max_entries:
                    self._done.popitem(last=False)
            return pending.text
        except Exception as exc:
            pending.error = exc
            raise
        finally:
            with self._lock:
                self._inflight.pop(key, None)
            pending.event.set()

    def clear(self):
        with self._lock:
            self._done.clear()

    def __len__(self):
        with self._lock:
            return len(self._done)


CACHE = ExplanationCache()
