<<<<<<< HEAD
# Heimdall IDS Dashboard
=======
# Heimdall
>>>>>>> 33d86bafdf87a86c7b59e0edfce9ee79f1d379f5

**A self-hosted, fully airgapped network intrusion detection dashboard for Suricata.**  
Built by G-Sentry · Licensed under [GNU AGPL v3.0](LICENSE)

---

## What is Heimdall?

Heimdall IDS is a lightweight, single-binary web dashboard that sits on top of [Suricata](https://suricata.io/) and turns raw `eve.json` output into a real-time analyst workstation. It requires no internet connection, no cloud services, and no runtime dependencies beyond Python 3.10.

- **Live alert feed** — new events pushed instantly via Server-Sent Events
- **Full triage workflow** — status tracking, analyst notes, activity log per alert
- **Threat intelligence** — per-signature knowledge base with CVE and MITRE ATT&CK linking
- **AI executive summaries** — auto-explain every new alert via OpenAI, Anthropic, or DeepSeek
- **Webhooks** — push alerts to Slack, Discord, n8n, or any HTTP endpoint
- **Four UI skins** — Original, Chronicles, Mosaic, Seal
- **Role-based access** — Admin, Analyst, Viewer roles
- **Installs in one command** — ships as a `.deb` package, runs as a systemd service

---

## Table of Contents

1. [Architecture](#architecture)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [First Login](#first-login)
5. [Configuration](#configuration)
6. [Features](#features)
7. [Skins](#skins)
8. [AI Explanation](#ai-explanation)
9. [Webhooks](#webhooks)
10. [Security](#security)
11. [Building from Source](#building-from-source)
12. [Changelog](#changelog)
13. [License](#license)

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                     Browser                         │
│  React (no build step) · 4 skins · SSE consumer     │
└────────────────────┬────────────────────────────────┘
                     │ HTTP / SSE
┌────────────────────▼────────────────────────────────┐
│              Heimdall HTTP Server                   │
│  ThreadedHTTPServer · BaseHTTPRequestHandler        │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │ tail     │  │ purge    │  │ delivery_worker   │  │
│  │ thread   │  │ thread   │  │ (webhooks)        │  │
│  └────┬─────┘  └────┬─────┘  └──────────────────┘   │
│       │              │                              │
│  ┌────▼──────────────▼───────────────────────────┐  │
│  │              SQLite (3 databases)             │  │
│  │  events.db · dns.db · config.db               │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
         ▲
         │ reads
┌────────┴────────┐
│  eve.json       │
│  (Suricata)     │
└─────────────────┘
```


## Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Debian 11+, Ubuntu 22.04+, or any systemd-based Debian derivative |
| Python | 3.10 or later (pre-installed on all supported OS versions) |
| Suricata | Any version writing `eve.json` |
| Browser | Chrome 90+, Firefox 88+, Safari 14+, Edge 90+ |
| Disk | ~320 KB for the package; database grows with traffic volume |
| Network | No internet access required at runtime |

> **Suricata group:** Heimdall reads `eve.json` directly. The `postinst` script automatically adds the `heimdall` system user to the `suricata` group. If Suricata is installed after Heimdall, run:
> ```bash
> sudo usermod -aG suricata heimdall && sudo systemctl restart heimdall
> ```

---

## Installation

```bash
sudo apt install ./heimdall-ids_0.5_all.deb
```

That's it. The installer will:

1. Create the `heimdall` system user (no login shell)
2. Add `heimdall` to the `suricata` group
3. Create `/var/lib/heimdall/`, `/var/log/heimdall/`, `/etc/heimdall/`
4. Generate a random admin password
5. Enable and start `heimdall.service` via systemd
6. Print your credentials to the terminal

```
╔══════════════════════════════════════════════╗
║      Heimdall IDS — Admin Credentials        ║
╠══════════════════════════════════════════════╣
║  Username : admin                            ║
║  Password : xK9mRp2vQnTfL6j                  ║
║  URL      : http://localhost:8765/           ║
╚══════════════════════════════════════════════╝

  Credentials saved at: /etc/heimdall/.credentials
  Change password:      sudo heimdall --password <new>
```

---


## First Login

Open your browser and navigate to:

```
http://localhost:8765/
```

Log in with `admin` and the generated password shown during install. The password is also saved at `/etc/heimdall/.credentials` (readable by root and the heimdall group).

**Change the admin password:**
```bash
sudo heimdall --password <yournewpassword>
```

---

## Configuration

Edit `/etc/heimdall/heimdall.conf` then restart the service:

```bash
sudo nano /etc/heimdall/heimdall.conf
sudo systemctl restart heimdall
```

| Option | Default | Description |
|--------|---------|-------------|
| `--eve <path>` | `/var/log/suricata/eve.json` | Path to Suricata `eve.json` |
| `--port <n>` | `8765` | Listening port |
| `--retain-days <n>` | `90` | Alert and flow retention in days |
| `--skin <name>` | `original` | Default skin: `original`, `chronicles`, `mosaic`, `seal` |
| `--ai-provider <name>` | `openai` | AI provider: `openai`, `anthropic`, `deepseek` |
| `--ai-key <key>` | _(none)_ | API key for AI explanation (UI setting takes precedence) |
| `--password <pw>` | — | Set or reset the admin password |

**Service management:**

```bash
sudo systemctl status heimdall       # check status
sudo systemctl restart heimdall      # restart after config changes
sudo journalctl -u heimdall -f       # follow live logs
sudo apt remove heimdall-ids         # remove (data preserved)
sudo apt purge heimdall-ids          # remove including all data
```

---

## Features

### Alert Feed
Real-time alert list with severity badges, source/destination IPs, protocol, and timestamp. New alerts appear instantly via Server-Sent Events — no polling, no page refresh.

### Alert Triage
Click any alert to open the detail panel:
- **Status** — mark as `new`, `open`, `closed`, or `false-positive`
- **Analyst notes** — add timestamped notes visible to your whole team
- **Activity log** — full history of every status change and note

### Threat Intelligence
Build a knowledge base per Suricata signature. Each entry supports:
- Description and recommended response
- CVE references
- MITRE ATT&CK technique mapping
- Analyst notes

The **Gaps** view lists the top signatures firing without any intel entry, so you know where to focus documentation effort.

### Suppression Rules
Create rules to drop noisy signatures from the live feed. Suppression is applied in the ingestion layer — suppressed events are never written to the database.

### Analytics
- Alert volume timeseries chart
- Top-10 firing signatures
- Top-10 source IP addresses

### Multi-user Access
Create analyst and viewer accounts from the Users panel. Roles are enforced at the API level on every request.

| Role | Can Do |
|------|--------|
| **Admin** | Everything — users, settings, webhooks, AI config, suppression |
| **Analyst** | Alert triage, threat intel create/edit, suppression create/edit |
| **Viewer** | Read-only access to all views |

---

## Skins

Switch between skins at any time from the Settings panel without restarting.

| Skin | Description |
|------|-------------|
| **Original** | Classic dark list view with slide-out detail panel. Highest information density. |
| **Chronicles** | Heatmap strip across the top, vertical timeline on the left, detail panel on the right. |
| **Mosaic** | Card-grid layout. Each alert is a colour-coded card. Best on large monitors. |
| **Seal** | Compact monochrome design. Minimal chrome. Best for focused analysis sessions. |

All skins share the same full feature set, the same bundled fonts (Inter + JetBrains Mono), and the same React version. No skin makes any external network requests.

---

## AI Explanation

Heimdall can automatically generate a short, actionable executive summary for every new alert using an AI provider of your choice.

### Setup

1. Go to the **AI Explain** tab in the navigation
2. Choose your provider and paste your API key
3. Toggle **AI Explanation** on

### How it works

- Every new alert arriving via SSE is automatically submitted to the AI provider in the background
- The summary is cached — by the time you open the Explain dialog, it's already ready
- Open any alert → click **Explain** → open the **AI Summary** tab
- Use the **Refresh** button to regenerate if needed

### Providers

| Provider | Model | Notes |
|----------|-------|-------|
| OpenAI | `gpt-4o-mini` | Default. Low cost, ~1–2s latency. |
| Anthropic | `claude-3-5-haiku-20241022` | Consistent output. ~1–2s latency. |
| DeepSeek | `deepseek-chat` | Very low cost. ~2–4s latency. |

### API Key Storage

API keys are stored in the config database with XOR obfuscation and are **never** returned to the browser. The UI only shows whether a key has been set. Keys can also be set in `heimdall.conf` — the UI setting takes precedence.

### Disabling AI

When disabled: no API calls are made, no AI tab appears in the Explain dialog, and there is zero performance impact. Toggle it off at any time from the AI Explain settings panel.

---

## Webhooks

Send alert notifications to external tools.

### Supported types
- **Slack** — formatted with severity colour and alert metadata
- **Discord** — same format, Discord-compatible payload
- **Generic** — raw JSON POST to any HTTP endpoint

### Creating a webhook

Go to **Settings → Webhooks → Add Webhook**. Configure:
- **Name** — label for the webhook card
- **Type** — Slack, Discord, or Generic
- **URL** — destination endpoint
- **Severity filter** — only fire for selected severity levels
- **Allow local / private URLs** — enable this for LAN-hosted tools like **n8n**, Home Assistant, or Mattermost

> **n8n users:** Enable the "Allow local / private URLs" toggle on any webhook pointing to your n8n instance. By default, Heimdall blocks webhook destinations that resolve to private IP ranges (RFC-1918) to prevent SSRF attacks. This toggle explicitly permits them on a per-webhook basis.

A yellow **local** badge appears on the webhook card when this is enabled, so it's always visible.

---

## Security

### What's in place

| Protection | Implementation |
|------------|----------------|
| Brute-force protection | 10 failed logins per IP per 5 minutes → HTTP 429 + 2s delay |
| Clickjacking | `X-Frame-Options: DENY` on every response |
| MIME sniffing | `X-Content-Type-Options: nosniff` on every response |
| Content Security Policy | `default-src 'self'` — no CDN, no eval, no external scripts |
| Referrer leakage | `Referrer-Policy: no-referrer` on every response |
| Source code exposure | `.jsx` and `.py` files return HTTP 403 from the static handler |
| Webhook SSRF | Private/loopback IP destinations blocked by default |
| API key storage | XOR-obfuscated in DB; never returned to browser |
| SQL injection | Parameterised queries throughout; no string interpolation into SQL |
| Session security | bcrypt passwords; indexed sessions with expiry |



### systemd sandboxing
The service unit applies the following restrictions:

```ini
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
ReadWritePaths=/var/lib/heimdall /var/log/heimdall
ReadOnlyPaths=/var/log/suricata
```

### Network exposure
By default Heimdall binds to `0.0.0.0:8765`. If you only need local access, change `--host` to `127.0.0.1` in the service file. For remote access, put Nginx or Caddy in front with TLS.


### Known gaps

- **No TLS** — Heimdall listens on plain HTTP. For any network-exposed deployment, place behind nginx, Caddy, or use Tailscale.
- **No CSRF tokens** — acceptable for a localhost-first tool; add if exposing on a shared network.
- **No admin audit log** — user creation and role changes are not currently written to a dedicated audit trail.


### Recommended Nginx reverse proxy (TLS)

```nginx
server {
    listen 443 ssl;
    server_name heimdall.yourdomain.com;

    ssl_certificate     /etc/ssl/certs/heimdall.crt;
    ssl_certificate_key /etc/ssl/private/heimdall.key;

    location / {
        proxy_pass         http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection keep-alive;
        proxy_set_header   Host $host;
        proxy_buffering    off;  # Required for SSE
    }
}
```

---

## Building from Source


### Prerequisites

```bash
npm install -g esbuild   # for JSX compilation
sudo apt install dpkg-dev
```

```bash
<<<<<<< HEAD
# Clone or extract the source
cd heimdall-github/

# Build current default version (0.5)
bash build-deb.sh

# Build a specific version
bash build-deb.sh 0.6

# Output
# packaging/build/heimdall-ids_0.5_all.deb
=======
git clone https://github.com/dzidulajubilee/Heimdall.git
cd Heimdall
./build-deb.sh 0.4.1
# → packaging/build/heimdall-ids_0.4.1_all.deb
>>>>>>> 33d86bafdf87a86c7b59e0edfce9ee79f1d379f5
```

The build script:
1. Compiles all four skin `app.jsx` files to minified `app.js` via esbuild
2. Assembles the Debian package tree under `packaging/build/`
3. Copies backend Python modules, compiled frontend assets, and bundled fonts
4. Runs `dpkg-deb` to produce the `.deb`

**No npm, no pip, no webpack at runtime.** All build-time tools are separate from the installed package.

---

## Changelog

<<<<<<< HEAD
### v0.5 — May 2026
**Critical bug fix: service crash-restart loop on startup**
=======
### v0.4.1 — 2026-05-06
- **Fix:** `NameError: name 'threading' is not defined` in `handlers.py` — `import threading` was missing, causing the service to crash on startup in a restart loop
>>>>>>> 33d86bafdf87a86c7b59e0edfce9ee79f1d379f5

- **Bug:** `handlers.py` used `threading.Lock()` at module level to initialise `_LOGIN_LOCK` (introduced in the v0.2 security audit), but `import threading` was missing from the file's imports block. Python evaluates module-level statements the instant a file is imported, so `server.py` crashed on its very first `from handlers import Handler` with `NameError: name 'threading' is not defined` — before the HTTP server could start. systemd detected the crash and restarted in a loop.
- **Fix:** Added `import threading` to the imports block in `handlers.py`.
- **Verified:** `py_compile` check passes; live `import handlers` confirms `threading.Lock()` initialises correctly as `<unlocked _thread.lock object>`.

---

### v0.4 — May 2026
**Bundled web fonts — Inter + JetBrains Mono**

- Fonts are now fully bundled inside the `.deb`. Zero external font requests at runtime.
- **Inter** (sans-serif): weights 400, 500, 600, 700 — latin subset, woff2 format
- **JetBrains Mono** (monospace): weights 400, 500, 600 — latin subset, woff2 format
- Total font payload: **168 KB** across 7 files
- `frontend/fonts/fonts.css` created with `@font-face` declarations and `font-display: swap`
- All four skin stylesheets updated to `@import url('../../fonts/fonts.css')`
- `login.html` updated with `<link rel="stylesheet" href="fonts/fonts.css">`
- `handlers.py` updated: `woff2/woff/ttf` MIME types added; `font-src 'self'` added to CSP; font files served with long-term cache headers
- `build-deb.sh` updated to copy `frontend/fonts/` into the package
- Package size: ~160 KB (v0.3) → ~318 KB (v0.4), difference is entirely the font payload

---

### v0.3 — May 2026
**Webhook SSRF refined — n8n and LAN tools now supported**

The v0.2 blanket private-IP block would have broken any webhook pointing to a locally-hosted tool. Replaced with a per-webhook explicit opt-in:

- **`allow_local` field** added to the `webhooks` table in `config.db`
- Automatic DB migration for existing installs (`ALTER TABLE webhooks ADD COLUMN allow_local INTEGER NOT NULL DEFAULT 0`)
- `_ssrf_safe(url, allow_local=False)` — when `allow_local=True`, the private-IP check is bypassed entirely
- `deliver()` and `delivery_worker()` updated to pass `allow_local` through the call chain
- **Toggle UI** added to the webhook create/edit form in all four skins — animated switch with status hint text
- **Yellow `local` badge** shown on webhook cards where `allow_local` is active
- User-Agent header updated to `Heimdall-IDS/0.3`

---

### v0.2 — May 2026
**AI Explain for all skins + airgap, performance, and security audits**

#### AI Explain — all skins
- `AIExplainView` settings component added to Original, Mosaic, and Seal (Chronicles had it since v0.1)
- `AIExplanationPanel` in the Explain dialog for all four skins
- `aiSettings`, `aiExplanations`, `aiEnabledRef` state and `requestAiExplain()` helper in every skin's `App` component
- SSE auto-explain on new alerts in all four skins
- Nav label fix: key-based auto-capitalisation would have produced "Ai-explain"; replaced with an explicit label map in all four nav renderers

#### Airgap audit
- **Google Fonts removed** — `@import url('https://fonts.googleapis.com/...')` was in all four skin stylesheets and `login.html`, making outbound HTTP requests on every page load
- Replaced with system font stack: `var(--font-sans)` and `var(--font-mono)` CSS variables
- **`.jsx` source files blocked** — the static file handler now returns HTTP 403 for `.jsx` and `.py` requests

#### Performance audit
- SQLite PRAGMA tuning added to `database.py` and `dns_db.py`: `cache_size = -8000` (8 MB), `temp_store = MEMORY`, `mmap_size = 268435456` (256 MB)
- Missing alert indexes added: `idx_a_sigid` on `alerts(sig_id)`, `idx_a_src` on `alerts(src_ip)`, `idx_a_cat` on `alerts(category)`
- Session indexes added: `idx_sess_tok` on `sessions(token)`, `idx_sess_exp` on `sessions(expires_at)`
- PRAGMA tuning added to `auth.py`: WAL mode, `cache_size = -2000`
- `get_alert_meta` consolidated from 3 separate `_conn()` calls to 1 shared connection per request

#### Security audit
- Security headers on every HTTP response: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, full `Content-Security-Policy`
- Login rate limiting: 10 failures per IP per 5-minute window → HTTP 429 + 2-second delay; resets on successful login
- AI API key obfuscation: stored as `obf1:<base64(XOR(key, sha256_mask))>` in config DB; never returned to frontend
- Webhook SSRF protection: `_ssrf_safe()` blocks RFC-1918 and loopback destinations by default
- Per-webhook `allow_local` flag for explicit LAN tool opt-in

---

### v0.1 — May 2026
**Initial release**

#### Bug fix
- **Chronicles "Explain" button** was broken. `showExplain`/`explainAlert` state lived at the `App` level but the `ExplainDialog` was never rendered there. Fixed by moving both state variables into `ChronicleView` where the dialog now correctly lives, renders, and closes.

#### AI Explanation system (new module: `ai_explain.py`)
- Uses Python stdlib `urllib` only — no third-party packages, fully airgap-safe
- Supports OpenAI (`gpt-4o-mini`), Anthropic (`claude-3-5-haiku-20241022`), DeepSeek (`deepseek-chat`)
- Executive prompt: 3–5 sentence summary — what triggered the alert, likely threat type, recommended action
- Auto-explain on every new SSE alert when enabled
- API key stored in `config.db` (XOR-obfuscated); UI setting takes precedence over `heimdall.conf`

#### New API endpoints
- `GET /ai-config` — returns `{provider, enabled, api_key_set}`. Never returns the raw key.
- `PUT /ai-config` — admin-only; update provider, API key, enabled toggle
- `POST /ai-explain` — accepts alert JSON body, returns `{explanation: "..."}` string

#### New UI (Chronicles skin)
- **AI Explain** nav tab with full settings panel (provider selector, API key field, enable/disable toggle)
- **AI Summary** tab inside the Explain dialog alongside Threat Intel
- `AIExplanationPanel` component: spinner while loading, summary text when ready, error state, Refresh button

#### Other changes
- **Install-time password display** — `postinst` generates a random password, prints it in a bordered box to the terminal, saves to `/etc/heimdall/.credentials` (mode 640, root:heimdall)
- **License changed** from MIT to GNU AGPL v3.0
- **Versioning** started at v0.1; `build-deb.sh` updated accordingly

---

## License

Heimdall IDS is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

This means:
- You can use, modify, and distribute Heimdall freely
- If you run a modified version as a network service, you must make the source code available to users under the same license
- See [LICENSE](LICENSE) for the full text

---

<<<<<<< HEAD
*Heimdall IDS — G-Sentry*
=======
If you run a modified version of this software on a network server, you must make the complete source code available to users interacting with it remotely, under the terms of this License.


>>>>>>> 33d86bafdf87a86c7b59e0edfce9ee79f1d379f5
