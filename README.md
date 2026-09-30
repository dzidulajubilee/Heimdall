# Heimdall IDS Dashboard

**A self-hosted, fully airgapped network intrusion detection dashboard for Suricata.**  
Built by G-Sentry · Licensed under [GNU AGPL v3.0](LICENSE)

---

## What is Heimdall?

Heimdall IDS is a lightweight web dashboard that sits on top of [Suricata](https://suricata.io/) and turns raw `eve.json` output into a real-time analyst workstation. It requires no internet connection, no cloud services, and no runtime dependencies beyond Python 3.10.

- **Live alert feed** — new events pushed instantly via Server-Sent Events (zero polling)
- **Full triage workflow** — per-alert status, analyst notes, and timestamped activity log
- **Threat intelligence** — per-signature knowledge base with CVE and MITRE ATT&CK linking
- **Suppression rules** — drop noisy signatures at ingestion; they never reach the database
- **AI executive summaries** — auto-explain every alert via OpenAI, Anthropic, or DeepSeek
- **Webhooks** — push alerts to Slack, Discord, n8n, or any HTTP endpoint
- **Four UI skins** — Original, Chronicles, Mosaic, Seal (switchable live, no restart)
- **Role-based access** — Admin, Analyst, Viewer roles enforced at the API level
- **Installs in one command** — ships as a `.deb` package, runs as a `systemd` service

---

## Table of Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [First Login](#first-login)
4. [Configuration](#configuration)
   - [HTTPS](#https)
5. [Architecture](#architecture)
6. [Features](#features)
7. [Skins](#skins)
8. [AI Explanation](#ai-explanation)
9. [Webhooks](#webhooks)
10. [Security](#security)
11. [Building from Source](#building-from-source)
12. [Changelog](#changelog)
13. [License](#license)

---

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
sudo apt install ./heimdall-ids_1.4.5_all.deb
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

### AI-Free Variant

A second package — `heimdall-ids-noai` — ships without the AI Explain module. It is otherwise identical and installs the same way. Use this variant in environments where AI API connectivity is prohibited by policy.

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

**Reset any other account** (for example a user who is locked out or disabled):
```bash
sudo heimdall --password <newpassword> --user bob
```
This resets the password, ends the user's sessions and re-enables the account if it was disabled; the role is unchanged. The account must already exist — if it does not, the command lists the existing usernames. Every reset is recorded in the audit log.

Without `--user`, the command resets `admin`. This is also the lock-out recovery path: it always leaves a working `admin` login with the admin role — creating the `admin` user if it was deleted, or re-enabling and re-promoting it if it was disabled or demoted — and ends every existing `admin` session. Since v1.4.4 the original install password stops working as soon as the admin password is changed.

---

## Configuration

Edit `/etc/heimdall/heimdall.conf` then restart the service:

```bash
sudo nano /etc/heimdall/heimdall.conf
sudo systemctl restart heimdall
```

The file holds one option per line, written exactly as on the command line (for example `--port 8765` or `--retain-days=30`); `#` starts a comment. The `heimdall` command always reads it (it passes `--config /etc/heimdall/heimdall.conf`), and options given on the command line override the file. Unknown options in the file are ignored with a warning in the journal; an invalid value (e.g. `--port abc`) stops startup and names the file and line. Option values are never written to the log.

> **Upgrading from 1.4.3 or earlier:** before v1.4.4 this file was never read. Any option you had already uncommented takes effect after the upgrade — review the file first.

| Option | Default | Description |
|--------|---------|-------------|
| `--eve <path>` | `/var/log/suricata/eve.json` | Path to Suricata `eve.json` |
| `--host <addr>` | `0.0.0.0` | Bind address |
| `--port <n>` | `8765` | Listening port |
| `--retain-days <n>` | `90` | Alert and flow retention in days |
| `--skin <name>` | `original` | Default skin for users who have not picked one: `original`, `chronicles`, `mosaic`, `seal`. A skin chosen with the switcher still wins. |
| `--ai-provider <name>` | `openai` | AI provider (`openai`, `anthropic`, `deepseek`), used until AI settings are saved in the UI |
| `--ai-key <key>` | _(none)_ | AI API key, used while no key is stored via the UI. Never copied into the database. Prefer the config file over the command line (command lines are visible in `ps`). |
| `--tls-cert <file>` / `--tls-key <file>` | _(off)_ | Built-in HTTPS — see [HTTPS](#https). Both are required together. |
| `--behind-proxy` | _(off)_ | Heimdall runs behind a reverse proxy on the same host: trust its `X-Real-IP` / `X-Forwarded-Proto` headers, from `127.0.0.1` only. Set automatically by `--setup-nginx`. |
| `--config <file>` | — | Read options from a file (command line only) |
| `--password <pw>` | — | Reset an account's password, then exit (command line only) |
| `--user <name>` | `admin` | With `--password`: the account to reset (command line only) |
| `--setup-nginx` / `--remove-nginx` | — | Put Heimdall behind NGINX, or undo it — see [HTTPS](#https) (command line only) |

### HTTPS

Heimdall can be reached over HTTPS in two ways. Both are off by default.

**Recommended — behind NGINX (Heimdall is not exposed at all):**

```bash
sudo heimdall --setup-nginx                                   # self-signed certificate
sudo heimdall --setup-nginx --nginx-cert /path/cert.pem --nginx-key /path/key.pem
sudo heimdall --setup-nginx --nginx-server-name ids.example.net   # optional host name
```

This single command:

1. Installs NGINX with `apt` if it is missing.
2. Uses your certificate, or generates a self-signed one (2048-bit RSA, 825 days) in `/etc/heimdall/tls/` whose names include the host name and IP addresses. It prints the certificate's SHA-256 fingerprint so users can verify it. A later run reuses it.
3. Writes one NGINX site (`/etc/nginx/sites-available/heimdall`): HTTPS on 443 (TLS 1.2/1.3), port 80 redirecting to HTTPS, and the live-alert stream unbuffered.
4. Binds Heimdall to `127.0.0.1` and enables `--behind-proxy`, through a clearly marked block at the end of `/etc/heimdall/heimdall.conf`. A timestamped backup of the file is kept; your own settings in it are untouched.
5. Checks the result with `nginx -t`, then reloads NGINX and restarts Heimdall. If any step fails, every change is rolled back.

Afterwards users open `https://<host>/`; `http://<host>:8765` no longer answers from the network. Other NGINX sites are never modified: if another site or program already uses port 443, setup stops without changing anything. When setup installs NGINX itself, NGINX's stock "Welcome to nginx" site is disabled.

`--behind-proxy` keeps the login lockout and the audit log per real user: the client address comes from NGINX's `X-Real-IP` header, which Heimdall accepts only from `127.0.0.1` — a client cannot fake it.

**Undo:** `sudo heimdall --remove-nginx` removes the Heimdall site and the managed block, reloads NGINX and restarts Heimdall on its own `--host`/`--port`. The NGINX package and the certificate are kept.

**Alternative — built-in HTTPS (no NGINX):** add to `heimdall.conf`

```
--tls-cert /etc/heimdall/tls/cert.pem
--tls-key  /etc/heimdall/tls/key.pem
```

The key must be readable by the `heimdall` user and no one else (`chown root:heimdall key.pem && chmod 640 key.pem`). Heimdall then serves HTTPS on its usual port (TLS 1.2 minimum) and refuses to start if the certificate cannot be loaded, rather than falling back to plain HTTP. `--setup-nginx` will not run while built-in HTTPS is enabled.

With either option the session cookie is marked `Secure`. HSTS is not sent, because it would apply to every port on the host.

**Service management:**

```bash
sudo systemctl status heimdall       # check status
sudo systemctl restart heimdall      # restart after config changes
sudo journalctl -u heimdall -f       # follow live logs
sudo apt remove heimdall-ids         # remove (data preserved)
sudo apt purge heimdall-ids          # remove including all data
```

---

## Architecture

Heimdall is a single self-contained Python process with no external runtime dependencies.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Heimdall Process                            │
│                                                                     │
│  ┌──────────────┐   ┌──────────────────────────────────────────┐    │
│  │  tail_thread │   │            HTTP Server                   │    │
│  │              │   │     (stdlib http.server, port 8765)      │    │
│  │  Reads and   │   │                                          │    │
│  │  parses      │──▶│ REST API  │  Static Files  │  SSE /events│    │
│  │  eve.json    │   └──────────────────────────────────────────┘    │
│  │  line by     │                      │                            │
│  │  line        │   ┌──────────────────▼───────────────────────┐    │
│  │              │   │            SQLite Databases              │    │
│  │  Applies     │   │                                          │    │
│  │  suppression │   │  events.db     config.db     dns.db      │    │
│  │  rules       │   │  ─────────     ─────────     ──────      │    │
│  │              │   │  alerts        users          dns        │    │
│  │  Broadcasts  │   │  flows         sessions       events     │    │
│  │  to SSE      │   │  http_events   webhooks                  │    │
│  │              │   │  alert_notes   suppression               │    │
│  │  Dispatches  │   │  alert_activity threat_intel             │    │
│  │  webhooks    │   │  alert_meta    ai_settings               │    │
│  │              │   │                audit_log                 │    │
│  └──────────────┘   └──────────────────────────────────────────┘    │
│                                                                     │
│  ┌────────────────┐  ┌───────────────┐  ┌──────────────────────┐    │
│  │ delivery_worker│  │  purge_thread │  │    replay_thread     │    │
│  │                │  │               │  │                      │    │
│  │ Drains webhook │  │ Hourly purge  │  │ Re-reads eve.json    │    │
│  │ delivery queue │  │ of old rows.  │  │ from start to fill   │    │
│  │ with retries   │  │ Cascades to   │  │ gaps (e.g. after     │    │
│  │ (max 3)        │  │ notes/activity│  │ downtime). Admin-    │    │
│  └────────────────┘  └───────────────┘  │ triggered via UI.    │    │
│                                         └──────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
         │ reads                                   │ serves
         ▼                                         ▼
  /var/log/suricata/              Browser (Chrome / Firefox / Safari)
       eve.json
  (Suricata output)           ┌─────────────────────────────────────┐
                              │ React SPA (no build step at runtime)│
                              │                                     │
                              │ skin-loader.js?v=N →styles.css?v=N  │
                              │                   → app.js?v=N      │
                              │                  → styles.css?v=N   │
                              │                                     │
                              │  Four skins: original · chronicles  │
                              │              mosaic  · seal         │
                              │                                     │
                              │  Fonts: Inter + JetBrains Mono      │
                              │  (bundled, zero external requests)  │
                              └─────────────────────────────────────┘
```

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Single Python process** | Zero installation complexity — no app server, no message broker, no reverse proxy required |
| **SQLite** | Fully embedded, no separate database process, trivially backed up with `cp` |
| **Server-Sent Events** | One-way push from server to browser; no WebSocket handshake overhead; survives proxies |
| **stdlib-only backend** | No `pip install` needed at runtime; safe in airgapped/restricted environments |
| **Versioned asset URLs** | `app.js?v=1.4.1` changes on every release; JS/CSS served `immutable` so the browser caches forever, but the URL change on upgrade forces an automatic fresh fetch — no hard reloads needed |
| **Four compiled skins** | Each skin is an independent esbuild bundle; switching skins loads a fresh JS bundle, no shared state |
| **AGPL-3.0** | Source must remain open if Heimdall is run as a network service |

---

## Features

### Alert Feed
Real-time alert list with severity badges, source/destination IPs, protocol, and timestamp. New alerts appear instantly via Server-Sent Events — no polling, no page refresh.

### Alert Triage
Click any alert to open the detail panel:
- **Status** — mark as `acknowledged`, `investigating`, or `closed` (or clear the status)
- **Analyst notes** — add timestamped notes visible to the whole team
- **Activity log** — full audit trail of every status change and note

### Bulk Triage
Select multiple alerts and apply a status or note to all of them in one action. Useful for clearing large volumes of known-benign traffic.

### Threat Intelligence
Build a per-signature knowledge base. Each entry supports:
- Description and recommended response
- CVE references
- MITRE ATT&CK technique mapping
- Analyst notes
- Import/export via `.htf` (Heimdall Threat Feed) text format with overwrite support

The **Gaps** view lists the top signatures currently firing without any intel entry.

### Suppression Rules
Create rules to drop noisy or known-safe signatures at the ingestion layer. Suppressed alerts never reach the database or the SSE stream — they consume no storage and generate no UI noise.

### Eve.json Replay
If Heimdall was offline while Suricata kept running, the **Replay** button re-reads `eve.json` from the beginning and fills any gaps in the database. Runs in the background; the dashboard stays fully usable during replay.

### Analytics
- Alert volume timeseries chart (24h / 7d / 30d / 60d / 90d windows)
- By-severity breakdown bar chart
- Top source IP addresses
- Alert category donut chart

### Multi-User Access

| Role | Permissions |
|------|-------------|
| **Admin** | Everything — users, webhooks, settings, AI config, suppression, flush/replay |
| **Analyst** | Alert triage (status, notes, bulk status), threat intel create/edit/import |
| **Viewer** | Read-only access to all views, including AI summaries |

Roles are enforced at the API level and checked against the user's current account on every request: disabling, deleting or changing the role of a user takes effect immediately, including on their open live-alert stream.

### Audit Log
**Settings → Audit Log** (admins only) shows who changed what, newest first: sign-ins (successful and failed), user and role changes, webhook changes and tests, suppression rules, threat intel edits and imports, data clears, flush and replay, AI settings, and command-line password resets and NGINX setup/removal. Each entry records the time, user, role, client IP, action, target and details.

Secrets are never recorded: passwords and API keys appear only as "changed", and webhook URLs only by host name because their paths contain tokens. The log keeps the newest 100,000 entries. It is also available as JSON from `GET /audit` (admin only; `limit`, `offset`, `action` prefix and `user` filters), and each entry is written to the journal (`journalctl -u heimdall | grep AUDIT`) for forwarding to a SIEM.

### Data Management
Per-table **Clear All** buttons let admins flush alerts, flows, or DNS records independently. After a flush, **Replay** can restore alert history from `eve.json`.

---

## Skins

Switch between skins at any time from the Settings panel or the skin switcher widget in the bottom-right corner. No restart required.

| Skin | Style | Best For |
|------|-------|----------|
| **Original** | Warm charcoal, Space Grotesk | High information density, classic list view |
| **Chronicles** | Obsidian violet, Inter | Timeline-focused analysis, heatmap header |
| **Mosaic** | Glass indigo, Inter | Card-grid layout, large monitors |
| **Seal** | Navy steel, Space Mono | Minimal monochrome, focused analysis sessions |

All skins share the same full feature set, bundled fonts (Inter + JetBrains Mono), and the same React runtime. No skin makes any external network requests.

---

## AI Explanation

Heimdall can automatically generate a short, actionable executive summary for every new alert using an AI provider of your choice.

### Setup

1. Go to the **AI Explain** tab in the navigation
2. Choose your provider and paste your API key
3. Optionally choose a **Model**. Click **Load models** to ask the provider which models your key can use — newly released models appear there without a Heimdall update — or type any model ID. Leave it blank to use the provider's default. Each provider remembers its own model.
4. Toggle **AI Explanation** on and click **Save Settings**

### How It Works

- Every new alert arriving via SSE is automatically submitted to the AI provider in the background
- Summaries are generated **once per alert on the server** and shared by every user and browser tab; simultaneous requests for the same alert wait for a single provider call. The cache lives in memory (last 2,000 alerts) and is cleared on restart or when AI settings change
- The prompt is built from the alert as stored in the database — the browser only says *which* alert, so the endpoint cannot be used to send arbitrary text to the provider
- Open any alert → click **Explain** → open the **AI Summary** tab

### Providers

| Provider | Default model | Notes |
|----------|---------------|-------|
| OpenAI | `gpt-4o-mini` | Default provider. Low cost, ~1–2s latency. |
| Anthropic | `claude-haiku-4-5-20251001` | Anthropic's documented successor to `claude-3-5-haiku-20241022`, which was retired in February 2026. |
| DeepSeek | `deepseek-chat` | Very low cost. ~2–4s latency. |

Any model the provider offers can be selected instead of the default (see *Setup*). **Load models** calls the provider's own model-list API (`/v1/models` for OpenAI and Anthropic, `/models` for DeepSeek) from the Heimdall server with the saved key, or with a key typed into the form, which is used for that lookup only and not stored. It is admin-only and, like AI Explain itself, needs outbound HTTPS to the provider. Summaries are capped at 1,024 output tokens so that reasoning models have room to answer; ordinary models stop far earlier.

### API Key Storage

API keys are stored in the config database with XOR obfuscation and are **never** returned to the browser. The UI only shows whether a key has been set. Keys can also be set in `heimdall.conf` (`--ai-key`) — a key saved in the UI takes precedence, and the config-file key is never copied into the database.

---

## Webhooks

Push alert notifications to external tools whenever a matching alert arrives.

### Supported Types
- **Slack** — Block Kit formatted, severity-coloured
- **Discord** — Embed formatted
- **Generic** — Raw JSON POST (works with n8n, Mattermost, Teams, Home Assistant, etc.)

### Creating a Webhook

Go to **Settings → Webhooks → Add Webhook** (admins only — webhook URLs contain secrets, so all webhook endpoints require the Admin role). Configure:
- **Name** — label for the webhook card
- **Type** — Slack, Discord, or Generic
- **URL** — destination endpoint
- **Severity filter** — only fire for selected severity levels
- **Allow local / private URLs** — enable for LAN-hosted tools like n8n

> **n8n / LAN tools:** Enable "Allow local / private URLs" for any webhook pointing to a private-IP destination. By default Heimdall blocks RFC-1918, loopback, link-local, `0.0.0.0/8`, carrier-grade NAT / Tailscale (`100.64.0.0/10`) and IPv6 private/loopback/link-local addresses (including IPv4-mapped forms) to prevent SSRF. This toggle opts that webhook in explicitly. A yellow **local** badge appears on the card as a reminder.
>
> HTTP redirects are never followed — point each webhook at its final URL.

### Behaviour
- Deliveries are queued and processed in a background thread — they never block alert ingestion
- Failed deliveries are retried up to 3 times with a 5-second delay between attempts
- Per-signature deduplication: the same SID will not fire the same webhook more than once per 60 seconds during burst events (scans, floods)
- Fire count and last-fired time update on the webhook card in real time

---

## Security

### Protections in Place

| Protection | Implementation |
|------------|----------------|
| Brute-force protection | 10 failed logins per IP per 5 minutes → HTTP 429 + 2s delay |
| Clickjacking | `X-Frame-Options: DENY` on every response |
| MIME sniffing | `X-Content-Type-Options: nosniff` on every response |
| Content Security Policy | `default-src 'self'` — no CDN, no eval, no external scripts |
| Referrer leakage | `Referrer-Policy: no-referrer` on every response |
| CSRF defence | `SameSite=Strict` session cookie + Origin/Referer header validation on all write requests |
| Source code exposure | `.jsx` and `.py` files return HTTP 403 from the static handler |
| Webhook SSRF | Webhooks are admin-only; private, loopback, link-local, CGNAT and IPv4-mapped destinations blocked by default (opt-in per webhook); redirects not followed |
| API key storage | XOR-obfuscated in DB; never returned to browser |
| SQL injection | Parameterised queries throughout; no string interpolation into SQL |
| Transport security | Optional HTTPS via `--setup-nginx` (Heimdall bound to loopback) or built-in TLS 1.2+; `Secure` session cookie over HTTPS |
| Audit trail | Admin-only audit log of sign-ins and all configuration and data-management changes; secrets never recorded |
| Session security | PBKDF2-SHA256 passwords (260,000 iterations); indexed sessions with 7-day expiry, re-validated against the user's current account on every request; password reset, disable and delete revoke sessions |
| Body size limits | Request bodies capped at 4 MB; bulk alert operations capped at 500 IDs |

### Known Gaps

- **HTTPS is opt-in** — out of the box Heimdall listens on plain HTTP. For any network-exposed deployment use `sudo heimdall --setup-nginx` or built-in HTTPS (see [HTTPS](#https)).
- **Webhook DNS rebinding** — the SSRF check resolves the hostname before delivery and the connection resolves it again, so a hostname whose DNS answer changes in between could reach a blocked address. Only admins can configure webhook URLs.

---

## Building from Source

**Requirements:** `esbuild` (`npm install -g esbuild`), `dpkg-deb`

```bash
# Build default version (1.4.5)
bash build-deb.sh

# Build a specific version
bash build-deb.sh 1.4.6

# Output
# packaging/build/heimdall-ids_1.4.5_all.deb
# packaging/build/heimdall-ids-noai_1.4.5_all.deb
```

The build script:
1. Compiles all four skin `app.jsx` files to minified JS via esbuild (`app.js`)
2. Assembles the Debian package tree, copies backend Python, frontend assets, and bundled fonts
3. Substitutes `__HEIMDALL_VERSION__` with the actual version string in `index.html` and `skin-loader.js`, baking `?v=VERSION` into every asset URL
4. Runs `dpkg-deb` to produce the `.deb`
5. Repeats steps 1–4 for the AI-free `noai` variant via `strip-ai.py`

**Tests:** `python3 -m unittest discover -s tests -v` runs the regression and fix suites (stdlib only; the skin-loader check also needs `node`). The `tests/` directory is not packaged.

**Asset caching model:** `index.html` is served `no-cache` so the browser always fetches it fresh. All JS, CSS, and fonts are served `immutable` with `?v=VERSION` appended to their URLs. When a new version is installed, the URL changes and the browser automatically fetches the updated files — no hard reload or cache clearing needed. **Always increment the version on every build** (`bash build-deb.sh 1.4.1`, `bash build-deb.sh 1.4.2`, etc.) — that is the only discipline required.

---

## Changelog

### v1.4.5 — September 2026

**HTTPS:**
- `sudo heimdall --setup-nginx` puts Heimdall behind NGINX in one step: NGINX is installed if missing, HTTPS on 443 with your certificate or a generated self-signed one, port 80 redirects, Heimdall is bound to `127.0.0.1` so only NGINX is exposed, and everything is validated with `nginx -t` and rolled back on failure. `sudo heimdall --remove-nginx` undoes it.
- New `--behind-proxy` mode keeps the login lockout and audit log per real client behind a proxy (headers trusted from `127.0.0.1` only).
- Built-in HTTPS as an alternative: `--tls-cert` / `--tls-key` (TLS 1.2+, refuses to start if the certificate cannot be loaded).
- The session cookie is marked `Secure` over HTTPS.

**Audit log:** new admin-only **Audit Log** card in Settings and `GET /audit` endpoint, recording sign-ins and every configuration and data-management change. Secrets are never recorded. New `audit_log` table in `config.db` (created automatically; nothing existing changes).

**Account recovery:** `sudo heimdall --password <pw> --user <name>` resets any account (password reset, sessions ended, re-enabled if disabled, role unchanged). `--user` is refused in `heimdall.conf`, so a stray line there can never redirect a reset.

**Fixes:**
- A rejected user edit (for example, demoting the last admin) no longer changes the password anyway: all checks now run before anything is saved.
- Renaming a user to an existing name returns a clear 409 error instead of a server error; empty usernames are rejected.
- Sending `null` for `enabled` in a user edit no longer disables the account.
- Non-numeric signature IDs or expiry times in threat intel and suppression requests return 400 instead of a server error.

---

### v1.4.4 — September 2026

Security and correctness fixes from a code audit, plus AI model selection. One additive schema change: a `models` column on `ai_settings` (added automatically on startup; existing settings are preserved and older versions ignore it).

**Security:**
- **Webhooks are admin-only at the API.** Any logged-in user (including Viewer) could list webhooks (exposing Slack/Discord secret URLs), create or edit them — including with *Allow local* — and use **Test** to make the server POST to internal hosts. All webhook endpoints now require the Admin role, matching the UI.
- **SSRF filter bypasses closed.** `0.0.0.0` (which reaches localhost on Linux), IPv4-mapped IPv6 such as `::ffff:127.0.0.1`, `100.64.0.0/10`, `::` and `fe80::/10` passed the private-address check; redirects were followed to unchecked hosts. Webhooks to CGNAT/Tailscale addresses now need *Allow local*.
- **Legacy install password removed.** The password generated at install kept logging in as admin forever — after the admin password was changed in the UI, with a blank username, and even for a disabled or deleted admin. Login now uses the user table only; `heimdall --password` remains the recovery path and always restores a working, enabled admin.
- **Sessions follow the account.** Disabling, deleting or demoting a user had no effect on their sessions for up to 7 days. Sessions are now checked against the user's current account on every request (live SSE streams are closed within one keep-alive), and password reset, disable and delete revoke sessions. Sessions of deleted/disabled users left by older versions are purged at startup.
- **AI Explain cannot be abused.** `/ai-explain` sent any client-supplied text to the paid provider for any role. Prompts are now built from the stored alert only.

**Fixes:**
- **Flush all** failed with HTTP 500 after deleting alerts, flows and HTTP records, leaving DNS untouched (it targeted a non-existent `dns_queries` table).
- **Replay** now applies suppression rules; suppressed alerts were re-ingested. Replay status gains a `suppressed` count.
- **`/etc/heimdall/heimdall.conf` is now read.** It was ignored, and the documented `--skin`, `--ai-provider` and `--ai-key` options did not exist. See *Configuration* — options already uncommented there take effect on upgrade.
- **AI cost no longer scales with open tabs.** Each open tab requested its own summary of every alert; summaries are now cached per alert on the server and concurrent requests share one call.
- **Timestamps with non-UTC offsets** (e.g. `+0100`) were replaced by the ingestion time on Python 3.10, and flow durations were 0. The alert timestamp is now included in AI prompts.
- SSE streams ended by the server now close the connection instead of hanging.

**AI model selection:**
- Every provider now has a selectable **Model**. **Load models** lists the models your key can use straight from the provider, so new models can be used without waiting for a Heimdall release; any model ID can also be typed in. Each provider remembers its own choice.
- The Anthropic default is now `claude-haiku-4-5-20251001`; `claude-3-5-haiku-20241022` was retired by Anthropic in February 2026, so the Anthropic provider had stopped working. OpenAI and DeepSeek defaults are unchanged.
- OpenAI requests use `max_completion_tokens` (required by OpenAI reasoning models); the output cap is 1,024 tokens for all providers (was 300). Provider errors are now readable (e.g. "Anthropic returned HTTP 404: model not found") and never echo API keys.

**Docs:** triage statuses, Analyst permissions, database table names and configuration corrected to match the code. Added a stdlib-only test suite (`tests/`).

---

### v1.4.2 — May 2026

**Health state architecture fix (all four skins):**
- `health` state was only defined inside `SettingsView`, not in the `App` component. The statusbar renders inside `App`, so `health?.status` and `health?.retain_days` resolved to `undefined`, causing a React crash and a blank page on login. Fixed: `health` state is now owned by `App`, fetched on mount, polled every 10 seconds, and passed down to `SettingsView` as a prop.
- All four skins had the duplicate local `health` state, `loadHealth` function, and `setInterval` removed from `SettingsView` — health is now fetched once at the App level, not twice.
- `onDataFlushed` callback now triggers an immediate `/health` re-fetch in all four skins, so Server Health stats update instantly after clearing alerts/flows/DNS rather than waiting up to 10 seconds for the next poll.

**Source tree cleanup:**
- Stale content-hashed artifacts (`app-XXXX.js`, `styles-XXXX.css`, `manifest.json`) left over from the experimental content-hash pipeline removed from the source tree. The installed deb was always correct — these were dead files in the working directory only.
- Removed unreachable `.jsx` entry from the `_MIME` map in `handlers.py` — `.jsx` files are blocked at HTTP 403 before the MIME lookup, so the entry was dead code.

**postinst hardening:**
- `postinst` now detects if `server.py --password` fails and prints a clear warning instead of silently showing credentials that won't work. Error output is saved to `/tmp/heimdall-init.log` for diagnosis.

---

### v1.4.1 — May 2026

**Admin credential fix (critical):**
- `postinst` generated a password and called `server.py --password $ADMIN_PW` to store it. The `--password` mode set the hash in the legacy `auth` table and exited — `UserManager.bootstrap_admin()` never ran, so the `users` table had no `admin` row. When the server started normally, `bootstrap_admin()` saw an empty users table and generated a **different** random password, logging it only to the journal. The credentials displayed on screen during install were wrong. Fixed: `--password` mode now creates the admin user row in the `users` table directly (or updates it if users already exist), ensuring the displayed password is exactly what works at login.

**User password editing (all four skins):**
- The Edit User modal only allowed changing a user's role — no password field was shown. Fixed: when editing an existing user, a **New Password** field now appears with a `(leave blank to keep current)` hint. If filled, the password is included in the PUT body; if left blank it is omitted and the existing password is unchanged.

**Blank screen on Edit User (chronicles, mosaic, seal):**
- The `newPw` state variable was added to the JSX but the `useState` declaration was missing in chronicles, mosaic, and seal. React threw a `ReferenceError` on mount, unmounting the entire component tree and producing a blank page. Fixed in all three skins.

**postrm cleanup:**
- `apt purge` left `/opt/heimdall` and `/etc/heimdall` behind with a warning because those directories contain files dpkg didn't install (SQLite databases, `.credentials`). `postrm` now explicitly `rm -rf`s all four Heimdall directories on purge, and also removes the `heimdall` group.

**AI Explain view centred:**
- The AI Explain content column had `maxWidth: 760` but no `margin: '0 auto'`, so it pinned to the left edge on all skins. Fixed.

**Dynamic statusbar:**
- Database dot was hardcoded green. Now reads `health?.status === 'ok'` — turns red and shows "DB Error" if `/health` fails.
- "Retain 90 days" was hardcoded. Now reads `health?.retain_days` from the server, reflecting whatever `--retain-days` is configured.
- `/health` response now includes `"retain_days": self.db.retain_days`.
- Original skin was missing a 10-second health poll in the `App` component — only fetched on mount. Fixed.

---

### v1.4 — May 2026

**Versioned asset URLs — automatic cache invalidation on upgrade:**
- `build-deb.sh` substitutes `__HEIMDALL_VERSION__` with the build version at package time, baking `?v=1.4` into every asset URL in `index.html` and `skin-loader.js`
- `skin-loader.js` loads `styles.css?v=VERSION` and `app.js?v=VERSION` for the active skin
- `index.html` is served `no-cache`; all JS, CSS, and fonts are served `immutable`
- When a new version is installed, every asset URL changes — the browser automatically fetches fresh files on the next normal page load, no hard reload required
- **Rule:** increment the version on every build (`bash build-deb.sh 1.4.1`) — that is the only discipline needed for cache correctness

**Webhook fire count now updates in real time:**
- `testWebhook()` in all four skins now calls `loadWebhooks()` immediately after the test completes, so fire count and last-fired time update on the card without a page reload
- A 30-second `setInterval` poll on `loadWebhooks` was added to all skins' Settings `useEffect`, keeping counts current as live alerts trigger webhook deliveries

**Webhook Test button now respects `allow_local`:**
- `_webhook_test` in `handlers.py` was calling `deliver(url, payload)` without passing `allow_local`, so the Test button always blocked private-IP webhooks regardless of the toggle. Fixed — now passes `allow_local=wh.get("allow_local", False)`

**Mosaic and Seal webhook card styling:**
- Both skins had only `.wh-settings-card` defined in their CSS — all inner elements (`.wh-top`, `.wh-name`, `.wh-toggle`, `.wh-url`, severity pills, `.wh-meta`, `.wh-actions`, `.wh-error`) were completely unstyled. Added all missing classes to both skins.

**Replay and Flush panels visible across all skins:**
- `ReplayFlushPanel` was using inline styles referencing CSS variables (`var(--s1)`, `var(--ln)`) that resolve differently across themes, making the panel invisible in some theme/skin combinations. Replaced inline styles with `.settings-card` / `.settings-card-header` / `.settings-card-body` / `.settings-card-title` class names — consistent with every other settings card in all four skins.

**Suppression rules now enforced (critical fix):**
- `tail_thread()` did not receive `sup_db` as a parameter and never called `sup_db.is_suppressed()`. Every alert passed through unconditionally regardless of configured suppression rules. Fixed: `tail_thread` now accepts `sup_db=None` and checks suppression before every insert and broadcast. `server.py` passes `sup_db` via `kwargs`.

**`purge_old()` orphan cascade (critical fix):**
- The hourly purge deleted rows from `alerts`, `flows`, and `http_events` but left all `alert_notes`, `alert_activity`, and `alert_meta` rows for those alerts as orphans. On a busy sensor these tables grew without bound. Fixed: metadata tables are now purged first (before the parent rows are deleted) using a `WHERE alert_id NOT IN (SELECT id FROM alerts WHERE ts_epoch>=?)` subquery.

**Immutable asset cache-busting (high fix):**
- All skin JS and CSS was served with `Cache-Control: immutable` but with static filenames (`app.js`, `styles.css`) and no version in the URL. After a deb upgrade, browsers would serve the old cached files for up to a year. Fixed: `?v=VERSION` is now baked into every asset URL at build time; upgrading to a new version automatically changes the URLs and forces a fresh fetch.

**`count_alerts()` cache keyed by days (high fix):**
- The count cache stored a single integer. If two requests used different `days` windows within the 5-second TTL, the second got the first's stale count, returning a wrong `total` in paginated alert responses. Fixed: cache is now a `dict` keyed by the `days` integer; `invalidate_count_cache()` clears all keys.

**Alert ID collision fix (high fix):**
- Alert IDs were composed as `f"{flow_id}-{sig_id}-{ts}"`. When `flow_id=0` (common for non-flow alerts) and the same signature fired from two different source IPs in the same second, both produced the same ID — the second was silently dropped by `INSERT OR IGNORE`. Fixed: `src_ip` is now included in the composite key.

**Mosaic Data Management alignment fix:**
- Mosaic's Settings JSX used `data-mgmt-row` / `data-mgmt-label` / `data-mgmt-sub` class names while its own CSS defined `data-action-row` / `data-action-info` / `data-action-sub`. The Clear All buttons rendered below the record count instead of on the right. Fixed via `sed` rename.

**Raw `.jsx` source removed from installed packages:**
- `build-deb.sh` was copying `app.jsx` source files into both deb packages alongside the compiled `app.js`. The server correctly refused to serve them but they were dead weight (~550 KB). Removed.

---

### v1.3 — May 2026

- Overwrite toggle in Threat Intel import redesigned as an animated pill switch
- Webhook per-SID cooldown deduplication: one notification per (webhook, SID) per 60-second window during burst events
- `import_htf` overwrite sentinel bug fixed (duplicate SIDs in same batch could overwrite twice)

### v1.2 — May 2026

- HTF import **Overwrite** mode — existing entries updated in-place instead of skipped; result banner shows imported/overwritten/skipped counts
- **Clear All** button in Threat Intel action bar (admin only, inline confirmation)
- `ThreatIntelDB.clear_all()` and `DELETE /threat-intel` route

### v1.1 — May 2026

- Request body size cap: 4 MB hard limit, HTTP 413 if exceeded
- Security headers on all JSON responses
- CSRF Origin/Referer validation on all state-changing requests
- Bulk alert status capped at 500 IDs
- Field length limits: usernames ≤ 64, passwords ≤ 256, notes ≤ 4000, webhook URLs ≤ 2048
- `DedupFilter` O(n) → O(1) with parallel set
- Compiled JS/CSS/fonts switched to `Cache-Control: immutable`

### v1.0 — May 2026

- `_read_json()` tuple return fix — `_ti_create`, `_ti_update`, `_sup_create`, `_sup_update` all crashed with `AttributeError` on every call
- `_import_htf()` and `_export_htf()` implemented (were called but never defined)
- Missing `POST /suppression`, `PUT /threat-intel/{id}`, `PUT /suppression/{id}`, `DELETE` routes added
- CSS variables `--sans`, `--teal`, `--accent-rgb`, `--radius-sm/md/lg` aligned across all four skins

### v0.5 — May 2026

- `import threading` added to `handlers.py` — server crashed on import with `NameError` before it could start

### v0.4 — May 2026

- Inter + JetBrains Mono fonts bundled in the `.deb` (168 KB, 7 woff2 files) — zero external font requests

### v0.3 — May 2026

- `allow_local` per-webhook field for private/LAN destinations (n8n, Mattermost, Home Assistant)
- Automatic DB migration for existing installs
- Yellow **local** badge on webhook cards where enabled

### v0.2 — May 2026

- AI Explain added to Original, Mosaic, Seal (Chronicles had it since v0.1)
- Google Fonts removed — replaced with system font stack, then bundled in v0.4
- `.jsx` and `.py` static serving blocked (HTTP 403)
- SQLite PRAGMA tuning, missing alert indexes, session indexes
- Security headers, login rate limiting, AI key obfuscation, webhook SSRF protection

### v0.1 — May 2026

- Initial release: AI Explain system (`ai_explain.py`), Chronicles skin AI UI, `GET/PUT /ai-config`, `POST /ai-explain`
- Install-time credential generation and display
- License changed to GNU AGPL v3.0

---

## License

Heimdall IDS is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

This means:
- You can use, modify, and distribute Heimdall freely
- If you run a modified version as a network service, you must make the source code available to users under the same license
- See [LICENSE](LICENSE) for the full text

---

*Heimdall IDS — G-Sentry*
