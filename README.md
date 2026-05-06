# Heimdall IDS

> Real-time Suricata IDS dashboard — alerts, flows, DNS, HTTP, AI-powered triage, and RBAC. Fully self-contained. No cloud. No external dependencies.

![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen)
![Architecture](https://img.shields.io/badge/arch-all-lightgrey)
![Version](https://img.shields.io/badge/version-0.4.1-orange)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [First Run](#first-run)
- [Configuration](#configuration)
- [User Roles (RBAC)](#user-roles-rbac)
- [AI Alert Explanation](#ai-alert-explanation)
- [Webhooks](#webhooks)
- [Threat Intelligence](#threat-intelligence)
- [Suppression Rules](#suppression-rules)
- [Skins](#skins)
- [API Reference](#api-reference)
- [Architecture](#architecture)
- [Security](#security)
- [Building from Source](#building-from-source)
- [Changelog](#changelog)
- [License](#license)

---

## Overview

Heimdall IDS is a lightweight, self-hosted web dashboard for [Suricata](https://suricata.io/). It tails your `eve.json` log file in real time and presents alerts, flows, DNS queries, and HTTP events through a clean, responsive interface — with zero runtime dependencies beyond Python 3.10.

It is designed to be installed on the same machine as Suricata and accessed from your browser. Everything — the database, the session store, the user accounts, the webhooks — lives in SQLite on disk. No Redis, no Postgres, no message broker.

```
Suricata → eve.json → Heimdall (tail thread) → SQLite → SSE → Browser
```

---

## Features

### Core Dashboard
- **Live alert stream** via Server-Sent Events (SSE) — no polling, no page refresh
- **Alerts view** — severity badges, signature details, src/dst IP, triage workflow (acknowledge / investigating / closed)
- **Flows view** — TCP/UDP/ICMP session summary with bytes, packets, duration
- **DNS view** — query/response pairs, rrtype breakdown, top queried domains
- **HTTP view** — method, URL, status, user-agent, referrer, content-type
- **Charts view** — alert timeline, top signatures, top source IPs, severity distribution
- **Bulk operations** — bulk status update and bulk delete across filtered alert sets
- **Retention policy** — configurable alert retention (default: 90 days), automatic purge

### Security
- **Session-based authentication** — PBKDF2-SHA256 (260,000 iterations) password hashing
- **Login rate limiting** — per-IP lockout after 10 failures in 5 minutes
- **Role-based access control** — three tiers: admin, analyst, viewer
- **systemd hardening** — `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, restricted address families
- **No external network calls** — unless you configure AI explanation or webhooks

### AI-Powered Triage
- **Per-alert AI explanation** — executive summary generated on demand
- **Multi-provider support** — OpenAI, Anthropic (Claude), DeepSeek
- **Response caching** — identical alerts return cached explanations instantly
- **API key obfuscation** — keys are XOR+base64 obfuscated in the database (not plaintext)
- **Zero dependencies** — implemented with `urllib` only, no `requests` or SDKs

### Notifications
- **Webhook engine** — async delivery with retry logic (3 attempts, 5s backoff)
- **Slack & Discord** — native payload formatting
- **Generic JSON** — any HTTP endpoint
- **Severity filters** — per-webhook severity thresholds (critical / high / medium / low / info)
- **SSRF protection** — private/loopback IP targets are blocked

### Customisation
- **4 built-in skins** — Original, Chronicles, Mosaic, Seal
- **Per-user skin preference** — persisted server-side, survives logout
- **Threat Intel annotations** — custom notes per signature ID or alert category
- **Suppression rules** — silence noisy rules by sig_id, src_ip, and/or category with optional expiry

---

## Installation

### Requirements

- Ubuntu 22.04 / Debian 12 (or any systemd distro with Python 3.10+)
- Suricata already installed and writing `eve.json`
- No internet connection required after download (fully airgapped)

### Install from .deb (recommended)

```bash
sudo dpkg -i heimdall-ids_0.4.1_all.deb
```

That's it. The installer will:

1. Create a `heimdall` system user
2. Add it to the `suricata` group (for `eve.json` read access)
3. Initialise the SQLite databases under `/var/lib/heimdall/`
4. Enable and start `heimdall.service`
5. Print your admin credentials to the terminal

> **Note:** If you see a dependency error, run `sudo apt-get install -f` after the dpkg command. The only dependency is `python3 (>= 3.10)`.

### Verify the service is running

```bash
sudo systemctl status heimdall
sudo journalctl -u heimdall -n 30
```

---

## First Run

After installation, your credentials are printed to the terminal and saved at:

```
/etc/heimdall/.credentials
```

```bash
# View credentials at any time
sudo cat /etc/heimdall/.credentials
```

Open your browser at **http://localhost:8765** and log in.

### Change the admin password

```bash
sudo heimdall --password mynewpassword
sudo systemctl restart heimdall
```

---

## Configuration

The service is configured via command-line flags passed in the systemd unit. Edit `/lib/systemd/system/heimdall.service` or use the config file:

```bash
sudo nano /etc/heimdall/heimdall.conf
```

| Flag | Default | Description |
|------|---------|-------------|
| `--eve` | `/var/log/suricata/eve.json` | Path to Suricata eve.json |
| `--port` | `8765` | TCP port to listen on |
| `--host` | `0.0.0.0` | Bind address |
| `--db` | `/var/lib/heimdall/events.db` | Events database (alerts, flows, HTTP) |
| `--dns-db` | `/var/lib/heimdall/dns.db` | DNS events database |
| `--config-db` | `/var/lib/heimdall/config.db` | Config database (auth, users, webhooks) |
| `--retain-days` | `90` | Days to retain events before purging |
| `--password` | — | Set/change admin password, then exit |

After editing the config, apply with:

```bash
sudo systemctl daemon-reload
sudo systemctl restart heimdall
```

### Database layout

Heimdall uses three separate SQLite databases to isolate write workloads:

```
/var/lib/heimdall/
├── events.db    # High-volume writes: alerts, flows, http_events
├── dns.db       # Dedicated DNS event store
└── config.db    # Low-write: auth, sessions, users, webhooks, threat intel
```

---

## User Roles (RBAC)

| Permission | Admin | Analyst | Viewer |
|---|:---:|:---:|:---:|
| View alerts, flows, DNS, HTTP | ✅ | ✅ | ✅ (alerts only) |
| Alert detail panel | ✅ | ✅ | ❌ |
| Triage (ack / investigating / close) | ✅ | ✅ | ❌ |
| Bulk status update / delete | ✅ | ❌ | ❌ |
| AI explanation | ✅ | ✅ | ❌ |
| Webhook management | ✅ | ❌ | ❌ |
| Threat intel management | ✅ | ❌ | ❌ |
| Suppression rules | ✅ | ❌ | ❌ |
| User management | ✅ | ❌ | ❌ |
| Change own password | ✅ | ✅ | ✅ |

Manage users at **Settings → Users** (admin only) or via the CLI.

---

## AI Alert Explanation

Heimdall can generate plain-English explanations of alerts on demand using your choice of AI provider.

### Setup

1. Go to **Settings → AI Configuration** in the dashboard
2. Select your provider: `openai`, `anthropic`, or `deepseek`
3. Enter your API key
4. Click Save — the key is stored obfuscated in `config.db`

### How it works

When you click **Explain** on an alert, Heimdall sends the alert metadata (signature, category, severity, src/dst IP and port) to the configured provider and returns a concise executive summary — what the alert means, why it fired, and what to do next.

Explanations are **cached by alert fingerprint** — the same alert type never makes two API calls.

### Supported providers

| Provider | Model used |
|----------|-----------|
| OpenAI | `gpt-4o-mini` |
| Anthropic | `claude-haiku-*` (latest) |
| DeepSeek | `deepseek-chat` |

> The AI module uses only Python's standard `urllib` — no `openai`, `anthropic`, or `httpx` packages required.

---

## Webhooks

Send alert notifications to Slack, Discord, or any HTTP endpoint.

### Add a webhook

Go to **Settings → Webhooks → Add Webhook**:

| Field | Description |
|-------|-------------|
| Name | Label for this webhook |
| URL | Slack/Discord/generic HTTPS endpoint |
| Type | `slack`, `discord`, or `generic` |
| Severities | Which severity levels trigger this webhook |
| Enabled | Toggle on/off without deleting |

### Delivery

- Delivery is asynchronous — it never blocks alert ingestion
- Failed deliveries are retried up to **3 times** with a **5-second** delay
- Private/loopback IP targets are rejected (SSRF protection)
- Timeout per request: **10 seconds**

---

## Threat Intelligence

Annotate Suricata signatures with your own context — what a rule means for your environment, links to CVEs, remediation steps.

Annotations can be keyed by:
- **Signature ID** (exact match, highest priority)
- **Category** (fallback for entire alert categories)

Manage at **Settings → Threat Intel**. Annotations appear inline on matching alerts.

---

## Suppression Rules

Silence known-false-positive rules without modifying Suricata's config.

Each rule can match on any combination of:
- `sig_id` — exact signature ID
- `src_ip` — exact source IP address
- `category` — alert category (case-insensitive)

Rules can carry an **expiry timestamp** — useful for temporary suppressions during maintenance windows.

Manage at **Settings → Suppression**. Suppression is checked in the tail hot-path with a 30-second in-memory cache — zero database hits per alert after the cache warms.

---

## Skins

Switch themes at any time from the top-right menu. Your choice is saved per user account.

| Skin | Character |
|------|-----------|
| **Original** | Dark terminal aesthetic, green accents |
| **Chronicles** | Ink-dark, editorial, high contrast |
| **Mosaic** | Tiled layout, navy blue |
| **Seal** | Clean, muted, professional |

---

## API Reference

All endpoints require a valid session cookie except `/login`, `/health`, and static assets.

### GET endpoints

| Path | Description |
|------|-------------|
| `GET /alerts` | Paginated alert list with filters |
| `GET /flows` | Flow events |
| `GET /dns` | DNS events |
| `GET /http` | HTTP events |
| `GET /charts` | Aggregated chart data |
| `GET /events` | SSE stream (live alert push) |
| `GET /webhooks` | List webhooks (admin) |
| `GET /users` | List users (admin) |
| `GET /threat-intel` | List threat intel entries |
| `GET /threat-intel/lookup` | Lookup annotation for a specific alert |
| `GET /threat-intel/gaps` | Signatures without annotations |
| `GET /suppression` | List suppression rules |
| `GET /ai-config` | AI provider config (admin) |
| `GET /me` | Current session user info |
| `GET /skin` | Current user's skin preference |
| `GET /health` | `{"status":"ok"}` — no auth required |

### POST endpoints

| Path | Description |
|------|-------------|
| `POST /login` | Authenticate, set session cookie |
| `POST /logout` | Invalidate session |
| `POST /users` | Create/update/delete user (admin) |
| `POST /skin` | Save skin preference |
| `POST /ai-explain` | Generate AI explanation for an alert |
| `POST /webhooks` | Create/update/delete webhook (admin) |
| `POST /alerts/bulk-status` | Update status on multiple alerts |
| `POST /alerts/delete-selected` | Delete up to 500 alerts by ID |

### DELETE endpoints

| Path | Description |
|------|-------------|
| `DELETE /alerts` | Clear all alerts (admin) |
| `DELETE /flows` | Clear all flows (admin) |
| `DELETE /dns` | Clear all DNS events (admin) |

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
│  ThreadedHTTPServer · BaseHTTPRequestHandler         │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ tail     │  │ purge    │  │ delivery_worker   │  │
│  │ thread   │  │ thread   │  │ (webhooks)        │  │
│  └────┬─────┘  └────┬─────┘  └──────────────────┘  │
│       │              │                              │
│  ┌────▼──────────────▼───────────────────────────┐ │
│  │              SQLite (3 databases)              │ │
│  │  events.db · dns.db · config.db               │ │
│  └───────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
         ▲
         │ reads
┌────────┴────────┐
│  eve.json       │
│  (Suricata)     │
└─────────────────┘
```

### Module map

| File | Responsibility |
|------|---------------|
| `server.py` | Entry point, wires all modules, starts HTTP server |
| `handlers.py` | HTTP request routing and response logic |
| `config.py` | Runtime constants and paths |
| `database.py` | AlertDB — alerts, flows, HTTP events |
| `dns_db.py` | DNSDB — DNS event store |
| `config_db.py` | ConfigDB — shared connection factory |
| `auth.py` | AuthManager — password hashing, session CRUD |
| `users.py` | UserManager — RBAC user accounts |
| `tail.py` | eve.json tailer and event ingestor |
| `webhooks.py` | WebhookDB + async delivery engine |
| `threat_intel.py` | ThreatIntelDB — signature annotations |
| `suppression.py` | SuppressionDB — false-positive suppression |
| `ai_explain.py` | AIExplainDB — multi-provider AI summaries |
| `registry.py` | In-process SSE broadcast registry |
| `password_utils.py` | PBKDF2-SHA256 hashing utilities |

---

## Security

### Authentication
- Passwords hashed with **PBKDF2-SHA256**, 260,000 iterations
- Sessions stored in `config.db`, TTL: **7 days**
- Login rate-limited: **10 failures per IP per 5 minutes**

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

### Build

```bash
git clone https://github.com/heimdall-ids/heimdall
cd heimdall
./build-deb.sh 0.4.1
# → packaging/build/heimdall-ids_0.4.1_all.deb
```

The build script:
1. Compiles all 4 skin `.jsx` files to `.js` via esbuild (minified)
2. Assembles the package tree under `packaging/build/`
3. Overrides `config.py` with system paths
4. Builds the `.deb` with `dpkg-deb`

> The pre-compiled `.js` files are included in the source zip, so you can build the `.deb` without `esbuild` if you don't modify the frontend.

---

## Changelog

### v0.4.1 — 2026-05-05
- **Fix:** `NameError: name 'threading' is not defined` in `handlers.py` — `import threading` was missing, causing the service to crash on startup in a restart loop

### v0.4.0 — 2026-05-03
- Initial public release
- Alerts, Flows, DNS, HTTP views with SSE live streaming
- RBAC user management (admin / analyst / viewer)
- AI alert explanation (OpenAI, Anthropic, DeepSeek)
- Webhook engine (Slack, Discord, generic)
- Threat intelligence annotations
- Suppression rules with optional expiry
- 4 UI skins: Original, Chronicles, Mosaic, Seal
- Dual-database layout (events.db + dns.db + config.db)
- systemd service with strict sandboxing

---

## License

**GNU Affero General Public License v3.0 (AGPL-3.0)**

Copyright © 2024–2026 Heimdall IDS Contributors

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

If you run a modified version of this software on a network server, you must make the complete source code available to users interacting with it remotely, under the terms of this License.

See [LICENSE](./LICENSE) for the full text or visit <https://www.gnu.org/licenses/agpl-3.0.txt>.
