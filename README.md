# 🛡️ Heimdall IDS Dashboard

A lightweight, zero-dependency web dashboard for [Suricata](https://suricata.io/) IDS. Heimdall tails your `eve.json` log in real time, stores every event in a local SQLite database, and streams live alerts to any number of browser clients over Server-Sent Events (SSE).

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Zero dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-orange)

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [First Run](#first-run)
- [Configuration](#configuration)
- [RBAC — Roles & Permissions](#rbac--roles--permissions)
- [Alert Triage](#alert-triage)
- [Webhooks](#webhooks)
- [API Reference](#api-reference)
- [Themes](#themes)
- [Security Notes](#security-notes)
- [License](#license)

---

## Features

- **Real-time streaming** — live alert feed pushed to every connected browser via SSE; no polling required.
- **Multi-event support** — ingests and stores Suricata `alert`, `flow`, `dns`, and `http` event types.
- **RBAC** — three built-in roles (`admin`, `analyst`, `viewer`) enforced on every API endpoint and UI control.
- **Alert triage** — per-alert status workflow (`acknowledged → investigating → closed`) with timestamped analyst notes and a full audit trail.
- **Bulk actions** — select and triage multiple alerts at once.
- **Charts view** — alert trend (hourly / daily), top talkers, by-category and by-severity breakdowns.
- **Webhooks** — deliver alert notifications to Slack, Discord, or any generic JSON endpoint, with per-webhook severity filters and automatic retries.
- **Six UI themes** — Night, Light, Midnight Blue, Solarized Dark, Dracula, Nord; persisted to `localStorage`.
- **Sliding-window deduplication** — prevents duplicate alert processing on log rotation or restart.
- **Automatic data retention** — configurable purge cycle keeps the SQLite database lean.
- **Zero npm / zero pip** — the entire stack is Python 3 stdlib + React 18 loaded from a CDN. No build step.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    server.py                        │
│  wires all modules; starts HTTP server + threads    │
└────────┬────────────┬──────────────┬────────────────┘
         │            │              │
    tail_thread   purge_thread  delivery_worker
    (tail.py)    (tail.py)      (webhooks.py)
         │
    eve.json  ──► AlertDB (database.py)
                      │
                  Registry (registry.py)  ──► SSE clients
                      │
                  WebhookDB (webhooks.py) ──► HTTP POST
```

All browser requests are handled by `Handler` (handlers.py), a subclass of `BaseHTTPRequestHandler` running in a `ThreadingMixIn` HTTP server — one thread per connection, allowing SSE streams to stay open indefinitely without blocking other requests.

---

## Project Structure

```
heimdall/
├── server.py        — Entry point; wires modules, starts HTTP server & background threads
├── config.py        — All runtime constants (port, paths, TTLs, etc.)
├── auth.py          — Session management, PBKDF2-SHA256 password hashing
├── users.py         — RBAC user management (CRUD, authentication, bootstrap)
├── database.py      — Thread-safe SQLite wrapper; all queries for all event types
├── handlers.py      — HTTP request handler; routing, auth checks, all API endpoints
├── registry.py      — Thread-safe SSE client registry; fan-out broadcast
├── tail.py          — eve.json tail loop, event parsing, deduplication
├── webhooks.py      — Webhook storage, payload formatting, async delivery queue
└── frontend/
    ├── index.html   — Dashboard shell; loads React 18 from CDN
    ├── app.jsx      — Full React SPA (Babel standalone; no build step)
    ├── styles.css   — All component styles; theme-variable driven
    ├── login.html   — Standalone login page
    └── login.js     — Login form logic
```

---

## Requirements

- Python 3.10 or later
- Suricata configured to write `eve.json` (any version that produces the EVE JSON format)
- A modern web browser

No third-party Python packages are required. The frontend uses React 18 and Babel Standalone loaded from `unpkg.com`, so an internet connection is needed on first load (or you can self-host those scripts).

---

## Installation

```bash
git clone https://github.com/your-org/heimdall.git
cd heimdall
```

That's it. There is nothing to install or compile.

---

## First Run

```bash
python3 server.py
```

On the very first run, if no password has been set, Heimdall auto-generates a strong random password and prints it to the console:

```
========================================================
  No password set — generated a random one:
  PASSWORD: xK9mQr2pLwTvNy4
  Change:   python3 server.py --password <new>
========================================================
========================================================
  RBAC enabled — first Admin account created:
  Username: admin
  Password: <generated>
  Change:   Settings → Users → Edit
========================================================
```

Then open your browser:

| URL | Purpose |
|-----|---------|
| `http://localhost:8765/login` | Sign-in page |
| `http://localhost:8765/` | Live dashboard |
| `http://localhost:8765/health` | Health check (JSON) |

To set or change the password at any time:

```bash
python3 server.py --password mysecretpassword
```

This updates the stored hash and exits. Restart the server normally afterwards.

---

## Configuration

All defaults live in `config.py` and can be overridden via CLI flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--eve` | `/var/log/suricata/eve.json` | Path to Suricata's EVE JSON log |
| `--port` | `8765` | TCP port to listen on |
| `--host` | `0.0.0.0` | Bind address |
| `--db` | `./alerts.db` | Path to the SQLite database file |
| `--retain-days` | `90` | Days of events to keep before purging |
| `--password` | *(none)* | Set/change the dashboard password, then exit |

**Example — custom eve path and port:**

```bash
python3 server.py --eve /data/suricata/eve.json --port 9000
```

**Constants in `config.py`** (edit the file directly to change them):

| Constant | Default | Description |
|----------|---------|-------------|
| `SESSION_TTL` | 7 days | Session cookie lifetime |
| `PBKDF2_ITERS` | 260,000 | PBKDF2-SHA256 iteration count |
| `PURGE_EVERY` | 3600 s | Seconds between database purge cycles |
| `PING_EVERY` | 10 s | SSE keep-alive ping interval |
| `MAX_QUEUE` | 500 | Max SSE messages queued per client before drop |

---

## RBAC — Roles & Permissions

Heimdall ships with three fixed roles assigned per user account:

| Permission | `admin` | `analyst` | `viewer` |
|-----------|:-------:|:---------:|:--------:|
| View alerts, flows, DNS, charts | ✅ | ✅ | ✅ (alerts only) |
| Alert detail panel + notes | ✅ | ✅ | ❌ |
| Triage alerts (set status) | ✅ | ✅ | ❌ |
| Bulk status actions | ✅ | ✅ | ❌ |
| Clear / delete data | ✅ | ❌ | ❌ |
| Manage webhooks | ✅ | ❌ | ❌ |
| Manage users | ✅ | ❌ | ❌ |

Roles are enforced server-side on every request — the UI controls are cosmetic reinforcement only.

### Managing users

Users can be created, edited, enabled/disabled, and deleted from **Settings → Users** (admin only). At least one active admin account must exist at all times; Heimdall will refuse operations that would remove the last admin.

---

## Alert Triage

Each alert supports a three-stage triage workflow:

| Status | Meaning |
|--------|---------|
| `acknowledged` | Alert has been seen and noted |
| `investigating` | Actively being investigated |
| `closed` | Investigation complete, no further action needed |

Status changes and analyst notes are recorded in a full audit log (`alert_activity` table) attached to each alert. Notes and the activity log are visible to any user with at least the `analyst` role.

**Bulk triage** lets you select multiple alerts from the feed and apply a status to all of them at once.

---

## Webhooks

Webhooks deliver alert payloads via HTTP POST whenever a new alert whose severity matches the webhook's filter arrives. Supported targets:

| Type | Payload format |
|------|---------------|
| `slack` | Slack Block Kit |
| `discord` | Discord Embeds |
| `generic` | Plain JSON (Teams, Mattermost, n8n, etc.) |

Each webhook can be scoped to one or more severity levels (`critical`, `high`, `medium`, `low`, `info`). Delivery is asynchronous (background thread + queue) so it never blocks the live alert stream. Failed deliveries are retried up to 3 times with a 5-second back-off.

A **Test** button in the Settings panel sends a synthetic medium-severity alert to verify your webhook URL before going live.

---

## API Reference

All endpoints require an authenticated session cookie (`suri_session`) except `/login` and `/frontend/login.js`.

### Auth

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/login` | Authenticate; sets `suri_session` cookie |
| `GET` | `/logout` | Revoke session and redirect to `/login` |

### Alerts

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/alerts` | Fetch recent alerts (`?days=N&limit=N`) |
| `GET` | `/alerts/<id>/meta` | Get triage status, notes, and activity log for one alert |
| `POST` | `/alerts/<id>/status` | Set triage status (`acknowledged`/`investigating`/`closed`/`null`) |
| `POST` | `/alerts/<id>/notes` | Add an analyst note |
| `POST` | `/alerts/bulk-status` | Bulk-set status on multiple alerts |
| `DELETE` | `/alerts` | Clear all alerts *(admin only)* |

### Event tables

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/flows` | Fetch flow events (`?days=N&limit=N`) |
| `GET` | `/dns` | Fetch DNS events (`?days=N&limit=N`) |
| `GET` | `/http` | Fetch HTTP events (`?days=N&limit=N`) |
| `DELETE` | `/flows` | Clear all flows *(admin only)* |
| `DELETE` | `/dns` | Clear all DNS events *(admin only)* |

### Charts & health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/charts` | Chart data: trend, top talkers, by-category, by-severity (`?trend=24`) |
| `GET` | `/health` | Server health, connected client count, DB stats |

### Webhooks

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/webhooks` | List all webhooks |
| `POST` | `/webhooks` | Create a webhook |
| `PUT` | `/webhooks/<id>` | Update a webhook |
| `DELETE` | `/webhooks/<id>` | Delete a webhook |
| `POST` | `/webhooks/<id>/test` | Send a test alert to a webhook |

### Users

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/users` | List all users *(admin only)* |
| `GET` | `/me` | Current session's username and role |
| `POST` | `/users` | Create a user *(admin only)* |
| `PUT` | `/users/<id>` | Update a user *(admin only)* |
| `DELETE` | `/users/<id>` | Delete a user *(admin only)* |

### SSE stream

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/events` | Server-Sent Events stream (`alert`, `flow`, `dns`, `http`, `ping` events) |

---

## Themes

Six themes are available and can be switched from the topbar dropdown. The selection is persisted to `localStorage`:

| Theme | Description |
|-------|-------------|
| Night | Warm charcoal (default) |
| Light | Off-white / parchment |
| Midnight Blue | Deep GitHub-inspired blue |
| Solarized Dark | Classic Solarized palette |
| Dracula | Purple-tinted dark theme |
| Nord | Arctic, blue-grey tones |

All colours are driven by CSS custom properties (variables), making it straightforward to add new themes by defining a new `html[data-theme="..."]` block in `styles.css` and adding an entry to the `THEMES` array in `app.jsx`.

---

## Security Notes

- **Passwords** are hashed with PBKDF2-SHA256 at 260,000 iterations using a per-password random salt. Timing-safe comparison (`hmac.compare_digest`) is used on verification.
- **Sessions** are 256-bit random hex tokens stored in an `HttpOnly; SameSite=Strict` cookie with a 7-day TTL.
- **RBAC** is enforced server-side; the role embedded in the session token is validated on every protected request.
- **TLS** is not handled by Heimdall directly. For production use, place it behind a reverse proxy (nginx, Caddy) that terminates HTTPS.
- The dashboard binds to `0.0.0.0` by default — restrict this to `127.0.0.1` if you're running it behind a local proxy:
  ```bash
  python3 server.py --host 127.0.0.1
  ```

---

## License

Copyright (C) 2026 — Present, Heimdall Contributors.

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU Affero General Public License** as published by the Free Software Foundation.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [GNU Affero General Public License](https://www.gnu.org/licenses/agpl-3.0.html) for more details.

> Under the AGPL-3.0, if you run a modified version of Heimdall over a network (e.g. as a hosted service), you must make the complete corresponding source code available to users of that service.


<div align="center">
<sub>Built for blue team ops. No cloud. No telemetry. Your data stays on your network.</sub>
</div>
