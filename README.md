# Heimdall IDS Dashboard

A self-hosted, real-time intrusion detection dashboard for [Suricata](https://suricata.io/).  
Zero npm, zero Docker, zero external runtime dependencies — just Python 3.10+ and a browser.

---

## Features

| Category | Details |
|---|---|
| **Live streaming** | SSE real-time push of alerts, flows, DNS, and HTTP — all four event types update instantly without refresh |
| **Triage workflow** | Per-alert status (acknowledged / investigating / closed) + analyst notes |
| **Bulk operations** | Multi-select alerts, bulk status update, bulk delete |
| **RBAC** | Three roles: Admin · Analyst · Viewer with per-route enforcement |
| **Webhooks** | Slack, Discord, or generic JSON — per-severity filters, retry logic |
| **Charts** | Severity distribution, alert timeline (24 h → 90 d windows) |
| **Skins** | Four built-in UI skins switchable live, persisted per user, no restart required |
| **Themes** | Six colour themes per skin (Night, Light, Midnight Blue, Solarized, Dracula, Nord) |
| **DNS detail modal** | Click any DNS row to view the full raw record — works identically across all skins |
| **Triple SQLite** | Events DB · DNS DB · Config DB — each isolated to its own WAL lock |
| **Data retention** | Configurable (default 90 days), automatic purge of all three databases |

---

## Requirements

- Python **3.10** or newer
- Suricata writing `eve.json` (any version supporting `event_type`)
- Linux — Debian/Ubuntu amd64 for the `.deb` installer

No pip packages. No Node.js. No external services.

---

## Installation

### Option A — Debian package (recommended)

```bash
sudo apt install ./heimdall-ids_5.0.0_amd64.deb
sudo systemctl enable --now heimdall
```

On first start, admin credentials are printed to the journal:

```bash
sudo journalctl -u heimdall -n 30
```

Then open **http://\<host\>:8765**

### Option B — Run directly from source

```bash
git clone https://github.com/yourname/heimdall-ids
cd heimdall-ids

# Build the frontend (one-time, requires esbuild)
./build.sh

# Start
python3 server.py
```

---

## First Run

Heimdall generates a random admin password on first start and prints it to the terminal / journal:

```
══════════════════════════════════════════════════════════
  No password set — generated a random one:
  USERNAME: admin
  PASSWORD: aB3xK9mRpQ2nW7s
  Change:   python3 server.py --password <new>
══════════════════════════════════════════════════════════
```

Change your password after signing in via **Settings → Users → Edit**.

---

## Configuration

All settings are CLI flags. Override them for the systemd service with a drop-in:

```bash
sudo systemctl edit heimdall
```

### Available flags

| Flag | Default | Description |
|---|---|---|
| `--eve` | `/var/log/suricata/eve.json` | Path to Suricata eve.json |
| `--port` | `8765` | HTTP listen port |
| `--host` | `0.0.0.0` | Bind address |
| `--db` | `/var/lib/heimdall/events.db` | Alerts + flows + HTTP database |
| `--dns-db` | `/var/lib/heimdall/dns.db` | DNS-only database |
| `--config-db` | `/var/lib/heimdall/config.db` | Auth, sessions, users, webhooks |
| `--retain-days` | `90` | Days to keep events in all three databases |
| `--password` | — | Set/change the admin password, then exit |

### Change password

```bash
# Stop service, reset, restart
sudo systemctl stop heimdall
sudo heimdall --password mynewpassword
sudo systemctl start heimdall

# Or via UI: Settings → Users → Edit
```

---

## Roles

| Role | Alerts | Flows / DNS / HTTP | Charts | Triage | Webhooks | Users |
|---|---|---|---|---|---|---|
| **Admin** | ✓ full | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Analyst** | ✓ full | ✓ | ✓ | ✓ | — | — |
| **Viewer** | read-only | — | — | — | — | — |

---

## Skins

Switch skins using the **floating button** (bottom-right corner). Choice persists per user account, no restart needed.

| Skin | Style | Font |
|---|---|---|
| **Original** | Warm charcoal · multi-theme | Space Grotesk |
| **Chronicles** | Obsidian violet · multi-theme | Inter |
| **Mosaic** | Glass indigo · multi-theme | Inter |
| **Seal** | Navy steel · multi-theme | Space Mono |

Each skin supports six colour themes selectable from the top-bar picker.

---

## Webhooks

Configured in **Settings → Webhooks**. Supported targets:

| Target | Format |
|---|---|
| **Slack** | Block Kit with severity emoji + field grid |
| **Discord** | Embed with colour-coded severity |
| **Generic** | Plain JSON — compatible with Teams, Mattermost, n8n, Zapier |

Each webhook filters by severity (critical / high / medium / low / info). Failed deliveries retry up to 3 times.

---

## Database Layout

Three SQLite databases, each with its own WAL lock:

```
events.db    — alerts, flows, http_events, alert_meta, alert_notes
dns.db       — dns_events  (high-frequency, isolated from alert writes)
config.db    — auth, sessions, users, webhooks
```

Default paths when installed via `.deb`:

```
/var/lib/heimdall/events.db
/var/lib/heimdall/dns.db
/var/lib/heimdall/config.db
```

---

## Security

- `HttpOnly; SameSite=Strict` session cookies, 7-day TTL
- PBKDF2-SHA256 password hashing (260,000 iterations)
- Service runs as a dedicated `heimdall` system user (created by `postinst`)
- systemd hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, restricted address families
- `/var/lib/heimdall/` and `/var/log/heimdall/` are mode `750` — no world access to database files
- `heimdall` user is added to the `adm` (and `suricata` if present) group to read eve.json without root

---

## File & Permission Reference

| Path | Mode | Purpose |
|---|---|---|
| `/usr/lib/heimdall/*.py` | `644 root:root` | Python backend |
| `/usr/lib/heimdall/frontend/` | `644 root:root` | Static frontend assets |
| `/usr/bin/heimdall` | `755 root:root` | CLI wrapper |
| `/lib/systemd/system/heimdall.service` | `644 root:root` | Service unit |
| `/var/lib/heimdall/` | `750 heimdall:heimdall` | SQLite databases |
| `/var/log/heimdall/` | `750 heimdall:heimdall` | Log output |

---

## Uninstall

```bash
# Remove package, keep data
sudo dpkg -r heimdall-ids

# Remove package + all databases + heimdall user
sudo dpkg --purge heimdall-ids
```

---

## Building from Source

### Prerequisites

```bash
npm install -g esbuild   # or download the esbuild binary directly
```

### Build

```bash
./build.sh   # compiles all four skin app.jsx → app.js
```

### Package

```bash
# After build.sh, the compiled app.js files live in frontend/skins/*/app.js
# Vendor React once:
mkdir -p frontend
npm pack react@18 react-dom@18
tar xzf react-18*.tgz     package/umd/react.production.min.js
tar xzf react-dom-18*.tgz package/umd/react-dom.production.min.js
mv package/umd/react.production.min.js     frontend/react.min.js
mv package/umd/react-dom.production.min.js frontend/react-dom.min.js

# Build the .deb
dpkg-deb --build --root-owner-group <package_dir> heimdall-ids_5.0.0_amd64.deb
```

---

## Project Structure

```
server.py           Entry point — wires all modules, starts HTTP server
handlers.py         HTTP router + all API endpoints + RBAC enforcement
auth.py             Session management, single-password fallback
users.py            RBAC user management (admin / analyst / viewer)
database.py         AlertDB — alerts, flows, HTTP events
dns_db.py           DNSDB — dedicated DNS event store (separate WAL lock)
config_db.py        ConfigDB — auth / sessions / webhooks connection pool
tail.py             eve.json tail thread, deduplication, SSE fan-out
registry.py         SSE client registry — thread-safe broadcast queue
webhooks.py         Webhook storage, Slack/Discord/generic formatters, delivery worker
password_utils.py   PBKDF2-SHA256 hash + verify (shared)
config.py           Runtime constants and defaults

frontend/
  index.html                  Minimal shell — delegates to skin-loader
  skin-loader.js              Dynamic CSS + JS injection, floating skin switcher
  login.html / login.js       Login page
  react.min.js                React 18 (vendored — no CDN)
  react-dom.min.js            ReactDOM 18 (vendored — no CDN)
  skins/
    original/   app.jsx + styles.css   Warm charcoal, Space Grotesk
    chronicles/ app.jsx + styles.css   Obsidian violet, Inter
    mosaic/     app.jsx + styles.css   Glass indigo, Inter
    seal/       app.jsx + styles.css   Navy steel, Space Mono

build.sh            Compiles all skin JSX → JS via esbuild
.gitignore          Excludes *.db, compiled app.js, vendored React
```

---

## License

MIT
