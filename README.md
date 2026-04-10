<div align="center">

<br/>

```
  ██╗  ██╗███████╗██╗███╗   ███╗██████╗  █████╗ ██╗     ██╗     
 ██║  ██║██╔════╝██║████╗ ████║██╔══██╗██╔══██╗██║     ██║     
 ███████║█████╗  ██║██╔████╔██║██║  ██║███████║██║     ██║     
 ██╔══██║██╔══╝  ██║██║╚██╔╝██║██║  ██║██╔══██║██║     ██║     
 ██║  ██║███████╗██║██║ ╚═╝ ██║██████╔╝██║  ██║███████╗███████╗
 ╚═╝  ╚═╝╚══════╝╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
 ╚═╝      ╚═╝╚══════╝╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
```

**Real-time Suricata IDS dashboard. Zero dependencies. Pure Python.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![No Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen?style=flat-square)](requirements.txt)
[![Suricata](https://img.shields.io/badge/Suricata-7.x-orange?style=flat-square)](https://suricata.io)

</div>

---

## Overview

Heimdall is a self-hosted, real-time network intrusion detection dashboard that sits on top of [Suricata IDS](https://suricata.io). It tails `eve.json`, persists events in SQLite, and streams them live to the browser over SSE — with zero external pip dependencies.

**No Node.js. No npm. No Docker. No pip install. Just Python 3.10+.**

<br/>

### What it looks like

| View | Description |
|---|---|
| **Alerts** | Live alert stream with severity filtering, search, sparkline, and detail panel |
| **Flow Events** | Network flow table with traffic stats and connection details |
| **DNS Queries** | DNS query/response log with answer inspection |
| **Webhooks** | Push notification configuration for Slack, Discord, or any JSON endpoint |

**7 themes** — Night · Light · Midnight Blue · Solarized Dark · Dracula · Nord · Terminal

---

## Features

- **Real-time streaming** via Server-Sent Events — 100ms poll of `eve.json`, no page refresh needed
- **Persistent storage** — SQLite with WAL mode, 90-day retention, hourly purge
- **Authentication** — PBKDF2-SHA256 (260k rounds), session tokens, HttpOnly cookies
- **4 event views** — Alerts, Flow Events, DNS Queries, Webhooks settings
- **Webhook notifications** — Slack Block Kit, Discord Embeds, Generic JSON; retry up to 3× with 5s delay
- **Severity filtering** — Critical / High / Medium / Low / Info per-alert in the sidebar
- **7 themes** — persisted to `localStorage`, instant switch
- **Health endpoint** — `/health` returns JSON with DB stats and client count
- **Zero dependencies** — `http.server`, `sqlite3`, `hashlib`, `threading` — all stdlib

---

## Requirements

| Requirement | Version |
|---|---|
| Python | 3.10 or later |
| Suricata | Any version writing `eve.json` |
| OS | Linux (Ubuntu 22.04+ / Debian 12+ recommended) |
| Browser | Any modern browser (Chrome, Firefox, Edge) |

No pip packages required. No virtual environment needed.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/heimdall.git
cd heimdall
```

### 2. Set your password

```bash
python3 server.py --password YourSecurePassword
```

This hashes the password with PBKDF2-SHA256 and stores it in `alerts.db`. Run this once — the server exits immediately after saving.

### 3. Start the server

```bash
python3 server.py \
  --eve  /var/log/suricata/eve.json \
  --host 0.0.0.0 \
  --port 8765
```

### 4. Open the dashboard

```
http://<your-server-ip>:8765/login
```

---

## Project Structure

```
heimdall/
├── server.py          # Entry point — CLI args, wiring, startup
├── config.py          # All constants (port, retention, paths)
├── auth.py            # AuthManager — PBKDF2 passwords + session tokens
├── database.py        # AlertDB — SQLite for alerts, flows, DNS, HTTP
├── registry.py        # SSE client registry — thread-safe fan-out
├── tail.py            # eve.json tail thread — parses all event types
├── handlers.py        # HTTP request handler — all routes
├── webhooks.py        # Webhook engine — storage, formatters, delivery
└── frontend/
    ├── index.html     # Dashboard shell — loads assets, theme CSS vars
    ├── app.jsx        # Full React app — compiled by Babel in browser
    ├── styles.css     # All component CSS
    ├── login.html     # Login page
    └── login.js       # Login page logic
```

---

## Configuration

All defaults live in `config.py`. Override any of them via CLI flags:

| Flag | Default | Description |
|---|---|---|
| `--eve` | `/var/log/suricata/eve.json` | Path to Suricata eve.json |
| `--host` | `0.0.0.0` | Bind address |
| `--port` | `8765` | TCP port |
| `--db` | `./alerts.db` | SQLite database path |
| `--retain-days` | `90` | Days to keep events |
| `--password` | *(set manually)* | Set/change password, then exit |

```bash
# Examples
python3 server.py --port 9000
python3 server.py --db /var/lib/heimdall/alerts.db --retain-days 30
python3 server.py --password NewPassword   # change password, server exits
```

---

## API Reference

All endpoints except `/login` and `/frontend/login.js` require a valid session cookie.

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Dashboard |
| `GET` | `/login` | Login page |
| `POST` | `/login` | Authenticate — body: `{"password": "..."}` |
| `GET` | `/logout` | Revoke session, redirect to `/login` |
| `GET` | `/events` | SSE stream (named events: `alert`, `flow`, `dns`, `ping`) |
| `GET` | `/alerts` | Alert history — params: `limit`, `days` |
| `GET` | `/flows` | Flow event history |
| `GET` | `/dns` | DNS event history |
| `DELETE` | `/alerts` | Wipe all alerts |
| `DELETE` | `/flows` | Wipe all flows |
| `GET` | `/webhooks` | List webhooks |
| `POST` | `/webhooks` | Create webhook |
| `PUT` | `/webhooks/<id>` | Update webhook |
| `DELETE` | `/webhooks/<id>` | Delete webhook |
| `POST` | `/webhooks/<id>/test` | Fire test payload |
| `GET` | `/health` | Server status + DB stats |

### Health response example

```json
{
  "status": "ok",
  "clients": 2,
  "db": {
    "alerts": { "total": 4821, "recent": 312 },
    "flows":  { "total": 18043, "recent": 1204 },
    "dns":    { "total": 9301, "recent": 601 },
    "http":   { "total": 2100, "recent": 88 },
    "oldest": "2026-01-12T08:14:32+0000"
  },
  "time": 1744300000
}
```

---

## Webhook Notifications

Go to the **Webhooks** tab in the sidebar to configure push notifications.

| Platform | Payload format |
|---|---|
| **Slack** | Block Kit cards with severity, source, destination, SID |
| **Discord** | Rich embeds with colour-coded severity |
| **Generic** | Flat JSON — works with Teams, Mattermost, n8n, or any webhook receiver |

Configure which **severity levels** trigger each webhook independently (Critical, High, Medium, Low, Info).

Failed deliveries are **retried up to 3 times** with a 5-second delay. The last error is shown on the webhook card.

---

## Suricata Suppression

Heimdall's HTTP server banner can trigger Suricata SID `2034635`. Suppress it:

```bash
echo "suppress gen_id 1, sig_id 2034635, track by_src, ip <your-server-ip>" \
  | sudo tee -a /etc/suricata/threshold.conf

sudo suricatasc -c reload-rules
```

---

## Systemd Service (Auto-start)

### 1. Create a dedicated system user

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin heimdall
```

### 2. Copy the project to a permanent location

```bash
sudo cp -r heimdall/ /opt/heimdall
sudo chown -R heimdall:heimdall /opt/heimdall
sudo chmod -R 750 /opt/heimdall
```

### 3. Set the password (as root)

```bash
sudo -u heimdall python3 /opt/heimdall/server.py --password YourSecurePassword
```

### 4. Create the systemd unit file

```bash
sudo nano /etc/systemd/system/heimdall.service
```

Paste the following — adjust `--eve`, `--host`, and `--port` as needed:

```ini
[Unit]
Description=Heimdall IDS Dashboard
Documentation=https://github.com/yourusername/heimdall
After=network.target suricata.service
Wants=suricata.service

[Service]
Type=simple
User=heimdall
Group=heimdall
WorkingDirectory=/opt/heimdall

ExecStart=/usr/bin/python3 /opt/heimdall/server.py \
    --eve  /var/log/suricata/eve.json \
    --host 0.0.0.0 \
    --port 8765 \
    --db   /opt/heimdall/alerts.db \
    --retain-days 90

# Restart policy
Restart=on-failure
RestartSec=5s
StartLimitIntervalSec=60s
StartLimitBurst=3

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=heimdall

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/heimdall
ReadOnlyPaths=/var/log/suricata
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

### 5. Enable and start

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable on boot
sudo systemctl enable heimdall

# Start now
sudo systemctl start heimdall

# Check status
sudo systemctl status heimdall
```

### 6. View logs

```bash
# Follow live logs
sudo journalctl -u heimdall -f

# Last 100 lines
sudo journalctl -u heimdall -n 100

# Since last boot
sudo journalctl -u heimdall -b
```

### 7. Managing the service

```bash
sudo systemctl stop    heimdall   # stop
sudo systemctl restart heimdall   # restart
sudo systemctl disable heimdall   # remove from boot
```

### Changing the password while the service is running

```bash
# Stop the service, update password, restart
sudo systemctl stop heimdall
sudo -u heimdall python3 /opt/heimdall/server.py --password NewPassword
sudo systemctl start heimdall
```

---

## Suricata eve.json Permissions

The `heimdall` user needs read access to `eve.json`. The easiest way:

```bash
# Add heimdall to the suricata group
sudo usermod -aG suricata heimdall

# Ensure suricata log directory is group-readable
sudo chmod 750 /var/log/suricata
sudo chmod 640 /var/log/suricata/eve.json
```

Or use a read-only bind mount / ACL if your setup requires stricter isolation:

```bash
sudo setfacl -m u:heimdall:r /var/log/suricata/eve.json
sudo setfacl -m u:heimdall:rx /var/log/suricata
```

---

## Firewall

If you're running UFW:

```bash
sudo ufw allow from <your-ip-or-subnet> to any port 8765
```

Heimdall has no TLS built in. For internet-facing deployments, put it behind an nginx reverse proxy with a certificate:

```nginx
server {
    listen 443 ssl;
    server_name heimdall.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/heimdall.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/heimdall.yourdomain.com/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header   Connection "";

        # Required for SSE (disable buffering)
        proxy_buffering    off;
        proxy_cache        off;
        proxy_read_timeout 3600s;
    }
}
```

---

## Upgrading

```bash
# Pull latest
git -C /opt/heimdall pull

# Fix ownership
sudo chown -R heimdall:heimdall /opt/heimdall

# Restart
sudo systemctl restart heimdall
```

The SQLite database is preserved between upgrades. New tables are created automatically on first run if the schema changes.

---

## Troubleshooting

**Blank page after login**
```bash
sudo journalctl -u heimdall -n 50
# Check for Python errors in the output
```

**`eve.json` not found**
```bash
# Verify path
ls -la /var/log/suricata/eve.json

# Check permissions
sudo -u heimdall cat /var/log/suricata/eve.json | head -1
```

**Port already in use**
```bash
sudo ss -tlnp | grep 8765
# Use a different port: --port 9000
```

**Suricata keeps alerting on the dashboard server itself**
```bash
# Add suppression for SID 2034635 (see Suricata Suppression section above)
sudo grep 2034635 /etc/suricata/threshold.conf
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+ stdlib (`http.server`, `socketserver`, `sqlite3`, `hashlib`, `threading`) |
| Database | SQLite (WAL mode, embedded) |
| Frontend | React 18 via unpkg CDN + Babel standalone |
| Streaming | Server-Sent Events (SSE) |
| Auth | PBKDF2-SHA256, session cookies |
| IDS | Suricata — `eve.json` format |

---

## License

GNU General Public License v2.0 — see [LICENSE](LICENSE) for details.

---

<div align="center">
<sub>Built for blue team ops. No cloud. No telemetry. Your data stays on your network.</sub>
</div>
