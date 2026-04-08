# Suricata Live Dashboard - Heimdall

A real-time Suricata IDS alert dashboard with persistent storage, session authentication, and zero external dependencies.

```
suricata-live/
├── server.py               ← Python backend (SSE + SQLite + auth)
├── heimdall-dashboard.html ← React dashboard (served by the backend)
├── alerts.db               ← SQLite database (auto-created on first run)
└── README.md
```

> **No pip install required.** Everything uses Python's standard library only.

---

## How it works

```
/var/log/suricata/eve.json
        │
        │  tail -F  (background thread, 100ms poll)
        ▼
   server.py  (stdlib http.server, threaded)
        │
        ├── POST /login     ← verifies password, sets session cookie
        ├── GET  /alerts    ← returns stored alerts from SQLite (JSON)
        ├── GET  /events    ← Server-Sent Events stream (live alerts)
        └── DELETE /alerts  ← wipes the database
        │
        ▼
  suricata-dashboard.html  (React, runs in browser)
```

The backend tails `eve.json` in a background thread. Each new `alert` event is written to SQLite and immediately pushed to all connected browsers over SSE. On page load the dashboard fetches the last 90 days of history from `/alerts` first, then the live stream layers new alerts on top as they arrive.

---

## Quick start

### 1 — Copy files to your server

```bash
mkdir -p /opt/suricata-live
cp server.py heimdall-dashboard.html /opt/suricata-live/
cd /opt/suricata-live
```

### 2 — Set your password

```bash
python3 server.py --password YourChosenPassword
```

If you skip this step, a random password is auto-generated and printed to the console on first boot.

### 3 — Start the server

```bash
python3 server.py --eve /var/log/suricata/eve.json --host 0.0.0.0 --port 8765
```

### 4 — Open the dashboard

```
http://<your-server-ip>:8765/
```

You will be redirected to the login page. After signing in, the session lasts 7 days. Use the **Sign Out** button in the top-right to end it early.

---

## Command-line options

| Flag            | Default                      | Description                          |
|-----------------|------------------------------|--------------------------------------|
| `--eve`         | `/var/log/suricata/eve.json` | Path to Suricata EVE JSON log        |
| `--port`        | `8765`                       | TCP port to listen on                |
| `--host`        | `0.0.0.0`                    | Bind address                         |
| `--db`          | `./alerts.db`                | Path to SQLite database file         |
| `--retain-days` | `90`                         | Days to keep alerts in the database  |
| `--password`    | *(not set)*                  | Set or change the dashboard password |

### Changing your password

```bash
# Stop the server, then:
python3 server.py --password NewPassword
# Start the server again normally
python3 server.py --eve /var/log/suricata/eve.json --host 0.0.0.0 --port 8765
```

---

## Authentication

Access to the dashboard is protected by a password. The implementation uses only Python stdlib — no third-party auth libraries.

- **Password storage** — hashed with PBKDF2-SHA256 (260,000 rounds) and a random salt. Never stored in plain text.
- **Sessions** — a random 64-character hex token is issued on login, stored in the database, and sent as an `HttpOnly; SameSite=Strict` cookie. JavaScript on the page cannot read it.
- **Session lifetime** — 7 days. Expired sessions are purged automatically every hour.
- **Brute-force protection** — failed login attempts are delayed by 1 second server-side.
- **Sign out** — the Sign Out button in the dashboard topbar immediately revokes the session in the database.

---

## Alert persistence

Alerts are stored in a SQLite database (`alerts.db`) alongside `server.py`.

- Every alert that arrives is written to the database immediately.
- On each page load, the dashboard fetches up to 5,000 alerts from the last 90 days — history survives server restarts and browser refreshes.
- A background thread purges alerts older than 90 days every hour.
- The **Clear** button in the dashboard prompts for confirmation, then calls `DELETE /alerts` which wipes the entire database.
- Retention period is configurable via `--retain-days`.

### Querying history directly

```bash
# All alerts from the last 90 days (default)
curl -b cookies.txt http://localhost:8765/alerts | python3 -m json.tool

# Last 7 days only, max 1000 results
curl -b cookies.txt "http://localhost:8765/alerts?days=7&limit=1000"
```

---

## Suppressing dashboard noise (recommended)

Suricata may fire **SID 2034635** ("ET INFO Python BaseHTTP ServerBanner") on traffic
to/from the dashboard server. Suppress it:

```bash
echo "suppress gen_id 1, sig_id 2034635, track by_src, ip <your-server-ip>" \
  >> /etc/suricata/threshold.conf

sudo suricatasc -c reload-rules
```

---

## Suricata configuration

Make sure EVE JSON output is enabled in `/etc/suricata/suricata.yaml`:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - flow
```

Restart Suricata after any config change:

```bash
sudo systemctl restart suricata
```

---

## Running as a systemd service

Create `/etc/systemd/system/suricata-dashboard.service`:

```ini
[Unit]
Description=Suricata Live Dashboard
After=network.target suricata.service

[Service]
ExecStart=/usr/bin/python3 /opt/suricata-live/server.py \
    --eve /var/log/suricata/eve.json \
    --host 127.0.0.1 \
    --port 8765 \
    --db /opt/suricata-live/alerts.db \
    --retain-days 90
WorkingDirectory=/opt/suricata-live
Restart=on-failure
RestartSec=5
User=www-data

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now suricata-dashboard
```

> If running as `www-data`, ensure that user has read access to `eve.json` (see Permissions below).

---

## Reverse proxy with nginx (optional)

Recommended if you want HTTPS or to serve on port 443:

```nginx
server {
    listen 443 ssl;
    server_name ids.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/ids.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ids.yourdomain.com/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:8765;
        proxy_set_header   Host $host;

        # Required for SSE — disable all buffering
        proxy_buffering    off;
        proxy_cache        off;
        proxy_read_timeout 86400s;
        proxy_set_header   X-Accel-Buffering no;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name ids.yourdomain.com;
    return 301 https://$host$request_uri;
}
```

---

## API reference

All endpoints except `/login` require a valid session cookie.

| Method   | Endpoint  | Description                                      |
|----------|-----------|--------------------------------------------------|
| `GET`    | `/login`  | Login page (public)                              |
| `POST`   | `/login`  | Submit password, receive session cookie (public) |
| `GET`    | `/logout` | Revoke session and redirect to login             |
| `GET`    | `/`       | Dashboard HTML                                   |
| `GET`    | `/events` | SSE stream of live alerts                        |
| `GET`    | `/alerts` | JSON array of stored alerts                      |
| `DELETE` | `/alerts` | Delete all alerts from database                  |
| `GET`    | `/health` | Server status, client count, DB stats            |

### POST /login

```bash
curl -c cookies.txt -X POST http://localhost:8765/login \
  -H "Content-Type: application/json" \
  -d '{"password": "YourPassword"}'
# {"ok": true}
```

### GET /alerts query parameters

| Parameter | Default | Maximum | Description                 |
|-----------|---------|---------|-----------------------------|
| `days`    | `90`    | `90`    | How many days back to query |
| `limit`   | `5000`  | `20000` | Maximum number of alerts    |

### SSE event format

```
event: alert
data: {"id":"...","ts":"2026-04-07T10:23:45.123456+0000","src_ip":"10.20.25.138",
       "src_port":54321,"dst_ip":"203.0.113.42","dst_port":443,"proto":"TCP",
       "sig_id":2024385,"sig_msg":"ET TROJAN Cobalt Strike Beacon Activity",
       "category":"Malware","severity":"critical","action":"allowed",
       "flow_id":1234567890,"iface":"eth0","raw":{...full EVE event...}}

event: ping
data: 1744019025
```

### GET /health

```bash
curl -b cookies.txt http://localhost:8765/health
```

```json
{
  "status": "ok",
  "clients": 1,
  "db": {
    "total": 1482,
    "recent": 1247,
    "oldest": "2026-01-07T06:14:55.469532+0000"
  },
  "time": 1744019025
}
```

---

## Permissions

The server process needs read access to `eve.json`:

```bash
# Option A — add your user to the suricata group
sudo usermod -aG suricata $USER
# (log out and back in for the group change to take effect)

# Option B — grant world-read on the log file and directory
sudo chmod o+r /var/log/suricata/eve.json
sudo chmod o+x /var/log/suricata/
```

---

## Dashboard features

| Feature            | Details                                                        |
|--------------------|----------------------------------------------------------------|
| Live alert stream  | Alerts appear within ~100ms of Suricata writing to eve.json   |
| History on load    | Last 90 days loaded from SQLite on every page open or refresh |
| Severity filtering | Toggle Critical / High / Medium / Low / Info in the sidebar   |
| Search             | Filter by signature name, IP address, or SID                  |
| Event detail       | Click any row for full network metadata and raw EVE JSON      |
| Top sources        | Top 5 source IPs by alert count, live-updated                 |
| Sparkline          | 30-second rolling alert rate chart                            |
| Pause / Resume     | Pause the live stream without disconnecting from the server   |
| Clear with confirm | Prompts before wiping the database — cannot be undone         |
| Connection badge   | Shows CONNECTING / LIVE / RECONNECTING with auto-retry        |
| Login page         | Password-protected with PBKDF2 hashing and HttpOnly cookie    |
| Sign out           | Revokes session immediately and redirects to login            |
