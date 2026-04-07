# Suricata Live Dashboard

A lightweight, real-time Suricata IDS alert dashboard.
Two files, no build step, no database.

```
suricata-live/
├── server.py               ← Python SSE backend  (tails eve.json)
├── suricata-dashboard.html ← Single-file dashboard (served by the backend)
├── requirements.txt
└── README.md
```

---

## How it works

```
/var/log/suricata/eve.json
        │
        │  async tail -F
        ▼
   server.py  (aiohttp)
        │
        │  Server-Sent Events  GET /events
        ▼
  suricata-dashboard.html
  (runs in your browser)
```

The backend asynchronously tails `eve.json`, filters for
`event_type == "alert"` lines, normalises them, and streams them
to every connected browser over SSE.

The dashboard connects on load. If the backend is unreachable it
automatically falls back to **demo mode** (synthetic data) and
retries the connection every 3 seconds. When the real feed arrives,
demo mode stops and the badge switches from **DEMO → LIVE**.

---

## Quick start

### 1 — Install dependencies

```bash
pip install aiofiles aiohttp
# or
pip install -r requirements.txt
```

### 2 — Start the server

```bash
# Default: tails /var/log/suricata/eve.json on port 8765
python3 server.py

# Custom path / port
python3 server.py --eve /var/log/suricata/eve.json --port 8765

# Bind to localhost only (more secure if behind a reverse proxy)
python3 server.py --host 127.0.0.1 --port 8765
```

### 3 — Open the dashboard

```
http://localhost:8765/
```

That's it. The dashboard is served by the Python server itself —
no separate web server needed.

---

## Command-line options

| Flag     | Default                          | Description              |
|----------|----------------------------------|--------------------------|
| `--eve`  | `/var/log/suricata/eve.json`     | Path to Suricata eve.json |
| `--port` | `8765`                           | TCP port to listen on     |
| `--host` | `0.0.0.0`                        | Bind address              |

---

## Suricata configuration

Make sure Suricata is writing EVE JSON output.
In `/etc/suricata/suricata.yaml`:

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

Then restart Suricata:

```bash
sudo systemctl restart suricata
```

---

## Running as a systemd service (optional)

Create `/etc/systemd/system/suricata-dashboard.service`:

```ini
[Unit]
Description=Suricata Live Dashboard
After=network.target suricata.service

[Service]
ExecStart=/usr/bin/python3 /opt/suricata-live/server.py \
    --eve /var/log/suricata/eve.json \
    --host 127.0.0.1 \
    --port 8765
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

---

## Reverse proxy (nginx, optional)

If you want HTTPS or to expose it on port 80/443:

```nginx
server {
    listen 443 ssl;
    server_name ids.yourdomain.com;

    location / {
        proxy_pass         http://127.0.0.1:8765;
        proxy_set_header   Host $host;

        # Required for SSE
        proxy_buffering    off;
        proxy_cache        off;
        proxy_read_timeout 86400s;
        proxy_set_header   X-Accel-Buffering no;
    }
}
```

---

## API endpoints

| Endpoint  | Description                         |
|-----------|-------------------------------------|
| `GET /`        | Serves `suricata-dashboard.html`  |
| `GET /events`  | SSE stream of normalised alerts   |
| `GET /health`  | JSON health check + client count  |

### SSE event format

```
event: alert
data: {"id":"...","ts":"2024-01-15T10:23:45.123456+0000","src_ip":"192.168.1.5",
       "src_port":54321,"dst_ip":"203.0.113.42","dst_port":443,"proto":"TCP",
       "sig_id":2024385,"sig_msg":"ET TROJAN Cobalt Strike Beacon Activity",
       "category":"Malware","severity":"critical","action":"allowed",
       "flow_id":1234567890,"iface":"eth0","raw":{...full eve event...}}

event: ping
data: 1705312345
```

### Health check

```bash
curl http://localhost:8765/health
# {"status": "ok", "clients": 2, "time": 1705312345}
```

---

## Permissions

The server process needs read access to `eve.json`.
On most systems:

```bash
# Add your user to the suricata group
sudo usermod -aG suricata $USER

# Or grant read permission directly
sudo chmod o+r /var/log/suricata/eve.json
sudo chmod o+x /var/log/suricata/
```
