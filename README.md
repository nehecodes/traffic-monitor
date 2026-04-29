# Anomally Traffic Detecteor — Real-Time Traffic Anomaly Detection

A long-running Python daemon that watches Nginx access logs in real time, learns what normal traffic looks like, and automatically blocks anomalous IPs using `iptables`. Built to protect a live Nextcloud instance deployed with Docker Compose.

---

## How It Works

```
Nginx writes JSON log
      ↓
Watchdog detects new bytes (inotify)
      ↓
Parse: source_ip, timestamp, method, path, status, response_size
      ↓
Update sliding windows (per-IP + global, last 60s)
      ↓
Compare against rolling 30-min baseline (mean + stddev)
      ↓
Anomalous?  ──yes──▶  iptables DROP + Slack alert + audit log
      ↓
Auto-unban after 10m → 30m → 2h → permanent
```

---

## Repository Structure

```
.
├── docker-compose.yaml
├── nginx/
│   └── nginx.conf
└── detector/
    ├── Dockerfile
    ├── main.py          # entry point — wires and starts all subsystems
    ├── monitor.py       # tails the JSON log, feeds sliding windows
    ├── baseline.py      # rolling 30-min mean/stddev, per-hour slots
    ├── detector.py      # z-score + rate-multiplier anomaly detection
    ├── blocker.py       # iptables bans with tiered escalation
    ├── unbanner.py      # auto-release on backoff schedule
    ├── notifier.py      # Slack webhook alerts
    ├── dashboard.py     # FastAPI live metrics API + static frontend
    ├── audit.py         # structured audit log writer
    ├── config.yaml      # all tunable settings
    ├── requirements.txt
    └── static/
        └── index.html   # dashboard UI (polls /api/metrics every 3s)
```

---

## Detection Logic

| Condition | Threshold | Action |
|---|---|---|
| Per-IP z-score | > 3.0 | Block IP + Slack alert |
| Per-IP rate | > 5× baseline mean | Block IP + Slack alert |
| Global z-score | > 3.0 | Slack alert only |
| IP error rate (4xx/5xx) | ≥ 3× baseline error rate | Tighten thresholds to z > 2.0 / rate > 3× |

**Ban escalation schedule** (same IP re-offending):

```
1st offence → 10 min
2nd offence → 30 min
3rd offence → 2 hours
4th offence → permanent
```

---

## Prerequisites

- Linux VPS — minimum 2 vCPU, 2 GB RAM (AWS, GCP, DigitalOcean, etc.)
- Docker and Docker Compose plugin installed
- A domain or subdomain pointing to your server IP (for the dashboard)
- Slack incoming webhook URL (for alerts)

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/yourname/sentinel.git
cd sentinel
```

### 2. Configure

```bash
cp detector/config.yaml detector/config.yaml.bak
nano detector/config.yaml
```

Minimum required changes:

```yaml
slack:
  webhook_url: "https://hooks.slack.com/services/YOUR/REAL/WEBHOOK"
```

### 3. Set your domain in nginx.conf

```bash
nano nginx/nginx.conf
```

Replace `monitor.yourdomain.com` with your actual dashboard subdomain. The Nextcloud server block uses `server_name _` (catch-all) so it responds to your server IP directly.

### 4. Add your IP to the whitelist

To prevent locking yourself out, add your IP to `config.yaml` before starting:

```yaml
whitelist:
  - "YOUR.HOME.IP.HERE"
```

### 5. Switch iptables to legacy mode on the host

Required on Debian 12+ — the daemon uses `iptables-legacy` to write rules that affect the host's actual packet filter, not a container-namespaced copy:

```bash
sudo update-alternatives --set iptables /usr/sbin/iptables-legacy
sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
```

### 6. Create the xtables lock file

```bash
# If /run/xtables.lock is a directory, remove it first
sudo rmdir /run/xtables.lock 2>/dev/null || true
sudo touch /run/xtables.lock
```

### 7. Deploy

```bash
docker compose pull
docker compose up -d --build
docker compose logs -f
```

---

## Verify It's Working

```bash
# All three containers running?
docker compose ps

# Dashboard API responding?
curl -s http://localhost:8080/api/metrics | python3 -m json.tool | head -20

# JSON logs being written by nginx?
tail -f $(docker volume inspect HNG-nginx-logs \
  --format '{{ .Mountpoint }}')/hng-access.log

# iptables rules landing on the host?
sudo iptables-legacy -L INPUT -n | grep DROP
```

Open the dashboard in your browser at `http://monitor.yourdomain.com`.

---

## Configuration Reference

All settings live in `detector/config.yaml`:

```yaml
slack:
  webhook_url: ""                  # Slack incoming webhook URL

log:
  nginx_access_log: "/var/log/nginx/hng-access.log"
  audit_log: "/var/log/detector/audit.log"

thresholds:
  anomaly_zscore: 3.0              # z-score threshold for anomaly
  anomaly_rate_multiplier: 5.0     # rate > N× mean triggers anomaly
  error_surge_multiplier: 3.0      # error rate > N× baseline tightens thresholds
  tightened_zscore: 2.0            # z-score threshold after error surge
  tightened_rate_multiplier: 3.0   # rate multiplier after error surge

windows:
  rate_window_seconds: 60          # sliding window size
  baseline_window_minutes: 30      # rolling baseline window
  baseline_recalc_seconds: 60      # how often baseline is recalculated
  min_baseline_samples: 10         # minimum samples before detection activates

ban:
  schedule_minutes: [10, 30, 120]  # ban durations; beyond this → permanent

whitelist:
  - "1.2.3.4"                      # IPs that are never blocked

dashboard:
  host: "0.0.0.0"
  port: 8080
```

---

## Dashboard

The live metrics UI is served at `/` and polls `/api/metrics` every 3 seconds.

| Metric | Description |
|---|---|
| Global req/s | Current request rate across all IPs (60s window) |
| Top 10 IPs | Source IPs ranked by request count |
| Banned IPs | Active bans with tier, ban time, and countdown to release |
| Baseline | Rolling mean and stddev used for anomaly detection |
| CPU / Memory | Host system resource usage |
| Uptime | Time since daemon started |

The API is also available directly:

```bash
curl -s http://localhost:8080/api/metrics | python3 -m json.tool
```

OpenAPI docs (auto-generated by FastAPI): `http://localhost:8080/docs`

---

## Audit Log

Every ban, unban, and baseline recalculation is written to `/var/log/detector/audit.log`:

```
[2026-04-29T06:58:29Z] BAN 107.155.48.46 | z-score=3.81>2.0 | rate=0.77 | baseline=0.19 | 120m
[2026-04-29T07:08:31Z] UNBAN 107.155.48.46 | tier=0 ban_expired | rate=0.00 | baseline=0.00 | next=30m
[2026-04-29T07:09:00Z] BASELINE_RECALC - | hour=7 samples=480 | rate=0.19 | baseline=0.19 | stddev=0.1500
```

Tail it live:

```bash
tail -f /var/log/detector/audit.log
```

---

## If You Get Locked Out

If your own IP gets blocked and you lose SSH access:

**Option 1 — AWS EC2 Instance Connect (browser-based SSH):**
```
AWS Console → EC2 → Instances → Connect → EC2 Instance Connect
```

**Option 2 — If you still have another session open:**
```bash
# List rules with line numbers
docker exec hng-detector iptables-legacy -L INPUT -n --line-numbers | grep DROP

# Remove by line number
docker exec hng-detector iptables-legacy -D INPUT <line_number>

# Or flush everything
docker exec hng-detector iptables-legacy -F INPUT
```

Add your IP to the `whitelist` in `config.yaml` before restarting.

---

## Day-to-Day Operations

```bash
# Live logs from all containers
docker compose logs -f

# Logs from one service
docker compose logs -f detector

# Restart after config change (no rebuild needed)
docker compose restart detector

# Rebuild and redeploy after code changes
docker compose up -d --build detector

# Current active bans
curl -s http://localhost:8080/api/metrics | python3 -c \
  "import json,sys; [print(b['ip'], b['remaining_seconds'],'s remaining') \
   for b in json.load(sys.stdin)['banned_ips']]"

# Manually unban an IP
docker exec hng-detector iptables-legacy -D INPUT -s <ip> -j DROP

# Check iptables on host
sudo iptables-legacy -L INPUT -n | grep DROP
```

---

## Slack Alert Format

**IP blocked:**
```
🚨 IP BLOCKED 107.155.48.46
Condition: z-score=3.81>2.0
Rate: 0.77 req/s  |  Baseline: 0.19 ± 0.15
Ban duration: 120 min
Time: 2026-04-29T06:58:29Z
```

**IP unbanned:**
```
✅ IP UNBANNED 107.155.48.46
Tier completed: 1  |  Next ban if re-offend: 2h
Time: 2026-04-29T07:28:31Z
```

**Global anomaly:**
```
⚠️ GLOBAL TRAFFIC ANOMALY
Condition: rate=12.40>5x_mean=2.10
Rate: 12.40 req/s  |  Baseline: 2.10 ± 0.80
Time: 2026-04-29T08:00:01Z
```

---

## Notes

- **Nextcloud** is accessible by server IP only (nginx `default_server` catch-all)
- **Dashboard** is accessible by subdomain only (separate nginx server block)
- The `HNG-nginx-logs` Docker volume name is pinned — renaming it will break the log pipeline
- The daemon needs approximately 10 seconds of traffic before the baseline is populated enough to start detecting anomalies
- `config.yaml` is gitignored by default to prevent webhook URL leaks — commit `config.yaml.example` instead