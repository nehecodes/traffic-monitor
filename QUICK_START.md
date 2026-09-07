# Quick Start 


## Setup Instructions

### 1. Create Environment File

```bash
cp .env.example .env
nano .env  # Add your Slack webhook URL
```

Your `.env` should look like:
```
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### 2. Update Config (if needed)

Edit `config.yaml` and update the whitelist:

```yaml
whitelist:
  ips:
    - "YOUR_IP_HERE"    # Your office/home IP
    # - "10.0.0.5"      # Add more IPs as needed
```

### 3. Rebuild and Start

```bash
# Rebuild the Docker image (this will install dependencies)
docker compose build --no-cache norma

# Start all services
docker compose up -d

# Check logs
docker compose logs -f norma
```

### 4. Verify

You should see:
```
[main] Loading configuration …
[config] Loaded environment from /app/.env
[config] Configuration validated successfully
[main] Initializing subsystems …
[main] Whitelist: 192.168.1.100
[main] Starting baseline engine …
[main] Starting log monitor …
[main] Starting anomaly detector …
[main] Starting auto-unbanner …
[main] Starting dashboard …
[main] All systems running. Dashboard → http://0.0.0.0:8080/
```

### 5. Access Dashboard

Open http://localhost:8080 in your browser

## Troubleshooting

### "No module named 'yaml'"
This means Docker didn't rebuild properly. Run:
```bash
docker compose down
docker compose build --no-cache norma
docker compose up -d
```

### "Configuration validation failed"
Check your `config.yaml` syntax. Common issues:
- Whitelist must be under `whitelist.ips` (not flat list)
- YAML indentation must be correct
- All numeric values must be valid ranges

### "No Slack webhook configured"
Add `SLACK_WEBHOOK_URL` to your `.env` file

### Container keeps restarting
```bash
# Check logs for the actual error
docker compose logs norma

# Check if config file is valid
cat config.yaml

# Check if .env exists
ls -la .env
```

