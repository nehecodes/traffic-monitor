# Phase 1 Migration Guide

## Overview
Phase 1 refactoring focused on **Safety & Security** improvements. All critical security issues have been addressed while maintaining backward compatibility where possible.

## What Changed

### 1. ✅ Secrets Management (.env)
**Before:** Slack webhook hardcoded in `config.yaml` (tracked in git)  
**After:** Secrets loaded from `.env` file (gitignored)

**Action Required:**
```bash
# 1. Copy the example file
cp .env.example .env

# 2. Edit .env and add your actual Slack webhook URL
nano .env

# 3. Ensure .env is never committed
git status  # Should show .env as untracked
```

### 2. ✅ Configuration Validation (Pydantic)
**Before:** Raw YAML dict, no validation, runtime errors  
**After:** Pydantic models with type checking and validation

**Benefits:**
- Startup fails fast with clear error messages if config is invalid
- Type safety throughout the application
- IP addresses validated (prevents injection)
- Numeric ranges enforced (e.g., port 1-65535)
- Unknown config keys rejected

**Breaking Changes:**
- `config.yaml` structure for whitelist changed:
  ```yaml
  # OLD (no longer works)
  whitelist:
    - ""
    - "192.168.1.100"
  
  # NEW (required)
  whitelist:
    ips:
      - "192.168.1.100"
      - "10.0.0.5"
  ```

### 3. ✅ Log Entry Validation
**Before:** Raw JSON parsing, no validation  
**After:** Pydantic `NginxLogEntry` model with validation

**Security Improvements:**
- IP address format validated (IPv4)
- Status codes range-checked (0-999)
- HTTP methods sanitized
- Path length limited (2048 chars)
- Malformed entries logged and skipped

### 4. ✅ Docker Path Fixes
**Before:** Incorrect paths caused container startup failures  
**After:** Proper Python module structure

**Changes:**
- `Dockerfile`: Now uses `python -m detector.main`
- `docker-compose.yaml`: Mounts `.env` file
- Added `detector/__init__.py` (proper Python package)

**Testing:**
```bash
# Rebuild and test
docker-compose build norma
docker-compose up norma
```

### 5. ✅ iptables Error Handling
**Before:** Silent failures, state desync  
**After:** Retry logic, exceptions, state rollback

**Improvements:**
- 3 retries with exponential backoff (0.5s, 1s, 2s)
- `IptablesError` exception raised after exhausting retries
- State only updated after successful iptables execution
- Rollback on failure (unbanner restores ban state)
- Idempotent operations (duplicate rules treated as success)

**Behavior:**
```python
# Ban fails → IP NOT added to _bans dict → detector will retry next tick
# Unban fails → IP restored to _bans dict → will retry on next unbanner tick
```

### 6. ✅ Whitelist Applied
**Before:** Whitelist defined but never used  
**After:** Properly loaded from config and enforced

**Verification:**
```bash
# Check logs on startup
docker-compose logs norma | grep -i whitelist
# Should show: "[main] Whitelist: 192.168.1.100, 10.0.0.5"
```

## Environment Variables

### Supported Overrides
```bash
# .env file
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Optional overrides
NGINX_ACCESS_LOG=/var/log/nginx/hng-access.log
AUDIT_LOG=/var/log/detector/audit.log
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=8080
```

## Testing Checklist

- [ ] Create `.env` file from `.env.example`
- [ ] Update `config.yaml` whitelist to new format
- [ ] Add your IP to whitelist
- [ ] Rebuild Docker image: `docker-compose build norma`
- [ ] Start services: `docker-compose up -d`
- [ ] Check logs: `docker-compose logs -f norma`
- [ ] Verify dashboard: `http://localhost:8080`
- [ ] Check whitelist: Look for `[main] Whitelist:` in logs
- [ ] Verify config validation: Try invalid config (should fail at startup)

## Rollback Plan

If you need to revert to the old version:

```bash
# 1. Checkout previous commit
git checkout <previous-commit-hash>

# 2. Rebuild
docker-compose build norma

# 3. Restore old config.yaml format
# (Put webhook back in config.yaml if needed)
```

