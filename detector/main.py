"""
main.py — Entry point. Loads config, wires up all subsystems, runs the
per-second baseline recording loop.
"""

import os
import sys
import time

from .config_schema import get_config
from . import audit
from . import notifier
from . import unbanner
from . import dashboard
from . import monitor as _monitor
from . import baseline as _baseline
from . import anomaly_detector as _detector
from . import blocker as _blocker

# ── Load and validate configuration ───────────────────────────────────────────

print("[main] Loading configuration …", flush=True)

try:
    cfg = get_config()
except Exception as e:
    print(f"[main] FATAL: Configuration error: {e}", flush=True)
    sys.exit(1)

# ── Initialize subsystems with validated config ───────────────────────────────

print("[main] Initializing subsystems …", flush=True)

# Audit logging
audit.init(cfg.log.audit_log)

# Slack notifications
notifier.init(cfg.slack_webhook_url)

# Monitor sliding windows
_monitor.WINDOW_SECONDS = cfg.windows.rate_window_seconds

# Baseline calculation
_baseline.BASELINE_WINDOW_SECONDS = cfg.windows.baseline_window_minutes * 60
_baseline.RECALC_INTERVAL = cfg.windows.baseline_recalc_seconds
_baseline.MIN_SAMPLES = cfg.windows.min_baseline_samples

# Detector thresholds
_detector.ANOMALY_ZSCORE = cfg.thresholds.anomaly_zscore
_detector.ANOMALY_RATE_MULT = cfg.thresholds.anomaly_rate_multiplier
_detector.ERROR_SURGE_MULT = cfg.thresholds.error_surge_multiplier
_detector.TIGHTENED_ZSCORE = cfg.thresholds.tightened_zscore
_detector.TIGHTENED_RATE_MULT = cfg.thresholds.tightened_rate_multiplier
_detector.MIN_ABSOLUTE_RATE = cfg.thresholds.min_absolute_rate
_detector.MIN_ABSOLUTE_GLOBAL_RATE = cfg.thresholds.min_absolute_global_rate
_detector.WINDOW_SECONDS = cfg.windows.rate_window_seconds

# Blocker configuration
_blocker.BAN_SCHEDULE_MINUTES = cfg.ban.schedule_minutes
_blocker.WHITELIST = set(cfg.whitelist.ips)

if _blocker.WHITELIST:
    print(f"[main] Whitelist: {', '.join(sorted(_blocker.WHITELIST))}", flush=True)
else:
    print("[main] Warning: No whitelist configured. Add IPs to config.yaml to prevent self-blocking.", flush=True)

# ── Start subsystems ──────────────────────────────────────────────────────────

print("[main] Starting baseline engine …", flush=True)
_baseline.start()

print("[main] Starting log monitor …", flush=True)
observer = _monitor.start(cfg.log.nginx_access_log)

print("[main] Starting anomaly detector …", flush=True)
_detector.start()

print("[main] Starting auto-unbanner …", flush=True)
unbanner.start()

print("[main] Starting dashboard …", flush=True)
dashboard.start(host=cfg.dashboard.host, port=cfg.dashboard.port)

print(
    f"[main] All systems running. Dashboard → http://{cfg.dashboard.host}:{cfg.dashboard.port}/",
    flush=True,
)

# ── Per-second baseline recording loop ───────────────────────────────────────

try:
    while True:
        time.sleep(1)
        with _monitor.state_lock:
            rps = len(_monitor.global_window) / _monitor.WINDOW_SECONDS
            eps = len(_monitor.global_error_window) / _monitor.WINDOW_SECONDS
        _baseline.record(rps, eps)
except KeyboardInterrupt:
    print("[main] Shutting down …", flush=True)
    observer.stop()
    observer.join()
    sys.exit(0)
