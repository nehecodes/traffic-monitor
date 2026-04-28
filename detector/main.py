"""
main.py — Entry point. Loads config, wires up all subsystems, runs the
per-second baseline recording loop.
"""

import os
import sys
import time

import yaml
from detector import audit
from detector import notifier
from detector import unbanner
from detector import dashboard
from detector import monitor as _monitor
from detector import baseline as _baseline
from detector import detector as _detector
import blocker as _blocker

# ── Config ────────────────────────────────────────────────────────────────────

_cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
with open(_cfg_path) as f:
    cfg = yaml.safe_load(f)


audit.init(cfg["log"]["audit_log"])


notifier.init(cfg["slack"]["webhook_url"])


_monitor.WINDOW_SECONDS = cfg["windows"]["rate_window_seconds"]


_baseline.BASELINE_WINDOW_SECONDS = cfg["windows"]["baseline_window_minutes"] * 60
_baseline.RECALC_INTERVAL = cfg["windows"]["baseline_recalc_seconds"]
_baseline.MIN_SAMPLES = cfg["windows"]["min_baseline_samples"]


_detector.ANOMALY_ZSCORE = cfg["thresholds"]["anomaly_zscore"]
_detector.ANOMALY_RATE_MULT = cfg["thresholds"]["anomaly_rate_multiplier"]
_detector.ERROR_SURGE_MULT = cfg["thresholds"]["error_surge_multiplier"]
_detector.TIGHTENED_ZSCORE = cfg["thresholds"]["tightened_zscore"]
_detector.TIGHTENED_RATE_MULT = cfg["thresholds"]["tightened_rate_multiplier"]


_blocker.BAN_SCHEDULE_MINUTES = cfg["ban"]["schedule_minutes"]

# ── Start subsystems ──────────────────────────────────────────────────────────

print("[main] Starting baseline engine …", flush=True)
_baseline.start()

print("[main] Starting log monitor …", flush=True)
observer = _monitor.start(cfg["log"]["nginx_access_log"])

print("[main] Starting anomaly detector …", flush=True)
_detector.start()

print("[main] Starting auto-unbanner …", flush=True)

unbanner.start()

print("[main] Starting dashboard …", flush=True)

dashboard.start(host=cfg["dashboard"]["host"], port=cfg["dashboard"]["port"])

print(
    f"[main] All systems running. Dashboard → http://0.0.0.0:{cfg['dashboard']['port']}/",
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
