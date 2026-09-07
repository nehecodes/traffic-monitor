"""
detector.py — Anomaly detection engine. Ticks every second.

Rules (per spec)
----------------
1. Z-score > 3.0  OR  rate > 5× mean  → anomaly (whichever fires first)
2. IP 4xx/5xx rate ≥ 3× error baseline → tighten thresholds to z>2.0 / 3×
3. Per-IP anomaly  → iptables block + Slack alert (within 10 s)
4. Global anomaly  → Slack alert only (never auto-block global traffic)

Guards against false positives
-------------------------------
* Detection is silent until sample_count >= MIN_SAMPLES (300 = 5 min).
  Below this threshold the baseline mean is not representative.

* MIN_ABSOLUTE_RATE = 10.0 req/s — an IP doing fewer than 10 requests
  per second is NEVER blocked regardless of z-score or multiplier.
  Rationale: at near-zero baselines (mean=0.05) the 5× multiplier fires
  at 0.25 req/s = 15 requests per minute, which is normal browser behaviour.
  The absolute floor ensures the spec thresholds are applied only when
  the rate is genuinely high in absolute terms.

* Error surge tightening requires BOTH err_mean > 0 AND at least
  MIN_SAMPLES error samples. Tightening on a zero or near-zero error
  baseline causes the same false-positive problem as the rate baseline.

* Global anomaly detection uses the same absolute floor.
"""

import threading
import time

from . import baseline
from . import blocker
from . import monitor
from . import notifier
from .audit import audit_log
from .blocker import IptablesError

# ── Configurable thresholds (overridden by main.py from config.yaml) ─────────
ANOMALY_ZSCORE = 3.0
ANOMALY_RATE_MULT = 5.0
ERROR_SURGE_MULT = 3.0
TIGHTENED_ZSCORE = 2.0
TIGHTENED_RATE_MULT = 3.0
WINDOW_SECONDS = 60

# Absolute rate floor — never block below this regardless of z-score.
# Set to 10 req/s: a legitimate page load generates ~20 req over ~2 seconds
# which looks like 0.33 req/s averaged over the 60s window — well below floor.
# A real attack at 10 req/s = 600 requests per minute is unambiguous.
MIN_ABSOLUTE_RATE = 10.0  # req/s — per-IP floor
MIN_ABSOLUTE_GLOBAL_RATE = 20.0  # req/s — global floor (higher: shared across all IPs)

# Minimum baseline samples before detection activates (must match baseline.py)
MIN_SAMPLES = 300

_alerted_global = False
_alerted_global_lock = threading.Lock()

_tightened_ips: set[str] = set()
_tightened_lock = threading.Lock()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _rate(window) -> float:
    return len(window) / WINDOW_SECONDS


def _zscore(rate: float, mean: float, stddev: float) -> float:
    return (rate - mean) / stddev if stddev else 0.0


def _is_anomalous(
    rate: float,
    mean: float,
    stddev: float,
    zt: float,
    mt: float,
    abs_floor: float,
) -> tuple[bool, str]:
    """
    Return (is_anomalous, reason_string).

    Checks in order:
    1. Absolute rate floor — never anomalous below this.
    2. Z-score threshold.
    3. Rate multiplier threshold.
    """
    # Absolute floor: protects against false positives on near-zero baselines
    if rate < abs_floor:
        return False, ""

    z = _zscore(rate, mean, stddev)
    if z > zt:
        return True, f"z-score={z:.2f}>{zt}"

    if mean > 0 and rate > mt * mean:
        return True, f"rate={rate:.2f}>{mt}x_mean={mean:.2f}"

    return False, ""


# ── Detection tick ────────────────────────────────────────────────────────────


def tick() -> None:
    stats = baseline.get_stats()
    mean = stats["mean"]
    stddev = stats["stddev"]
    err_mean = stats["error_mean"]
    n_samples = stats["sample_count"]
    n_error_samples = stats["error_sample_count"]

    # Gate: require a mature baseline before any detection fires.
    # 300 samples = 5 minutes of 1-per-second recordings.
    if n_samples < MIN_SAMPLES:
        return

    # ── Global check ──────────────────────────────────────────────────────────
    with monitor.state_lock:
        g_rate = _rate(monitor.global_window)

    anomalous, reason = _is_anomalous(
        g_rate,
        mean,
        stddev,
        ANOMALY_ZSCORE,
        ANOMALY_RATE_MULT,
        MIN_ABSOLUTE_GLOBAL_RATE,
    )
    with _alerted_global_lock:
        global _alerted_global
        if anomalous and not _alerted_global:
            _alerted_global = True
            notifier.send_global_alert(
                condition=reason,
                rate=g_rate,
                baseline_mean=mean,
                baseline_stddev=stddev,
            )
        elif not anomalous:
            _alerted_global = False

    # ── Per-IP checks ─────────────────────────────────────────────────────────
    with monitor.state_lock:
        ips = list(monitor.ip_windows.keys())

    for ip in ips:
        if blocker.is_blocked(ip):
            continue

        with monitor.state_lock:
            ip_rate = _rate(monitor.ip_windows.get(ip, []))
            ip_erate = _rate(monitor.ip_error_windows.get(ip, []))

        with _tightened_lock:
            tightened = ip in _tightened_ips

        # Error surge → tighten thresholds.
        # Guard: require err_mean > 0 AND enough error baseline samples.
        # Without the sample guard, a single 404 on a zero-error baseline
        # produces err_mean≈0 → the "err_mean > 0" check passes spuriously
        # on the first recalc tick after errors arrive.
        if (
            err_mean > 0
            and n_error_samples >= MIN_SAMPLES
            and ip_erate >= ERROR_SURGE_MULT * err_mean
        ):
            with _tightened_lock:
                _tightened_ips.add(ip)
            tightened = True

        zt = TIGHTENED_ZSCORE if tightened else ANOMALY_ZSCORE
        mt = TIGHTENED_RATE_MULT if tightened else ANOMALY_RATE_MULT

        anomalous, reason = _is_anomalous(
            ip_rate,
            mean,
            stddev,
            zt,
            mt,
            MIN_ABSOLUTE_RATE,
        )
        if anomalous:
            try:
                duration = blocker.block(ip)
                
                # Format duration for logging
                if duration is None:
                    duration_str = "permanent"
                elif duration == 0:
                    duration_str = "whitelisted"
                else:
                    duration_str = f"{duration}m"
                
                audit_log(
                    action="BAN",
                    ip=ip,
                    condition=reason,
                    rate=ip_rate,
                    baseline=mean,
                    duration=duration_str,
                )
                notifier.send_ip_alert(
                    ip=ip,
                    condition=reason,
                    rate=ip_rate,
                    baseline_mean=mean,
                    baseline_stddev=stddev,
                    ban_duration_minutes=duration if duration else 0,
                )
            except IptablesError as e:
                # Log the failure but don't crash the detector
                audit_log(
                    action="BAN_FAILED",
                    ip=ip,
                    condition=f"iptables_error: {reason}",
                    rate=ip_rate,
                    baseline=mean,
                    duration=str(e),
                )
                print(f"[detector] Failed to block {ip}: {e}", flush=True)


def start() -> None:
    def _loop():
        while True:
            try:
                tick()
            except Exception as exc:
                print(f"[detector] error: {exc}", flush=True)
            time.sleep(1)

    threading.Thread(target=_loop, daemon=True, name="detector").start()
