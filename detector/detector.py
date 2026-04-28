"""
detector.py — Anomaly detection engine. Ticks every second.

Rules
-----
1. Z-score > 3.0  OR  rate > 5× mean  → anomaly (whichever fires first)
2. IP 4xx/5xx rate ≥ 3× error baseline → tighten thresholds to z>2.0 / rate>3×
3. Per-IP anomaly  → iptables block + Slack alert (target: within 10 s of event)
4. Global anomaly  → Slack alert only
"""

import time
import threading

import monitor
import baseline
import blocker
import notifier
from audit import audit_log

ANOMALY_ZSCORE = 3.0
ANOMALY_RATE_MULT = 5.0
ERROR_SURGE_MULT = 3.0
TIGHTENED_ZSCORE = 2.0
TIGHTENED_RATE_MULT = 3.0
WINDOW_SECONDS = 60

_alerted_global = False
_alerted_global_lock = threading.Lock()

_tightened_ips: set[str] = set()
_tightened_lock = threading.Lock()


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
) -> tuple[bool, str]:
    z = _zscore(rate, mean, stddev)
    if z > zt:
        return True, f"z-score={z:.2f}>{zt}"
    if mean > 0 and rate > mt * mean:
        return True, f"rate={rate:.2f}>{mt}x_mean={mean:.2f}"
    return False, ""


def tick() -> None:
    stats = baseline.get_stats()
    mean = stats["mean"]
    stddev = stats["stddev"]
    err_mean = stats["error_mean"]

    if stats["sample_count"] < 10:
        return

    # ── Global ────────────────────────────────────────────────────────────────
    with monitor.state_lock:
        g_rate = _rate(monitor.global_window)

    anomalous, reason = _is_anomalous(
        g_rate, mean, stddev, ANOMALY_ZSCORE, ANOMALY_RATE_MULT
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

    # ── Per-IP ────────────────────────────────────────────────────────────────
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

        # Error surge → tighten thresholds
        if err_mean > 0 and ip_erate >= ERROR_SURGE_MULT * err_mean:
            with _tightened_lock:
                _tightened_ips.add(ip)
            tightened = True

        zt = TIGHTENED_ZSCORE if tightened else ANOMALY_ZSCORE
        mt = TIGHTENED_RATE_MULT if tightened else ANOMALY_RATE_MULT

        anomalous, reason = _is_anomalous(ip_rate, mean, stddev, zt, mt)
        if anomalous:
            duration = blocker.block(ip)
            audit_log(
                action="BAN",
                ip=ip,
                condition=reason,
                rate=ip_rate,
                baseline=mean,
                duration=f"{duration}m" if duration else "permanent",
            )
            notifier.send_ip_alert(
                ip=ip,
                condition=reason,
                rate=ip_rate,
                baseline_mean=mean,
                baseline_stddev=stddev,
                ban_duration_minutes=duration,
            )


def start() -> None:
    def _loop():
        while True:
            try:
                tick()
            except Exception as exc:
                print(f"[detector] error: {exc}", flush=True)
            time.sleep(1)

    threading.Thread(target=_loop, daemon=True, name="detector").start()
