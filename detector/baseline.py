"""
baseline.py — Rolling 30-minute baseline of per-second request counts.

* Every second main.py appends the current req/s to a circular buffer.
* A background thread recalculates mean/stddev every 60 seconds and
  writes a BASELINE_RECALC entry to the audit log.
* Counts are also bucketed by hour-of-day; the current hour's slot is
  preferred once it has >= MIN_SAMPLES entries.
"""

import math
import time
import threading
from collections import deque, defaultdict

from audit import audit_log

BASELINE_WINDOW_SECONDS = 30 * 60
RECALC_INTERVAL = 60
MIN_SAMPLES = 10

_counts: deque = deque()
_error_counts: deque = deque()

_hour_slots: defaultdict = defaultdict(list)
_error_hour_slots: defaultdict = defaultdict(list)

_lock = threading.Lock()

stats = {
    "mean": 0.0,
    "stddev": 1.0,
    "error_mean": 0.0,
    "error_stddev": 1.0,
    "last_recalc": 0.0,
    "sample_count": 0,
}


def _mean_stddev(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 1.0
    n = len(values)
    mu = sum(values) / n
    if n < 2:
        return mu, 1.0
    var = sum((x - mu) ** 2 for x in values) / (n - 1)
    return mu, max(math.sqrt(var), 0.01)


def _recalc() -> None:
    now = time.time()
    cutoff = now - BASELINE_WINDOW_SECONDS
    current_hour = int(time.strftime("%H"))

    with _lock:
        while _counts and _counts[0][0] < cutoff:
            _counts.popleft()
        while _error_counts and _error_counts[0][0] < cutoff:
            _error_counts.popleft()

        values = [c for _, c in _counts]
        error_values = [c for _, c in _error_counts]

        # Prefer current-hour slot when it has enough samples
        hour_vals = _hour_slots[current_hour]
        if len(hour_vals) >= MIN_SAMPLES:
            values = hour_vals[-BASELINE_WINDOW_SECONDS:]

        hour_err_vals = _error_hour_slots[current_hour]
        if len(hour_err_vals) >= MIN_SAMPLES:
            error_values = hour_err_vals[-BASELINE_WINDOW_SECONDS:]

    mu, sd = _mean_stddev(values)
    emu, esd = _mean_stddev(error_values)

    with _lock:
        stats.update(
            {
                "mean": mu,
                "stddev": sd,
                "error_mean": emu,
                "error_stddev": esd,
                "last_recalc": now,
                "sample_count": len(values),
            }
        )

    # Audit log every recalculation — required by spec
    audit_log(
        action="BASELINE_RECALC",
        ip="-",
        condition=f"hour={current_hour} samples={len(values)}",
        rate=mu,
        baseline=mu,
        duration=f"stddev={sd:.4f}",
    )


def _background_recalc() -> None:
    while True:
        time.sleep(RECALC_INTERVAL)
        try:
            _recalc()
        except Exception as exc:
            print(f"[baseline] recalc error: {exc}", flush=True)


def record(req_per_second: float, error_per_second: float = 0.0) -> None:
    """Called once per second by main.py."""
    now = time.time()
    hour = int(time.strftime("%H"))
    max_per_hour = BASELINE_WINDOW_SECONDS * 4
    with _lock:
        _counts.append((now, req_per_second))
        _error_counts.append((now, error_per_second))
        _hour_slots[hour].append(req_per_second)
        _error_hour_slots[hour].append(error_per_second)
        if len(_hour_slots[hour]) > max_per_hour:
            _hour_slots[hour] = _hour_slots[hour][-max_per_hour:]
        if len(_error_hour_slots[hour]) > max_per_hour:
            _error_hour_slots[hour] = _error_hour_slots[hour][-max_per_hour:]


def get_stats() -> dict:
    with _lock:
        return dict(stats)


def start() -> None:
    t = threading.Thread(target=_background_recalc, daemon=True, name="baseline-recalc")
    t.start()
    threading.Timer(5.0, _recalc).start()
