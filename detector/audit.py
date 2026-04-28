"""
audit.py — Structured audit log.

Format: [timestamp] ACTION ip | condition | rate | baseline | duration

Actions logged: BAN, UNBAN, BASELINE_RECALC
"""

import os
import threading
from datetime import datetime, timezone

_log_path: str = "/var/log/detector/audit.log"
_lock = threading.Lock()


def init(log_path: str) -> None:
    global _log_path
    _log_path = log_path
    os.makedirs(os.path.dirname(log_path), exist_ok=True)


def audit_log(
    action: str,
    ip: str,
    condition: str,
    rate: float,
    baseline: float,
    duration: str,
) -> None:
    """
    Write one structured line. Always echoes to stdout for journald capture.

    Format: [timestamp] ACTION ip | condition | rate | baseline | duration
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = (
        f"[{ts}] {action} {ip} | {condition} | "
        f"rate={rate:.2f} | baseline={baseline:.2f} | {duration}\n"
    )
    print(line.rstrip(), flush=True)
    try:
        with _lock:
            with open(_log_path, "a") as f:
                f.write(line)
    except OSError as exc:
        print(f"[audit] cannot write log: {exc}", flush=True)
