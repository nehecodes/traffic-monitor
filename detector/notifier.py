"""
notifier.py — Slack webhook alerts.

All outgoing alerts include: condition, rate, baseline, timestamp, and
ban duration where applicable. Alerts are dispatched in background
threads so they never block the detection loop.
"""

import threading
from datetime import datetime, timezone

import requests

_webhook_url: str = ""


def init(webhook_url: str) -> None:
    global _webhook_url
    _webhook_url = webhook_url


def _post(payload: dict) -> None:
    if not _webhook_url:
        print(f"[notifier] (no webhook) would send: {payload['text'][:120]}")
        return
    try:
        requests.post(_webhook_url, json=payload, timeout=8)
    except requests.RequestException as exc:
        print(f"[notifier] Slack error: {exc}")


def _send(text: str) -> None:
    t = threading.Thread(target=_post, args=({"text": text},), daemon=True)
    t.start()


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ──────────────────────────────────────────────
# Alert constructors
# ──────────────────────────────────────────────


def send_ip_alert(
    ip: str,
    condition: str,
    rate: float,
    baseline_mean: float,
    baseline_stddev: float,
    ban_duration_minutes: int,
) -> None:
    dur = f"{ban_duration_minutes} min" if ban_duration_minutes else "permanent"
    text = (
        f":rotating_light: *IP BLOCKED* `{ip}`\n"
        f">*Condition:* {condition}\n"
        f">*Rate:* {rate:.2f} req/s  |  *Baseline:* {baseline_mean:.2f} ± {baseline_stddev:.2f}\n"
        f">*Ban duration:* {dur}\n"
        f">*Time:* {_ts()}"
    )
    _send(text)


def send_global_alert(
    condition: str,
    rate: float,
    baseline_mean: float,
    baseline_stddev: float,
) -> None:
    text = (
        f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
        f">*Condition:* {condition}\n"
        f">*Rate:* {rate:.2f} req/s  |  *Baseline:* {baseline_mean:.2f} ± {baseline_stddev:.2f}\n"
        f">*Time:* {_ts()}"
    )
    _send(text)


def send_unban_alert(ip: str, tier: int, next_duration: str) -> None:
    text = (
        f":white_check_mark: *IP UNBANNED* `{ip}`\n"
        f">*Tier completed:* {tier}  |  *Next ban if re-offend:* {next_duration}\n"
        f">*Time:* {_ts()}"
    )
    _send(text)
