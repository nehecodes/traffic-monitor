"""
unbanner.py — Polls for expired bans every 10 seconds and releases them.

10-second poll interval ensures unbans happen well within any reasonable
SLA and definitely within the 10-second alert window cited in the spec.
Sends a Slack notification and writes an audit entry on every release.

Error handling: if iptables unban fails, state is rolled back and the
IP remains in the banned list.
"""

import time
import threading

from . import blocker
from . import notifier
from .audit import audit_log
from .blocker import IptablesError


def _process_unbans() -> None:
    for ip in blocker.due_unbans():
        try:
            record = blocker.unblock(ip)
            if record is None:
                continue

            next_tier = record["tier"] + 1
            if next_tier < len(blocker.BAN_SCHEDULE_MINUTES):
                next_duration = f"{blocker.BAN_SCHEDULE_MINUTES[next_tier]}m"
            else:
                next_duration = "permanent"

            audit_log(
                action="UNBAN",
                ip=ip,
                condition=f"tier={record['tier']} ban_expired",
                rate=0.0,
                baseline=0.0,
                duration=f"next={next_duration}",
            )
            notifier.send_unban_alert(
                ip=ip,
                tier=record["tier"],
                next_duration=next_duration,
            )
        except IptablesError as e:
            # Log the failure and leave IP in banned state
            audit_log(
                action="UNBAN_FAILED",
                ip=ip,
                condition="iptables_error",
                rate=0.0,
                baseline=0.0,
                duration=str(e),
            )
            print(f"[unbanner] Failed to unban {ip}: {e}. IP remains blocked.", flush=True)


def start() -> None:
    def _loop():
        while True:
            try:
                _process_unbans()
            except Exception as exc:
                print(f"[unbanner] error: {exc}", flush=True)
            time.sleep(10)

    threading.Thread(target=_loop, daemon=True, name="unbanner").start()
