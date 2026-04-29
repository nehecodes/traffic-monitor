"""
blocker.py — Per-IP iptables blocking with tiered ban-state tracking.

Ban schedule (minutes): 10 → 30 → 120 → permanent
Each re-offense advances one tier. Tier history is kept in a separate
dict so the active-ban lookup stays clean.
"""

import subprocess
import threading
import time

BAN_SCHEDULE_MINUTES = [10, 30, 120]

# IPs that are never blocked — populated from config.yaml by main.py
WHITELIST: set[str] = set()

# Active bans:  ip → {tier, banned_at, unban_at, permanent}
_bans: dict[str, dict] = {}
# Tier memory:  ip → next_tier (persists across unban/reban cycles)
_tier_memory: dict[str, int] = {}
_lock = threading.Lock()


# ── iptables ──────────────────────────────────────────────────────────────────


def _iptables(action: str, ip: str) -> None:
    flag = "-I" if action == "add" else "-D"
    try:
        result = subprocess.run(
            ["iptables", flag, "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            print(
                f"[blocker] iptables error: {result.stderr.decode().strip()}",
                flush=True,
            )
        else:
            print(f"[blocker] iptables {action} {ip} OK", flush=True)
    except (subprocess.SubprocessError, FileNotFoundError) as exc:
        print(f"[blocker] iptables unavailable: {exc}", flush=True)


# ── Public API ────────────────────────────────────────────────────────────────


def is_blocked(ip: str) -> bool:
    with _lock:
        return ip in _bans


def block(ip: str) -> int:
    """
    Add iptables DROP rule. Returns ban duration in minutes (0 = permanent).
    Idempotent — if already blocked, returns 0 without re-blocking.
    Whitelisted IPs are silently skipped.
    """
    if ip in WHITELIST:
        print(f"[blocker] skipping whitelisted IP {ip}", flush=True)
        return 0

    with _lock:
        if ip in _bans:
            return 0

        tier = _tier_memory.get(ip, 0)
        now = time.time()

        if tier >= len(BAN_SCHEDULE_MINUTES):
            duration_minutes = None
        else:
            duration_minutes = BAN_SCHEDULE_MINUTES[tier]

        _bans[ip] = {
            "tier": tier,
            "banned_at": now,
            "unban_at": (now + duration_minutes * 60) if duration_minutes else None,
            "permanent": duration_minutes is None,
        }

    _iptables("add", ip)
    return duration_minutes or 0


def unblock(ip: str) -> dict | None:
    """
    Remove iptables rule and advance tier memory for next offence.
    Returns the completed ban record, or None if IP wasn't blocked.
    """
    with _lock:
        if ip not in _bans:
            return None
        record = _bans.pop(ip)
        _tier_memory[ip] = record["tier"] + 1

    _iptables("remove", ip)
    return record


def get_bans() -> list[dict]:
    now = time.time()
    with _lock:
        result = []
        for ip, info in _bans.items():
            remaining = None
            if info["unban_at"] is not None:
                remaining = max(0, int(info["unban_at"] - now))
            result.append(
                {
                    "ip": ip,
                    "banned_at": info["banned_at"],
                    "tier": info["tier"],
                    "permanent": info["permanent"],
                    "remaining_seconds": remaining,
                }
            )
        return result


def due_unbans() -> list[str]:
    now = time.time()
    with _lock:
        return [
            ip
            for ip, info in _bans.items()
            if not info["permanent"]
            and info["unban_at"] is not None
            and info["unban_at"] <= now
        ]
