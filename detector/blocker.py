"""
blocker.py — Per-IP iptables blocking with tiered ban-state tracking.

Ban schedule (minutes): 10 → 30 → 120 → permanent
Each re-offense advances one tier. Tier history is kept in a separate
dict so the active-ban lookup stays clean.

Error handling: iptables failures trigger retries with exponential backoff.
State consistency: ban state is only updated after successful iptables execution.
"""

import subprocess
import threading
import time
from typing import Optional

BAN_SCHEDULE_MINUTES = [10, 30, 120]

# IPs that are never blocked — populated from config.yaml by main.py
WHITELIST: set[str] = set()

# Active bans:  ip → {tier, banned_at, unban_at, permanent}
_bans: dict[str, dict] = {}
# Tier memory:  ip → next_tier (persists across unban/reban cycles)
_tier_memory: dict[str, int] = {}
_lock = threading.Lock()


# ── Custom Exceptions ─────────────────────────────────────────────────────────


class IptablesError(Exception):
    """Raised when iptables command fails after all retries."""
    pass


# ── iptables with retry logic ─────────────────────────────────────────────────


def _iptables(action: str, ip: str, max_retries: int = 3) -> None:
    """
    Execute iptables command with retry logic.
    
    Args:
        action: "add" to block, "remove" to unblock
        ip: IP address to block/unblock
        max_retries: Number of retry attempts (default: 3)
        
    Raises:
        IptablesError: If command fails after all retries
    """
    flag = "-I" if action == "add" else "-D"
    cmd = ["iptables", flag, "INPUT", "-s", ip, "-j", "DROP"]
    
    for attempt in range(1, max_retries + 1):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=5,
                check=False,
            )
            
            if result.returncode == 0:
                print(f"[blocker] iptables {action} {ip} OK", flush=True)
                return
            
            # Handle specific error cases
            stderr = result.stderr.decode().strip()
            
            # If removing a non-existent rule, treat as success
            if action == "remove" and "No chain/target/match" in stderr:
                print(f"[blocker] iptables {action} {ip} (already removed)", flush=True)
                return
            
            # If adding a duplicate rule, treat as success
            if action == "add" and "already exists" in stderr.lower():
                print(f"[blocker] iptables {action} {ip} (already exists)", flush=True)
                return
            
            # Log error and retry
            print(
                f"[blocker] iptables {action} {ip} failed (attempt {attempt}/{max_retries}): {stderr}",
                flush=True,
            )
            
            if attempt < max_retries:
                # Exponential backoff: 0.5s, 1s, 2s
                backoff = 0.5 * (2 ** (attempt - 1))
                time.sleep(backoff)
            
        except subprocess.TimeoutExpired:
            print(
                f"[blocker] iptables {action} {ip} timeout (attempt {attempt}/{max_retries})",
                flush=True,
            )
            if attempt < max_retries:
                time.sleep(0.5 * (2 ** (attempt - 1)))
        
        except FileNotFoundError:
            # iptables not available on this system
            raise IptablesError(
                f"iptables command not found. Cannot {action} IP {ip}. "
                "Ensure iptables is installed and accessible."
            )
        
        except Exception as e:
            print(
                f"[blocker] iptables {action} {ip} unexpected error: {e}",
                flush=True,
            )
            if attempt < max_retries:
                time.sleep(0.5 * (2 ** (attempt - 1)))
    
    # All retries exhausted
    raise IptablesError(
        f"iptables {action} failed for IP {ip} after {max_retries} attempts"
    )


# ── Public API ────────────────────────────────────────────────────────────────


def is_blocked(ip: str) -> bool:
    with _lock:
        return ip in _bans


def block(ip: str) -> Optional[int]:
    """
    Add iptables DROP rule. Returns ban duration in minutes (None = permanent).
    
    Args:
        ip: IP address to block
        
    Returns:
        Ban duration in minutes, or None for permanent ban
        Returns 0 if IP is whitelisted
        
    Raises:
        IptablesError: If iptables command fails after retries
        
    State consistency: ban state is only updated after successful iptables execution.
    Idempotent: if already blocked, returns existing duration without re-blocking.
    """
    if ip in WHITELIST:
        print(f"[blocker] skipping whitelisted IP {ip}", flush=True)
        return 0

    with _lock:
        if ip in _bans:
            # Already blocked, return existing duration
            info = _bans[ip]
            if info["permanent"]:
                return None
            return BAN_SCHEDULE_MINUTES[info["tier"]]

        tier = _tier_memory.get(ip, 0)

    # Execute iptables BEFORE updating state
    try:
        _iptables("add", ip)
    except IptablesError as e:
        print(f"[blocker] CRITICAL: Failed to block IP {ip}: {e}", flush=True)
        # Do NOT update ban state if iptables failed
        raise

    # Only update state after successful iptables execution
    now = time.time()
    
    if tier >= len(BAN_SCHEDULE_MINUTES):
        duration_minutes = None
    else:
        duration_minutes = BAN_SCHEDULE_MINUTES[tier]

    with _lock:
        _bans[ip] = {
            "tier": tier,
            "banned_at": now,
            "unban_at": (now + duration_minutes * 60) if duration_minutes else None,
            "permanent": duration_minutes is None,
        }

    return duration_minutes


def unblock(ip: str) -> Optional[dict]:
    """
    Remove iptables rule and advance tier memory for next offence.
    
    Args:
        ip: IP address to unblock
        
    Returns:
        The completed ban record dict, or None if IP wasn't blocked
        
    State consistency: if iptables removal fails, state is rolled back.
    """
    with _lock:
        if ip not in _bans:
            return None
        record = _bans.pop(ip)
        original_tier = record["tier"]

    # Execute iptables removal
    try:
        _iptables("remove", ip)
    except IptablesError as e:
        print(f"[blocker] CRITICAL: Failed to unblock IP {ip}: {e}", flush=True)
        # Rollback: restore ban state
        with _lock:
            _bans[ip] = record
        raise

    # Only advance tier after successful iptables removal
    with _lock:
        _tier_memory[ip] = original_tier + 1

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
