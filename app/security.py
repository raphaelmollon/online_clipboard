"""
security.py — IP-based rate limiting and ban management
=========================================================

Redis key schema:
  ratelimit:{ip}:attempts     STRING  integer (expires after window)
  ratelimit:{ip}:tempbans     STRING  integer (number of temp bans received)
  ratelimit:{ip}:banned       STRING  "temp" or "perm" (expiry = ban duration)
"""

from config import (
    RATE_LIMIT_MAX_ATTEMPTS,
    RATE_LIMIT_WINDOW_SECONDS,
    RATE_LIMIT_BAN_SECONDS,
    RATE_LIMIT_PERM_BAN_THRESHOLD,
)
from session import get_redis


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _key_attempts(ip: str) -> str: return f"ratelimit:{ip}:attempts"
def _key_tempbans(ip: str) -> str: return f"ratelimit:{ip}:tempbans"
def _key_banned(ip: str)   -> str: return f"ratelimit:{ip}:banned"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def is_banned(ip: str) -> tuple[bool, str]:
    """
    Returns (is_banned, ban_type) where ban_type is "temp", "perm", or "".
    """
    r = await get_redis()
    status = await r.get(_key_banned(ip))
    if status:
        return True, status
    return False, ""


async def check_and_record_attempt(ip: str) -> tuple[bool, str]:
    """
    Record a failed auth attempt for this IP.
    Returns (is_now_banned, ban_type).

    Call this ONLY on authentication failures.
    """
    r = await get_redis()

    # Increment attempt counter within the window
    attempts = await r.incr(_key_attempts(ip))
    if attempts == 1:
        await r.expire(_key_attempts(ip), RATE_LIMIT_WINDOW_SECONDS)

    if attempts < RATE_LIMIT_MAX_ATTEMPTS:
        return False, ""

    # Threshold reached — apply temporary ban
    tempbans = await r.incr(_key_tempbans(ip))

    if tempbans >= RATE_LIMIT_PERM_BAN_THRESHOLD:
        # Escalate to permanent ban
        await r.set(_key_banned(ip), "perm")
        # No expiry = permanent
        await r.delete(_key_attempts(ip))
        return True, "perm"
    else:
        # Temporary ban
        await r.set(_key_banned(ip), "temp", ex=RATE_LIMIT_BAN_SECONDS)
        await r.delete(_key_attempts(ip))
        return True, "temp"


async def record_success(ip: str) -> None:
    """Reset the attempt counter on successful authentication."""
    r = await get_redis()
    await r.delete(_key_attempts(ip))


async def get_attempts_remaining(ip: str) -> int:
    """How many failed attempts before a ban kicks in."""
    r = await get_redis()
    val = await r.get(_key_attempts(ip))
    used = int(val) if val else 0
    return max(0, RATE_LIMIT_MAX_ATTEMPTS - used)
