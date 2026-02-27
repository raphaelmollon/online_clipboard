"""
session.py — Session management backed by Redis
================================================

Redis key schema:
  session:{sid}:meta          HASH   { has_password, created_at, locked }
  session:{sid}:items         LIST   [ token, token, ... ]  (encrypted)
  session:{sid}:failed        STRING  integer counter
  session:{sid}:locked        STRING  "1"  (permanent lock flag)

TTL policy (Option B — sliding, activity-only):
  _refresh_ttl() is called ONLY on real user actions (create, add_item, auth).
  Heartbeats and reads do NOT refresh the TTL.
  This means an idle session expires even if a browser tab stays open.

Pub/Sub:
  When an item is added, we publish to channel "session:{sid}:notify".
  SSE connections subscribe to this channel to push live updates to browsers.
"""

import time
from typing import Optional, AsyncIterator

import redis.asyncio as aioredis

from config import (
    REDIS_URL,
    SESSION_TTL_SECONDS,
    SESSION_MAX_FAILED_ATTEMPTS,
)
from crypto import encrypt, decrypt, generate_session_id


# ---------------------------------------------------------------------------
# Redis connection (module-level, reused across requests)
# ---------------------------------------------------------------------------

_redis: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    return _redis


async def close_redis() -> None:
    global _redis
    if _redis:
        await _redis.aclose()
        _redis = None


def _channel(sid: str) -> str:
    """Redis pub/sub channel name for a session."""
    return f"session:{sid}:notify"


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _key_meta(sid: str)   -> str: return f"session:{sid}:meta"
def _key_items(sid: str)  -> str: return f"session:{sid}:items"
def _key_failed(sid: str) -> str: return f"session:{sid}:failed"
def _key_locked(sid: str) -> str: return f"session:{sid}:locked"


async def _refresh_ttl(r: aioredis.Redis, sid: str) -> None:
    """Reset the 2-hour sliding TTL on all keys for this session."""
    for key in (_key_meta(sid), _key_items(sid), _key_failed(sid)):
        await r.expire(key, SESSION_TTL_SECONDS)


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------

async def create_session(
    first_item: str,
    password: str,
    secure_mode: bool = False,
) -> str:
    """
    Create a new session with the first clipboard item already encrypted.

    Returns the new session ID.
    Retries up to 5 times if the generated ID is already in use.
    """
    r = await get_redis()

    for _ in range(5):
        sid = generate_session_id(secure_mode=secure_mode)

        # Atomic check-and-set: only create if meta key doesn't exist
        meta = {
            "has_password": "1" if password else "0",
            "created_at": str(int(time.time())),
        }

        # Use a pipeline for atomicity
        async with r.pipeline(transaction=True) as pipe:
            pipe.hsetnx(_key_meta(sid), "has_password", meta["has_password"])
            pipe.hsetnx(_key_meta(sid), "created_at",   meta["created_at"])
            results = await pipe.execute()

        if not results[0]:
            # ID collision — try again
            continue

        # Encrypt and store the first item
        token = encrypt(first_item, sid, password)
        await r.rpush(_key_items(sid), token)
        await _refresh_ttl(r, sid)

        return sid

    raise RuntimeError("Could not generate a unique session ID after 5 attempts.")


async def session_exists(sid: str) -> bool:
    r = await get_redis()
    return bool(await r.exists(_key_meta(sid)))


async def session_is_locked(sid: str) -> bool:
    r = await get_redis()
    return bool(await r.exists(_key_locked(sid)))


async def session_has_password(sid: str) -> bool:
    r = await get_redis()
    val = await r.hget(_key_meta(sid), "has_password")
    return val == "1"


async def lock_session_forever(sid: str) -> None:
    """Lock a session permanently (e.g. after brute-force detected)."""
    r = await get_redis()
    # Keep the locked marker for 48h so we can show the warning
    await r.set(_key_locked(sid), "1", ex=SESSION_TTL_SECONDS * 24)
    # Wipe actual data immediately
    await r.delete(_key_items(sid), _key_failed(sid), _key_meta(sid))


async def delete_session(sid: str, wiped: bool = False) -> None:
    """
    Delete all data for a session.
    wiped=True: manual wipe by the user — publishes session_wiped event
                so other connected browsers show the right message.
    wiped=False: normal TTL expiry path.
    """
    r = await get_redis()
    if wiped:
        # Notify before deleting so SSE subscribers still receive it
        await r.publish(_channel(sid), "session_wiped")
    await r.delete(
        _key_meta(sid),
        _key_items(sid),
        _key_failed(sid),
        _key_locked(sid),
    )


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

async def verify_password(sid: str, password: str) -> bool:
    """
    Attempt to decrypt the first stored item to verify the password.
    Increments the failure counter on wrong password.
    Locks the session after too many failures.

    Returns True if password is correct (or session has no password).
    """
    r = await get_redis()

    if await session_is_locked(sid):
        return False

    has_pwd = await session_has_password(sid)

    # No password set: only empty string accepted.
    # A non-empty submission is treated as wrong password — prevents
    # an attacker from learning whether a session has a password or not.
    if not has_pwd:
        if password != "":
            failures = await r.incr(_key_failed(sid))
            await r.expire(_key_failed(sid), SESSION_TTL_SECONDS)
            if failures >= SESSION_MAX_FAILED_ATTEMPTS:
                await lock_session_forever(sid)
            return False
        return True

    # Try decrypting the first item as proof
    first_token = await r.lindex(_key_items(sid), 0)
    if not first_token:
        return False

    try:
        decrypt(first_token, sid, password)
        # Success — reset failure counter
        await r.delete(_key_failed(sid))
        return True
    except Exception:
        # Wrong password — increment failure counter
        failures = await r.incr(_key_failed(sid))
        await r.expire(_key_failed(sid), SESSION_TTL_SECONDS)

        if failures >= SESSION_MAX_FAILED_ATTEMPTS:
            await lock_session_forever(sid)

        return False


# ---------------------------------------------------------------------------
# Data operations
# ---------------------------------------------------------------------------

async def add_item(sid: str, plaintext: str, password: str) -> None:
    """
    Encrypt and append a new item to the session.
    Refreshes TTL (real user activity) and publishes a notification
    so all connected SSE clients update in real time.
    """
    r = await get_redis()
    token = encrypt(plaintext, sid, password)
    await r.rpush(_key_items(sid), token)
    await _refresh_ttl(r, sid)
    # Notify all SSE subscribers for this session
    await r.publish(_channel(sid), "new_item")


async def get_items(sid: str, password: str) -> list[str]:
    """
    Retrieve and decrypt all items for a session.

    NOTE: does NOT refresh the TTL — reads are not considered activity.
    Only writes (add_item) and auth extend the session lifetime.
    """
    r = await get_redis()
    tokens = await r.lrange(_key_items(sid), 0, -1)

    results = []
    for token in tokens:
        try:
            results.append(decrypt(token, sid, password))
        except Exception:
            pass  # Corrupted or tampered item — skip silently

    return results


async def get_item_count(sid: str) -> int:
    """Return the number of items stored for a session (no TTL refresh)."""
    r = await get_redis()
    return await r.llen(_key_items(sid))


async def subscribe_to_session(sid: str) -> AsyncIterator[str]:
    """
    Async generator that yields events published to a session channel.
    Used by the SSE endpoint. Each yield is a raw message string.

    The generator exits when the session no longer exists (expired/locked),
    allowing the SSE connection to close cleanly.
    """
    # Each SSE connection needs its own Redis connection for pub/sub
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe(_channel(sid))

    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                yield message["data"]

            # Check if session still alive (heartbeat-triggered check)
            if not await session_exists(sid):
                yield "session_expired"
                break

            if await session_is_locked(sid):
                yield "session_locked"
                break
    finally:
        await pubsub.unsubscribe(_channel(sid))
        await r.aclose()


async def get_failed_attempts(sid: str) -> int:
    r = await get_redis()
    val = await r.get(_key_failed(sid))
    return int(val) if val else 0
