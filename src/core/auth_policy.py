"""Password complexity + account lockout (Audit D9).

The lockout uses the same Redis pool the rate-limiter does, so a
multi-process deploy shares state. If Redis is unavailable we used
to fail open; adversarial audit D-12 flagged that as a brute-force
escape hatch, so we now fall back to a per-process in-memory
counter and emit a SECURITY warning. The single-process bucket
won't catch a coordinated attack across multiple API workers, but
it is strictly stronger than fail-open and lets ops see the
degradation in JSON logs.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Final

from src.core.rate_limit import _get_redis

_logger = logging.getLogger(__name__)


# --- Password complexity ----------------------------------------------

MIN_LENGTH: Final = 12
_LOWER = re.compile(r"[a-z]")
_UPPER = re.compile(r"[A-Z]")
_DIGIT = re.compile(r"\d")
_SPECIAL = re.compile(r"[^A-Za-z0-9]")


class WeakPasswordError(ValueError):
    """Raised when a password fails the complexity policy."""


def validate_password_complexity(password: str) -> None:
    """Enforce: ≥12 chars, mixed case, ≥1 digit, ≥1 special.

    Raises ``WeakPasswordError`` with a single descriptive message
    suitable to surface to the user via 422.
    """
    if not isinstance(password, str):
        raise WeakPasswordError("password must be a string")
    if len(password) < MIN_LENGTH:
        raise WeakPasswordError(
            f"password must be at least {MIN_LENGTH} characters"
        )
    missing = []
    if not _LOWER.search(password):
        missing.append("lowercase letter")
    if not _UPPER.search(password):
        missing.append("uppercase letter")
    if not _DIGIT.search(password):
        missing.append("digit")
    if not _SPECIAL.search(password):
        missing.append("special character")
    if missing:
        raise WeakPasswordError(
            "password must include: " + ", ".join(missing)
        )


# --- Account lockout --------------------------------------------------

LOCKOUT_THRESHOLD: Final = 5
LOCKOUT_WINDOW_SECONDS: Final = 15 * 60  # 15 minutes


def _key(email: str) -> str:
    return f"argus:login_fail:{email.strip().lower()}"


# Adversarial audit D-12 — per-process fallback used only when Redis is
# unavailable. State is keyed by lowercase email; values are
# (count, expiry_unix). The lock prevents a torn read between an incr
# and an expiry sweep.
_FALLBACK_LOCK = asyncio.Lock()
_FALLBACK_COUNTERS: dict[str, tuple[int, float]] = {}


def _now() -> float:
    return time.time()


async def _fallback_get(email: str) -> int:
    async with _FALLBACK_LOCK:
        rec = _FALLBACK_COUNTERS.get(email.strip().lower())
        if rec is None:
            return 0
        count, expiry = rec
        if expiry < _now():
            _FALLBACK_COUNTERS.pop(email.strip().lower(), None)
            return 0
        return count


async def _fallback_incr(email: str) -> int:
    async with _FALLBACK_LOCK:
        key = email.strip().lower()
        rec = _FALLBACK_COUNTERS.get(key)
        now = _now()
        if rec is None or rec[1] < now:
            _FALLBACK_COUNTERS[key] = (1, now + LOCKOUT_WINDOW_SECONDS)
            return 1
        count, expiry = rec
        _FALLBACK_COUNTERS[key] = (count + 1, expiry)
        return count + 1


async def _fallback_clear(email: str) -> None:
    async with _FALLBACK_LOCK:
        _FALLBACK_COUNTERS.pop(email.strip().lower(), None)


def _warn_redis_outage() -> None:
    _logger.warning(
        "SECURITY: auth_policy lockout running on in-process fallback "
        "(Redis unreachable). Coordinated brute-force across multiple "
        "API workers may slip through until Redis recovers."
    )


async def is_account_locked(email: str) -> bool:
    """Return True if this email has hit the lockout threshold within
    the current window. Falls back to a per-process counter when Redis
    is unreachable (adversarial audit D-12)."""
    rds = await _get_redis()
    if rds is None:
        _warn_redis_outage()
        return await _fallback_get(email) >= LOCKOUT_THRESHOLD
    try:
        v = await rds.get(_key(email))
        return v is not None and int(v) >= LOCKOUT_THRESHOLD
    except Exception:  # noqa: BLE001
        _warn_redis_outage()
        return await _fallback_get(email) >= LOCKOUT_THRESHOLD


async def record_failed_login(email: str) -> int:
    """Increment the failure counter and return the new count. The key
    expires after ``LOCKOUT_WINDOW_SECONDS`` so the lockout auto-lifts
    without admin intervention."""
    rds = await _get_redis()
    if rds is None:
        _warn_redis_outage()
        return await _fallback_incr(email)
    try:
        key = _key(email)
        count = await rds.incr(key)
        if count == 1:
            await rds.expire(key, LOCKOUT_WINDOW_SECONDS)
        return int(count)
    except Exception:  # noqa: BLE001
        _warn_redis_outage()
        return await _fallback_incr(email)


async def clear_failed_logins(email: str) -> None:
    rds = await _get_redis()
    if rds is None:
        await _fallback_clear(email)
        return
    try:
        await rds.delete(_key(email))
    except Exception as exc:  # noqa: BLE001
        # Best-effort cleanup — login already succeeded so the dangling
        # counter is harmless until the lockout window expires. We log
        # at WARNING (not ERROR) so a Redis blip during peak login
        # traffic doesn't drown the SOC, but it's still visible in JSON
        # log scans for "auth_policy" health checks.
        _logger.warning(
            "auth_policy: failed-login counter cleanup failed for %r: %s",
            email, exc,
        )
        await _fallback_clear(email)


__all__ = [
    "MIN_LENGTH",
    "LOCKOUT_THRESHOLD",
    "LOCKOUT_WINDOW_SECONDS",
    "WeakPasswordError",
    "validate_password_complexity",
    "is_account_locked",
    "record_failed_login",
    "clear_failed_logins",
]
