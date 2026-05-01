"""Redis-backed sliding window rate limiter with in-memory fallback.

Uses Redis sorted sets (ZADD/ZRANGEBYSCORE) for distributed rate limiting
across multiple instances. Falls back to in-memory sliding window on Redis
connection failure, suitable for single-instance deployments.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level Redis connection pool (lazy singleton)
# ---------------------------------------------------------------------------
_redis_pool: "redis.asyncio.Redis | None" = None
_redis_pool_lock = asyncio.Lock()
_redis_unavailable: bool = False  # Flip once on first failure to avoid log spam


async def _get_redis() -> "redis.asyncio.Redis | None":
    """Return a shared Redis client, or None if Redis is unreachable."""
    global _redis_pool, _redis_unavailable

    if _redis_unavailable:
        return None

    if _redis_pool is not None:
        return _redis_pool

    async with _redis_pool_lock:
        # Double-check after acquiring lock
        if _redis_pool is not None:
            return _redis_pool
        if _redis_unavailable:
            return None

        try:
            import redis.asyncio as aioredis
            from src.config.settings import settings

            pool = aioredis.from_url(
                settings.redis.url,
                decode_responses=False,
                max_connections=20,
                socket_connect_timeout=3,
                socket_timeout=3,
                retry_on_timeout=False,
            )
            # Verify connectivity
            await pool.ping()
            _redis_pool = pool
            logger.info("Rate limiter connected to Redis at %s", settings.redis.url)
            return _redis_pool
        except Exception as exc:
            _redis_unavailable = True
            logger.warning(
                "Redis unavailable for rate limiting (%s). "
                "Falling back to in-memory rate limiter.",
                exc,
            )
            return None


# ---------------------------------------------------------------------------
# In-memory fallback structures
# ---------------------------------------------------------------------------

@dataclass
class _Window:
    timestamps: list[float] = field(default_factory=list)


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Sliding window rate limiter keyed by client IP.

    Attempts Redis-backed enforcement first. On any Redis failure the check
    transparently falls back to an in-memory sliding window for the current
    process.
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        name: str = "default",
    ) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.name = name

        # In-memory fallback state
        self._windows: dict[str, _Window] = defaultdict(_Window)
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _redis_key(self, client_ip: str) -> str:
        return f"argus:ratelimit:{self.name}:{client_ip}"

    # ------------------------------------------------------------------
    # Redis path
    # ------------------------------------------------------------------

    async def _check_redis(self, client_ip: str) -> bool:
        """Check and record a request via Redis sorted set.

        Returns True if the request is allowed, False if rate-limited.
        Raises on Redis errors so the caller can fall back.
        """
        rds = await _get_redis()
        if rds is None:
            raise RuntimeError("Redis not available")

        key = self._redis_key(client_ip)
        now = time.time()
        cutoff = now - self.window_seconds

        # Use a unique member to avoid collisions within the same millisecond.
        # Combining monotonic nanoseconds with wall-clock gives practical uniqueness.
        member = f"{now}:{time.monotonic_ns()}"

        pipe = rds.pipeline(transaction=True)
        # 0: Remove expired entries
        pipe.zremrangebyscore(key, 0, cutoff)
        # 1: Count remaining entries in the window (before adding new one)
        pipe.zcard(key)
        # 2: Add current request
        pipe.zadd(key, {member: now})
        # 3: Set key expiry for automatic cleanup
        pipe.expire(key, self.window_seconds + 10)

        results = await pipe.execute()
        current_count = results[1]  # zcard result — count BEFORE our addition

        if current_count >= self.max_requests:
            # Over limit — remove the entry we just optimistically added
            await rds.zrem(key, member)
            return False

        return True

    async def _get_retry_after_redis(self, client_ip: str) -> int:
        """Compute Retry-After from the oldest entry still in the Redis window."""
        rds = await _get_redis()
        if rds is None:
            return 1

        key = self._redis_key(client_ip)
        now = time.time()
        cutoff = now - self.window_seconds

        # Oldest entry still in the window determines when the first slot frees up
        oldest = await rds.zrangebyscore(key, cutoff, "+inf", start=0, num=1)
        if oldest:
            try:
                oldest_score_str = oldest[0].decode() if isinstance(oldest[0], bytes) else str(oldest[0])
                oldest_ts = float(oldest_score_str.split(":")[0])
                return max(1, int((oldest_ts + self.window_seconds) - now) + 1)
            except (ValueError, IndexError):
                pass
        return 1

    # ------------------------------------------------------------------
    # In-memory fallback path
    # ------------------------------------------------------------------

    async def _check_memory(self, client_ip: str) -> tuple[bool, int]:
        """In-memory sliding window check.

        Returns (allowed, retry_after_seconds).
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds

        async with self._lock:
            window = self._windows[client_ip]
            window.timestamps = [ts for ts in window.timestamps if ts > cutoff]

            if len(window.timestamps) >= self.max_requests:
                retry_after = int(window.timestamps[0] - cutoff) + 1
                return False, retry_after

            window.timestamps.append(now)
            return True, 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check(self, request: Request) -> None:
        """Check rate limit for the request. Raises 429 if exceeded."""
        client_ip = self._get_client_ip(request)

        # Try Redis first
        try:
            allowed = await self._check_redis(client_ip)
            if not allowed:
                retry_after = await self._get_retry_after_redis(client_ip)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Try again in {retry_after}s.",
                    headers={"Retry-After": str(retry_after)},
                )
            return
        except HTTPException:
            raise
        except Exception:
            # Redis failed at runtime — fall through to in-memory
            pass

        # In-memory fallback
        allowed, retry_after = await self._check_memory(client_ip)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Try again in {retry_after}s.",
                headers={"Retry-After": str(retry_after)},
            )

    async def check_for_key(self, key: str) -> None:
        """Variant of ``check`` that's keyed by an arbitrary string
        (typically a user id or API key prefix) rather than the client
        IP. Lets callers rate-limit a logged-in analyst across IPs."""
        try:
            allowed = await self._check_redis(key)
            if not allowed:
                retry_after = await self._get_retry_after_redis(key)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Try again in {retry_after}s.",
                    headers={"Retry-After": str(retry_after)},
                )
            return
        except HTTPException:
            raise
        except Exception:
            pass
        allowed, retry_after = await self._check_memory(key)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Try again in {retry_after}s.",
                headers={"Retry-After": str(retry_after)},
            )

    async def cleanup(self) -> None:
        """Remove stale in-memory entries. Call periodically to prevent memory growth.

        Redis keys auto-expire via EXPIRE, so this only cleans the fallback store.
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds * 2
        async with self._lock:
            stale_keys = [
                key
                for key, w in self._windows.items()
                if not w.timestamps or w.timestamps[-1] < cutoff
            ]
            for key in stale_keys:
                del self._windows[key]


async def close_redis_pool() -> None:
    """Gracefully close the Redis connection pool. Call on app shutdown."""
    global _redis_pool, _redis_unavailable
    if _redis_pool is not None:
        await _redis_pool.aclose()
        _redis_pool = None
    _redis_unavailable = False


# ---------------------------------------------------------------------------
# Pre-configured limiters
# ---------------------------------------------------------------------------
login_limiter = RateLimiter(max_requests=10, window_seconds=300, name="login")
register_limiter = RateLimiter(max_requests=5, window_seconds=3600, name="register")
api_limiter = RateLimiter(max_requests=100, window_seconds=60, name="api")

# Per-analyst limiter for sensitive operations that take SHA-1 password
# hashes / k-anon prefixes as input (P3 #3.9 audit). Keeps a
# single analyst with the API token from iterating through the
# corporate password set.
breach_password_limiter = RateLimiter(
    max_requests=20, window_seconds=60, name="breach_password",
)
