"""Async circuit breaker for outbound HTTP clients.

Argus calls many external services (notification webhooks, takedown
partners, threat-intel feeds, IP geolocation). A single misbehaving
upstream — wedged TCP, 5xx storm, DNS black-hole — shouldn't be allowed
to block a worker for 6+ seconds per call by burning the full retry
budget on every attempt.

This module provides a minimal three-state breaker:

    CLOSED      — calls flow through. On failure, increment counter.
                  When counter reaches ``fail_max``, transition to OPEN.
    OPEN        — calls fail fast with ``CircuitBreakerOpenError``.
                  After ``reset_timeout_s`` elapses, transition to
                  HALF_OPEN.
    HALF_OPEN   — exactly one probe call is allowed through. Success
                  closes the breaker; failure re-opens it for another
                  ``reset_timeout_s``.

Why hand-rolled instead of pybreaker / aiobreaker? Argus deliberately
keeps its dependency surface tight, and this is ~80 lines of standard
library code. The semantics here are deliberately conservative —
``CircuitBreakerOpenError`` is a normal Python exception so existing
``except Exception`` handlers in adapters degrade to the same
already-tested error path (recorded as failure_reason / error_message).
No adapter behaviour changes when the breaker is closed.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class _State(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpenError(Exception):
    """Raised when a call is rejected because the breaker is open."""

    def __init__(self, name: str, opened_at: float, reset_timeout_s: float):
        self.name = name
        self.opened_at = opened_at
        self.reset_timeout_s = reset_timeout_s
        remaining = max(0.0, (opened_at + reset_timeout_s) - time.monotonic())
        super().__init__(
            f"circuit '{name}' is open; retry in ~{remaining:.0f}s"
        )


@dataclass
class CircuitBreaker:
    """Async-safe circuit breaker keyed by ``name``.

    Construct via :func:`get_breaker` so identical names share state
    across coroutines and module imports.
    """

    name: str
    fail_max: int = 5
    reset_timeout_s: float = 60.0
    _state: _State = field(default=_State.CLOSED, init=False)
    _failures: int = field(default=0, init=False)
    _opened_at: float = field(default=0.0, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    @property
    def state(self) -> str:
        return self._state.value

    async def __aenter__(self) -> "CircuitBreaker":
        async with self._lock:
            if self._state is _State.OPEN:
                if (time.monotonic() - self._opened_at) >= self.reset_timeout_s:
                    self._state = _State.HALF_OPEN
                    logger.info("[circuit:%s] half-open trial", self.name)
                else:
                    raise CircuitBreakerOpenError(
                        self.name, self._opened_at, self.reset_timeout_s
                    )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        async with self._lock:
            if exc is None:
                if self._state is _State.HALF_OPEN:
                    logger.info("[circuit:%s] closed after probe success", self.name)
                self._state = _State.CLOSED
                self._failures = 0
                return False

            # CircuitBreakerOpenError is its own short-circuit; don't
            # double-count it as a real upstream failure.
            if isinstance(exc, CircuitBreakerOpenError):
                return False

            self._failures += 1
            if self._state is _State.HALF_OPEN or self._failures >= self.fail_max:
                if self._state is not _State.OPEN:
                    logger.warning(
                        "[circuit:%s] opened after %d failure(s); cooling for %.0fs",
                        self.name,
                        self._failures,
                        self.reset_timeout_s,
                    )
                self._state = _State.OPEN
                self._opened_at = time.monotonic()
        return False  # never suppress the original exception


_REGISTRY: dict[str, CircuitBreaker] = {}


def get_breaker(
    name: str,
    *,
    fail_max: int = 5,
    reset_timeout_s: float = 60.0,
) -> CircuitBreaker:
    """Fetch (or lazily create) the named breaker.

    Names are global — pass a stable identifier per upstream
    (``"netcraft"``, ``"jira"``, ``"feed:otx"``, ...). Once a breaker
    exists, the constructor parameters on subsequent calls are ignored
    so all callers observe the same state.
    """
    breaker = _REGISTRY.get(name)
    if breaker is None:
        breaker = CircuitBreaker(
            name=name, fail_max=fail_max, reset_timeout_s=reset_timeout_s
        )
        _REGISTRY[name] = breaker
    return breaker


def snapshot() -> list[dict[str, object]]:
    """Read-only view of every breaker's current state. For /health."""
    out: list[dict[str, object]] = []
    now = time.monotonic()
    for breaker in _REGISTRY.values():
        out.append(
            {
                "name": breaker.name,
                "state": breaker.state,
                "failures": breaker._failures,
                "fail_max": breaker.fail_max,
                "seconds_until_half_open": (
                    max(0.0, (breaker._opened_at + breaker.reset_timeout_s) - now)
                    if breaker.state == _State.OPEN.value
                    else 0.0
                ),
            }
        )
    return out
