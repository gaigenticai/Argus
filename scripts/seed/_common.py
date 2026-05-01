"""Shared seed helpers — idempotency, deterministic randomness, logging."""

from __future__ import annotations

import hashlib
import logging
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


# Deterministic RNG seeded so the realistic dataset is reproducible across
# fresh installs. Demos should not see different values on every restart.
SEED_RNG_SEED = 0xA86_5_AE_2026
rng = random.Random(SEED_RNG_SEED)


logger = logging.getLogger("argus.seed")
if not logger.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("[seed] %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)


def now() -> datetime:
    """UTC `now`, frozen-style — the realistic dataset uses ``ago()`` to
    produce backdated rows so charts and "last 30 days" filters look real."""
    return datetime.now(timezone.utc)


def ago(*, days: int = 0, hours: int = 0, minutes: int = 0) -> datetime:
    return now() - timedelta(days=days, hours=hours, minutes=minutes)


def deterministic_uuid(*parts: str) -> uuid.UUID:
    """Stable UUID from a tuple of strings. Use for fixtures that need the
    same id across re-seeds (e.g. global MITRE techniques)."""
    h = hashlib.sha256(":".join(parts).encode()).hexdigest()
    return uuid.UUID(h[:32])


def fake_sha256(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def fake_md5(seed: str) -> str:
    return hashlib.md5(seed.encode()).hexdigest()


async def already_seeded(
    session: AsyncSession, model: Any, *, where: Any = None
) -> bool:
    """Cheap existence check — returns True if at least one row matches."""
    stmt = select(model.id)
    if where is not None:
        stmt = stmt.where(where)
    res = await session.execute(stmt.limit(1))
    return res.scalar_one_or_none() is not None


def section(label: str):
    """Decorator stamping section start/finish in the seed log so a long
    realistic run shows progress instead of a silent multi-minute wait."""

    def deco(fn):
        async def wrapper(*args, **kwargs):
            logger.info(f"  · {label}")
            try:
                result = await fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001
                logger.error(f"    ✗ {label} failed: {type(exc).__name__}: {exc}")
                raise
            return result

        return wrapper

    return deco
