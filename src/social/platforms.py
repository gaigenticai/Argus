"""Runtime social-platform registry.

Backs the ``social_platforms`` table introduced by migration
``c3d4e5f6a7b8``. The Python ``SocialPlatform`` enum still exists in
``src.models.social`` as a list of the seed defaults, but production
code looks up platforms via this module so adding a new platform
(e.g. Threads, Lemmy, Nostr) is a runtime config change, not a code
deploy.

Surface:

    list_platforms(db, *, active_only=True)
        Return all rows, optionally filtered to active ones.

    get_platform(db, name)
        Look up by machine name; raises if missing.

    register_platform(db, name, label, scraper_module=None, ...)
        Insert a new platform; idempotent.

    is_known_platform(db, name)
        Cheap membership check used at API boundaries.

A small in-process cache (60 s TTL) keeps repeated lookups off the
DB. The cache is invalidated on every write through ``register_platform``
and ``set_platform_active``.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass
from typing import Iterable

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    String,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base, TimestampMixin, UUIDMixin


class SocialPlatformDef(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "social_platforms"

    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    scraper_module: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    config: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    __table_args__ = (
        Index("ix_social_platforms_name", "name"),
    )


@dataclass(frozen=True)
class PlatformInfo:
    id: uuid.UUID
    name: str
    label: str
    scraper_module: str | None
    is_active: bool
    config: dict


_CACHE_TTL_SECONDS = 60.0
_cache: tuple[float, dict[str, PlatformInfo]] | None = None
_cache_lock = asyncio.Lock()


def _from_row(row: SocialPlatformDef) -> PlatformInfo:
    return PlatformInfo(
        id=row.id,
        name=row.name,
        label=row.label,
        scraper_module=row.scraper_module,
        is_active=row.is_active,
        config=dict(row.config or {}),
    )


async def _refresh_cache(db: AsyncSession) -> dict[str, PlatformInfo]:
    rows = (await db.execute(select(SocialPlatformDef))).scalars().all()
    return {row.name: _from_row(row) for row in rows}


async def _ensure_fresh(db: AsyncSession) -> dict[str, PlatformInfo]:
    global _cache
    now = time.monotonic()
    cached = _cache
    if cached is not None and (now - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]
    async with _cache_lock:
        cached = _cache
        if cached is not None and (now - cached[0]) < _CACHE_TTL_SECONDS:
            return cached[1]
        fresh = await _refresh_cache(db)
        _cache = (now, fresh)
        return fresh


def invalidate_cache() -> None:
    global _cache
    _cache = None


# --- public surface ----------------------------------------------------


async def list_platforms(
    db: AsyncSession, *, active_only: bool = True
) -> list[PlatformInfo]:
    rows = await _ensure_fresh(db)
    items = list(rows.values())
    if active_only:
        items = [p for p in items if p.is_active]
    return sorted(items, key=lambda p: p.name)


async def get_platform(db: AsyncSession, name: str) -> PlatformInfo:
    rows = await _ensure_fresh(db)
    info = rows.get(name)
    if info is None:
        raise LookupError(f"unknown social platform: {name!r}")
    return info


async def is_known_platform(db: AsyncSession, name: str) -> bool:
    rows = await _ensure_fresh(db)
    return name in rows


async def register_platform(
    db: AsyncSession,
    name: str,
    label: str,
    *,
    scraper_module: str | None = None,
    config: dict | None = None,
    is_active: bool = True,
) -> PlatformInfo:
    """Idempotent insert. Returns the existing row if ``name`` already
    exists with matching label / scraper_module; raises if the existing
    row contradicts the supplied values."""
    name = name.strip().lower()
    if not name or not name.replace("_", "").replace("-", "").isalnum():
        raise ValueError(
            "Platform name must be alphanumeric (with optional - or _)."
        )

    existing = (
        await db.execute(
            select(SocialPlatformDef).where(SocialPlatformDef.name == name)
        )
    ).scalar_one_or_none()
    if existing is not None:
        # Idempotency check — refuse to silently overwrite a row.
        if existing.label != label or existing.scraper_module != scraper_module:
            raise ValueError(
                f"platform {name!r} already exists with different label / scraper. "
                f"Use update_platform() to change it explicitly."
            )
        return _from_row(existing)

    row = SocialPlatformDef(
        name=name,
        label=label,
        scraper_module=scraper_module,
        is_active=is_active,
        config=config or {},
    )
    db.add(row)
    await db.flush()
    invalidate_cache()
    return _from_row(row)


async def set_platform_active(
    db: AsyncSession, name: str, active: bool
) -> PlatformInfo:
    """Toggle ``is_active``. Returns the updated row."""
    await db.execute(
        update(SocialPlatformDef)
        .where(SocialPlatformDef.name == name)
        .values(is_active=active)
    )
    await db.flush()
    invalidate_cache()
    return await get_platform(db, name)


__all__ = [
    "PlatformInfo",
    "SocialPlatformDef",
    "list_platforms",
    "get_platform",
    "is_known_platform",
    "register_platform",
    "set_platform_active",
    "invalidate_cache",
]
