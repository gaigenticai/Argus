"""Typed AppSetting accessor.

The detector / scoring code never reads ``AppSetting`` rows directly.
It calls ``get_setting(db, key, default=…, cast=…)`` and gets a typed
value back, falling back to the in-code default when no row exists.
This means every magic number that the audit flagged ("0.4 fraud
threshold", "0.85 impersonation cutoff", "PILLAR_WEIGHTS dict") can be
live-edited from the dashboard, and a fresh install with no config
still works because the defaults ship in code.

The first time a key is read with no row, we *create* the row with
the default — so the dashboard immediately shows the live value.
``get_settings(db, prefix=…)`` is a bulk read for editor pages.

Caching: per-process LRU keyed by ``(org_id, key)`` with a short TTL
(60 seconds). Invalidated on every write.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Callable, TypeVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.admin import AppSetting, AppSettingCategory, AppSettingType


T = TypeVar("T")

_CACHE_TTL_SECONDS = 60.0
_cache: dict[tuple[uuid.UUID, str], tuple[float, Any]] = {}
_cache_lock = asyncio.Lock()


def _is_fresh(entry: tuple[float, Any]) -> bool:
    return (time.monotonic() - entry[0]) < _CACHE_TTL_SECONDS


def _coerce(value_type: str, value: Any) -> Any:
    if value is None:
        return None
    if value_type == AppSettingType.STRING.value:
        return str(value)
    if value_type == AppSettingType.INTEGER.value:
        return int(value)
    if value_type == AppSettingType.FLOAT.value:
        return float(value)
    if value_type == AppSettingType.BOOLEAN.value:
        return bool(value)
    return value


async def get_setting(
    db: AsyncSession,
    organization_id: uuid.UUID,
    key: str,
    *,
    default: T,
    value_type: str | None = None,
    category: str = AppSettingCategory.GENERAL.value,
    description: str | None = None,
) -> T:
    """Return the live value for ``key`` or auto-create with ``default``.

    On first read for a key, a row is inserted with the supplied
    default and ``value_type`` (inferred from the default if not
    given). Subsequent reads hit the cache.
    """
    cache_key = (organization_id, key)
    cached = _cache.get(cache_key)
    if cached and _is_fresh(cached):
        return cached[1]

    async with _cache_lock:
        cached = _cache.get(cache_key)
        if cached and _is_fresh(cached):
            return cached[1]

        row = (
            await db.execute(
                select(AppSetting).where(
                    AppSetting.organization_id == organization_id,
                    AppSetting.key == key,
                )
            )
        ).scalar_one_or_none()

        if row is not None:
            coerced = _coerce(row.value_type, row.value)
            _cache[cache_key] = (time.monotonic(), coerced)
            return coerced

        # First-touch: persist the default so the dashboard reflects it.
        inferred_type = value_type or _infer_value_type(default)
        new_row = AppSetting(
            organization_id=organization_id,
            key=key,
            category=category,
            value_type=inferred_type,
            value=default,
            description=description,
        )
        db.add(new_row)
        await db.flush()
        _cache[cache_key] = (time.monotonic(), default)
        return default


async def set_setting(
    db: AsyncSession,
    organization_id: uuid.UUID,
    key: str,
    value: Any,
    *,
    value_type: str | None = None,
    category: str = AppSettingCategory.GENERAL.value,
    description: str | None = None,
    minimum: float | None = None,
    maximum: float | None = None,
) -> AppSetting:
    """Upsert a setting and invalidate the cache."""
    row = (
        await db.execute(
            select(AppSetting).where(
                AppSetting.organization_id == organization_id,
                AppSetting.key == key,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = AppSetting(
            organization_id=organization_id,
            key=key,
            category=category,
            value_type=value_type or _infer_value_type(value),
            value=value,
            description=description,
            minimum=minimum,
            maximum=maximum,
        )
        db.add(row)
    else:
        row.value = value
        if value_type is not None:
            row.value_type = value_type
        if description is not None:
            row.description = description
        if minimum is not None:
            row.minimum = minimum
        if maximum is not None:
            row.maximum = maximum
        if category is not None:
            row.category = category
    await db.flush()
    _cache.pop((organization_id, key), None)
    return row


async def list_settings(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    category: str | None = None,
) -> list[AppSetting]:
    query = select(AppSetting).where(AppSetting.organization_id == organization_id)
    if category:
        query = query.where(AppSetting.category == category)
    query = query.order_by(AppSetting.category, AppSetting.key)
    return list((await db.execute(query)).scalars().all())


def invalidate_cache(organization_id: uuid.UUID | None = None) -> None:
    """Clear cache; pass ``organization_id`` to scope, omit to flush all."""
    if organization_id is None:
        _cache.clear()
        return
    keys = [k for k in _cache.keys() if k[0] == organization_id]
    for k in keys:
        _cache.pop(k, None)


def _infer_value_type(value: Any) -> str:
    if isinstance(value, bool):
        return AppSettingType.BOOLEAN.value
    if isinstance(value, int):
        return AppSettingType.INTEGER.value
    if isinstance(value, float):
        return AppSettingType.FLOAT.value
    if isinstance(value, str):
        return AppSettingType.STRING.value
    return AppSettingType.JSON.value


__all__ = [
    "get_setting",
    "set_setting",
    "list_settings",
    "invalidate_cache",
]
