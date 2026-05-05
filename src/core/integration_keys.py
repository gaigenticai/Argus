"""Process-wide cache for third-party integration API keys.

Operators set keys via ``Settings → Integrations`` in the dashboard,
which writes ``integration.<name>.api_key`` rows into ``app_settings``.
This module exposes a *synchronous* lookup so existing providers
(``HibpProvider``, ``urlscan.search_recent``, etc.) can keep their
sync ``__init__`` shape — they don't need to thread an async DB
session through every call site.

How it stays current:

  - On API boot and worker boot, ``start_refresh_loop()`` is launched
    as a background task that re-reads all ``category=integrations``
    settings every ``REFRESH_INTERVAL_S`` and rebuilds the in-process
    cache.
  - The admin settings PUT route also calls
    ``invalidate()`` so a saved key takes effect within a few seconds
    rather than a full minute later.
  - Until the first refresh completes, ``get()`` falls back to
    ``os.environ`` so ``.env``-only deployments keep working.

Resolution order for ``get(name, env_fallback="ARGUS_FOO_KEY")``:

  1. ``app_settings`` row keyed ``integration.<name>.api_key`` (DB).
  2. ``os.environ[env_fallback]`` (boot-time env var).
  3. ``None`` — caller treats provider as unconfigured.

This replaces the previous "edit ``.env`` and restart" loop with a
self-service rotation surface, which is what real customers expect.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

from sqlalchemy import select

from src.models.admin import AppSetting, AppSettingCategory
from src.storage import database as _db

_logger = logging.getLogger(__name__)

# Process-wide cache. Empty until first refresh completes. Reads fall
# back to env until then so we don't briefly look unconfigured at
# boot.
_cache: dict[str, str] = {}
_cache_lock = asyncio.Lock()
_first_refresh_done = asyncio.Event()

REFRESH_INTERVAL_S = 60
_INTEGRATION_PREFIX = "integration."
_KEY_SUFFIX = ".api_key"


def _strip_to_name(setting_key: str) -> Optional[str]:
    """``integration.hibp.api_key`` → ``hibp``. Returns None if the
    key isn't an integration key."""
    if not setting_key.startswith(_INTEGRATION_PREFIX):
        return None
    if not setting_key.endswith(_KEY_SUFFIX):
        return None
    return setting_key[
        len(_INTEGRATION_PREFIX): -len(_KEY_SUFFIX)
    ] or None


async def _refresh_once() -> None:
    if _db.async_session_factory is None:
        return
    async with _db.async_session_factory() as session:
        rows = (
            await session.execute(
                select(AppSetting).where(
                    AppSetting.category == AppSettingCategory.INTEGRATIONS.value
                )
            )
        ).scalars().all()
    fresh: dict[str, str] = {}
    for row in rows:
        name = _strip_to_name(row.key)
        if not name:
            continue
        value = row.value
        if isinstance(value, str) and value.strip():
            fresh[name] = value.strip()
    async with _cache_lock:
        _cache.clear()
        _cache.update(fresh)
    _first_refresh_done.set()


async def refresh_loop(stop_event: asyncio.Event) -> None:
    """Background task — loops until ``stop_event`` is set, refreshing
    the cache every ``REFRESH_INTERVAL_S`` seconds. Exceptions are
    logged but never propagate; integration keys are non-critical
    enough that a transient DB hiccup shouldn't crash the worker
    loop."""
    _logger.info("integration-keys: refresh loop starting")
    while not stop_event.is_set():
        try:
            await _refresh_once()
        except Exception:  # noqa: BLE001
            _logger.exception("integration-keys: refresh failed")
        try:
            await asyncio.wait_for(
                stop_event.wait(), timeout=REFRESH_INTERVAL_S,
            )
            return
        except asyncio.TimeoutError:
            continue


def invalidate() -> None:
    """Force the next ``get()`` to re-fetch on next refresh tick.
    Called by the admin settings PUT route so saved keys take effect
    quickly. Sync-friendly so the route handler can call it without
    awaiting."""
    _first_refresh_done.clear()
    # Schedule an immediate refresh if we're inside a running loop.
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_refresh_once())
    except RuntimeError:
        # No running loop — caller is sync test/script. The next
        # ``refresh_loop`` tick will pick up the change.
        pass


def get(name: str, *, env_fallback: str | None = None) -> str | None:
    """Synchronous resolver — DB cache first, env second, None last.

    Safe to call from inside any provider's ``__init__`` without an
    async context. Returns the trimmed key string or ``None``."""
    cached = _cache.get(name)
    if cached:
        return cached
    if env_fallback:
        env_val = (os.environ.get(env_fallback) or "").strip()
        if env_val:
            return env_val
    return None


def is_configured(name: str, *, env_fallback: str | None = None) -> bool:
    return bool(get(name, env_fallback=env_fallback))
