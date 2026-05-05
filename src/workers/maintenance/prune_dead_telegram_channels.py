"""Telegram-channel self-healing job.

Probes every ``telegram_channel`` row in ``crawler_targets`` against
``https://t.me/s/<handle>`` and marks dead handles inactive. The
public preview endpoint returns:

  - HTTP 200 with ``tgme_widget_message_wrap`` divs in the body →
    channel is reachable and serving messages.
  - HTTP 302 → channel has disabled the public preview (banned,
    private, age-restricted, or rebranded). Cannot scrape.
  - HTTP 200 with no message wraps → channel exists but is empty
    (rare; usually means freshly created).

We only need a HEAD-style check per handle: a single GET (no
redirect-follow) returning the status code and ~10KB of body so we
can tell join-page from preview. Bandwidth-light, ~6 channels per org
per week.

Without this job, the curated Telegram catalogue silently rots —
hacktivist channels get banned constantly, and the operator stares at
a Feed Health row that says "ok, 0 messages" forever.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timezone

import aiohttp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core import feed_health
from src.models.admin import CrawlerTarget
from src.storage import database as _db

_logger = logging.getLogger(__name__)

FEED_NAME = "maintenance.prune_dead_telegram_channels"

_TG_BASE = "https://t.me/s/{handle}"
_PROBE_TIMEOUT = aiohttp.ClientTimeout(total=12)
_USER_AGENT = "Mozilla/5.0 (compatible; argus-channel-prober/1.0)"

# Cap probes per tick. Defensive against a deployment with thousands
# of channels — the probe is fast (~200ms each) but bounded work
# per tick keeps the worker loop responsive.
_MAX_PROBES = int(os.environ.get("ARGUS_TELEGRAM_PROBE_MAX", "100"))
# Lower bound on probe interval. Telegram has rate limits on the
# preview surface; spreading probes prevents 429s.
_PROBE_DELAY_S = float(os.environ.get("ARGUS_TELEGRAM_PROBE_DELAY", "0.6"))


async def _probe_handle(http: aiohttp.ClientSession, handle: str) -> str:
    """Return one of ``alive`` / ``preview_disabled`` / ``empty`` /
    ``error``. Doesn't follow redirects; a 302 means Telegram bounced
    us off the preview path."""
    url = _TG_BASE.format(handle=handle)
    try:
        async with http.get(
            url,
            headers={"User-Agent": _USER_AGENT},
            allow_redirects=False,
        ) as resp:
            if resp.status in (301, 302, 303, 307, 308):
                return "preview_disabled"
            if resp.status != 200:
                return "error"
            body = await resp.text()
            if "tgme_widget_message_wrap" in body:
                return "alive"
            # 200 but no message wraps — channel page rendered the
            # join CTA instead of the message preview. Treat the same
            # way as a redirect.
            if "tgme_action_button_new" in body or "tgme_page_action" in body:
                return "preview_disabled"
            return "empty"
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        _logger.debug("telegram probe @%s failed: %s", handle, exc)
        return "error"


async def tick_once() -> None:
    if _db.async_session_factory is None:
        return
    started = time.monotonic()

    async with _db.async_session_factory() as session:
        rows = (
            await session.execute(
                select(CrawlerTarget).where(
                    CrawlerTarget.kind == "telegram_channel",
                    CrawlerTarget.is_active.is_(True),
                )
            )
        ).scalars().all()
        if not rows:
            await feed_health.mark_unconfigured(
                session,
                feed_name=FEED_NAME,
                detail=(
                    "No active telegram_channel rows in crawler_targets. "
                    "Seed defaults or add via /admin → Crawler Targets."
                ),
            )
            await session.commit()
            return

        rows = rows[:_MAX_PROBES]
        results: dict[str, int] = {
            "alive": 0, "preview_disabled": 0, "empty": 0, "error": 0,
        }
        deactivated_handles: list[str] = []

        async with aiohttp.ClientSession(timeout=_PROBE_TIMEOUT) as http:
            for row in rows:
                verdict = await _probe_handle(http, row.identifier)
                results[verdict] = results.get(verdict, 0) + 1

                meta = dict(row.config or {})
                meta["_last_probed_at"] = datetime.now(timezone.utc).isoformat()
                meta["_last_probe_verdict"] = verdict

                if verdict == "preview_disabled":
                    # Channel can't be scraped via t.me/s/. Don't
                    # delete — the operator may still want to track
                    # via Telethon (private mode) or remove explicitly.
                    row.is_active = False
                    deactivated_handles.append(row.identifier)
                    meta["_deactivated_reason"] = (
                        "preview disabled by Telegram (banned / private "
                        "/ restricted / rebranded)"
                    )
                row.config = meta

                # Spread probes to dodge rate limits.
                await asyncio.sleep(_PROBE_DELAY_S)

        detail_parts = [f"probed={len(rows)}"]
        for status, count in results.items():
            if count:
                detail_parts.append(f"{status}={count}")
        if deactivated_handles:
            detail_parts.append(
                "deactivated=" + ",".join(deactivated_handles[:5])
                + ("…" if len(deactivated_handles) > 5 else "")
            )

        await feed_health.mark_ok(
            session,
            feed_name=FEED_NAME,
            rows_ingested=results["alive"],
            duration_ms=int((time.monotonic() - started) * 1000),
            detail=" · ".join(detail_parts),
        )
        await session.commit()

    _logger.info(
        "maintenance: telegram-channel prune — alive=%d, preview_disabled=%d, "
        "empty=%d, error=%d (deactivated=%d)",
        results["alive"], results["preview_disabled"],
        results["empty"], results["error"], len(deactivated_handles),
    )
