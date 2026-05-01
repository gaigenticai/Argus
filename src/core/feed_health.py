"""FeedHealth recording helper.

The replacement for the silent-zero pattern. Every feed runner calls
``record(...)`` exactly once per run with the outcome. The dashboard
queries ``latest_per_feed`` to render the feed-health panel, so a
missing API key or a rate-limited upstream surfaces immediately
instead of presenting as "0 rows ingested" forever.

Usage::

    async with feed_health.record(
        db, feed_name="otx",
        organization_id=org_id,
    ) as ctx:
        # raise on failure; ctx.set_rows(...) on success.
        rows = await fetch_otx(...)
        ctx.set_rows(len(rows))

    # On a missing API key, record once at the top of the runner:
    if not settings.feeds.otx_api_key:
        await feed_health.mark_unconfigured(
            db, feed_name="otx",
            organization_id=org_id,
            detail="ARGUS_FEED_OTX_API_KEY not set",
        )
        return
"""

from __future__ import annotations

import contextlib
import logging
import time
import uuid
from typing import AsyncIterator

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.admin import FeedHealth, FeedHealthStatus


logger = logging.getLogger(__name__)


async def _persist(
    db: AsyncSession,
    *,
    feed_name: str,
    status: str,
    organization_id: uuid.UUID | None = None,
    detail: str | None = None,
    rows_ingested: int = 0,
    duration_ms: int | None = None,
) -> FeedHealth:
    row = FeedHealth(
        organization_id=organization_id,
        feed_name=feed_name,
        status=status,
        detail=(detail or "")[:1024] or None,
        rows_ingested=rows_ingested,
        duration_ms=duration_ms,
    )
    db.add(row)
    await db.flush()
    return row


async def mark_ok(
    db: AsyncSession,
    *,
    feed_name: str,
    rows_ingested: int = 0,
    duration_ms: int | None = None,
    organization_id: uuid.UUID | None = None,
    detail: str | None = None,
) -> FeedHealth:
    return await _persist(
        db,
        feed_name=feed_name,
        organization_id=organization_id,
        status=FeedHealthStatus.OK.value,
        detail=detail,
        rows_ingested=rows_ingested,
        duration_ms=duration_ms,
    )


async def mark_unconfigured(
    db: AsyncSession,
    *,
    feed_name: str,
    organization_id: uuid.UUID | None = None,
    detail: str,
) -> FeedHealth:
    return await _persist(
        db,
        feed_name=feed_name,
        organization_id=organization_id,
        status=FeedHealthStatus.UNCONFIGURED.value,
        detail=detail,
    )


async def mark_disabled(
    db: AsyncSession,
    *,
    feed_name: str,
    organization_id: uuid.UUID | None = None,
    detail: str | None = None,
) -> FeedHealth:
    return await _persist(
        db,
        feed_name=feed_name,
        organization_id=organization_id,
        status=FeedHealthStatus.DISABLED.value,
        detail=detail,
    )


async def mark_failure(
    db: AsyncSession,
    *,
    feed_name: str,
    error: BaseException | str,
    organization_id: uuid.UUID | None = None,
    duration_ms: int | None = None,
    classify: str = FeedHealthStatus.NETWORK_ERROR.value,
) -> FeedHealth:
    detail = str(error) if not isinstance(error, str) else error
    return await _persist(
        db,
        feed_name=feed_name,
        organization_id=organization_id,
        status=classify,
        detail=detail,
        duration_ms=duration_ms,
    )


class _Ctx:
    """Context object yielded by :func:`record`."""

    def __init__(self) -> None:
        self.rows = 0
        self.detail: str | None = None

    def set_rows(self, n: int) -> None:
        self.rows = int(n)

    def set_detail(self, s: str | None) -> None:
        self.detail = s


@contextlib.asynccontextmanager
async def record(
    db: AsyncSession,
    *,
    feed_name: str,
    organization_id: uuid.UUID | None = None,
    on_error_status: str = FeedHealthStatus.NETWORK_ERROR.value,
) -> AsyncIterator[_Ctx]:
    """Context manager that records a single FeedHealth row per run.

    Records ``OK`` if the body returns normally, otherwise records the
    exception classified as ``on_error_status`` and re-raises so the
    caller's normal error path runs.
    """
    ctx = _Ctx()
    started = time.monotonic()
    try:
        yield ctx
    except Exception as e:  # noqa: BLE001
        elapsed_ms = int((time.monotonic() - started) * 1000)
        try:
            await mark_failure(
                db,
                feed_name=feed_name,
                organization_id=organization_id,
                error=e,
                duration_ms=elapsed_ms,
                classify=on_error_status,
            )
        except Exception:
            logger.exception(
                "feed_health.record could not persist failure for %s", feed_name
            )
        raise
    else:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        await mark_ok(
            db,
            feed_name=feed_name,
            organization_id=organization_id,
            rows_ingested=ctx.rows,
            duration_ms=elapsed_ms,
            detail=ctx.detail,
        )


async def latest_per_feed(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID | None = None,
) -> list[FeedHealth]:
    """Return the most recent FeedHealth row for each feed_name.

    Used by the dashboard's feed-health panel.
    """
    # We use a window function via raw SQL because SA's correlate
    # patterns for "latest per group" are noisy.
    from sqlalchemy import text

    org_clause = "organization_id IS NULL OR organization_id = :org_id" if organization_id else "TRUE"
    sql = text(
        f"""
        SELECT * FROM (
            SELECT *, ROW_NUMBER() OVER (
                PARTITION BY feed_name ORDER BY observed_at DESC
            ) AS rn
            FROM feed_health
            WHERE {org_clause}
        ) ranked
        WHERE rn = 1
        ORDER BY feed_name
        """
    )
    bind: dict = {}
    if organization_id:
        bind["org_id"] = organization_id
    result = await db.execute(sql, bind)
    rows = result.mappings().all()
    out: list[FeedHealth] = []
    for r in rows:
        h = FeedHealth(
            organization_id=r["organization_id"],
            feed_name=r["feed_name"],
            status=r["status"],
            detail=r["detail"],
            rows_ingested=r["rows_ingested"],
            duration_ms=r["duration_ms"],
            observed_at=r["observed_at"],
        )
        h.id = r["id"]
        out.append(h)
    return out


async def history(
    db: AsyncSession,
    *,
    feed_name: str,
    organization_id: uuid.UUID | None = None,
    limit: int = 100,
) -> list[FeedHealth]:
    query = select(FeedHealth).where(FeedHealth.feed_name == feed_name)
    if organization_id:
        query = query.where(
            (FeedHealth.organization_id == organization_id)
            | (FeedHealth.organization_id.is_(None))
        )
    query = query.order_by(desc(FeedHealth.observed_at)).limit(limit)
    return list((await db.execute(query)).scalars().all())


__all__ = [
    "mark_ok",
    "mark_unconfigured",
    "mark_disabled",
    "mark_failure",
    "record",
    "latest_per_feed",
    "history",
]
