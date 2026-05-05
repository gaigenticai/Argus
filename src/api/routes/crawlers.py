"""Crawler management and manual trigger endpoints."""

from __future__ import annotations


from fastapi import APIRouter, BackgroundTasks, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, audit_log
from src.core.scheduler import _CRAWLER_REGISTRY, Scheduler
from src.core.activity import ActivityType, emit as activity_emit
from src.models.auth import AuditAction
from src.storage.database import get_session

router = APIRouter(prefix="/crawlers", tags=["Threat Intelligence"])

# Singleton — used by ``trigger_crawler`` below to share state across
# requests. ``list_crawlers`` reads from the module-level registry
# instead, since the per-instance ``schedules`` attribute was removed
# when the scheduler was rewritten around ``_CRAWLER_REGISTRY``.
scheduler = Scheduler()


@router.get("/")
async def list_crawlers(db: AsyncSession = Depends(get_session)):
    """List all registered crawlers and their last-run state.

    The scheduler runs in the worker process. The API's
    ``Scheduler()._last_tick`` is therefore always empty —
    previously every crawler showed "Never run" on the dashboard
    even when the worker had been polling them for hours.

    Source of truth is the ``feed_health`` table where each
    crawler tick writes a row keyed ``crawler.<kind>`` with status
    (ok / unconfigured / network_error / etc.), rows ingested,
    detail, and observed_at. We surface the latest row per kind so
    the dashboard reflects what actually happened.
    """
    from sqlalchemy import select
    from src.models.admin import FeedHealth

    rows = (
        await db.execute(
            select(FeedHealth)
            .where(FeedHealth.feed_name.like("crawler.%"))
            .order_by(FeedHealth.feed_name, FeedHealth.observed_at.desc())
        )
    ).scalars().all()

    # Most-recent row per crawler kind. SQLAlchemy doesn't have a
    # portable DISTINCT ON, so do the dedup in Python — there are
    # only ~9 kinds, the cost is trivial.
    latest: dict[str, FeedHealth] = {}
    for r in rows:
        if r.feed_name not in latest:
            latest[r.feed_name] = r

    import re as _re
    _ALERTS_RE = _re.compile(r"alerts=(\d+)")

    out = []
    for kind, (crawler_class, _kwarg, interval_minutes) in _CRAWLER_REGISTRY.items():
        feed_name = f"crawler.{kind.value}"
        h = latest.get(feed_name)

        # ``last_alerts_created`` is parsed out of FeedHealth.detail
        # (the scheduler writes ``targets=N alerts=M``). We do this
        # instead of adding a column so the crawler-runs feature
        # doesn't drag a schema migration just to surface a counter.
        last_alerts = 0
        if h and h.detail:
            m = _ALERTS_RE.search(h.detail)
            if m:
                try:
                    last_alerts = int(m.group(1))
                except ValueError:
                    last_alerts = 0

        out.append({
            "name": kind.value,
            "crawler_name": crawler_class.__name__,
            "interval_seconds": interval_minutes * 60,
            "last_run": h.observed_at.isoformat() if h else None,
            "last_status": h.status if h else None,
            "last_detail": h.detail if h else None,
            "last_rows_ingested": h.rows_ingested if h else 0,
            "last_alerts_created": last_alerts,
        })
    return out


@router.post("/{crawler_name}/run")
async def trigger_crawler(
    crawler_name: str,
    request: Request,
    analyst: AnalystUser,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_session),
):
    """Manually trigger a crawler run (requires analyst or admin role)."""
    from fastapi import HTTPException
    from src.models.admin import CrawlerKind

    # The dashboard widget sends the kind value (``tor_forum``,
    # ``ransomware_leak_group``, ...). Older clients sent the class
    # name (``TorForumCrawler``). Accept both — convert to the enum
    # before dispatch so ``scheduler.run_once`` doesn't KeyError on
    # a raw string lookup against ``_CRAWLER_REGISTRY``.
    try:
        kind_enum = CrawlerKind(crawler_name)
    except ValueError:
        # Try class-name match as a fallback for legacy clients.
        kind_enum = next(
            (k for k, (cls, _, _) in _CRAWLER_REGISTRY.items()
             if cls.__name__ == crawler_name),
            None,
        )
        if kind_enum is None:
            raise HTTPException(
                404,
                f"Crawler {crawler_name!r} not registered. "
                f"Valid kinds: {sorted(k.value for k in CrawlerKind)}",
            )

    forwarded = request.headers.get("X-Forwarded-For")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")

    await audit_log(
        db,
        AuditAction.CRAWLER_TRIGGER,
        user=analyst,
        resource_type="crawler",
        resource_id=kind_enum.value,
        details={"trigger": "manual"},
        ip_address=ip,
        user_agent=request.headers.get("User-Agent", "unknown")[:500],
    )
    await db.commit()

    await activity_emit(
        ActivityType.SYSTEM,
        "api",
        f"Manual trigger: {kind_enum.value} crawler started by {analyst.username}",
        {"crawler": kind_enum.value, "trigger": "manual", "user": analyst.username},
    )
    background_tasks.add_task(scheduler.run_once, kind_enum)
    return {"status": "triggered", "crawler": kind_enum.value}
