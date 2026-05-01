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
async def list_crawlers():
    """List all registered crawlers and their last-run timestamps.

    The scheduler keeps a per-process ``_last_tick`` dict keyed on
    :class:`CrawlerKind`; we expose those alongside the static registry
    so the dashboard can render "last seen" without each crawler
    needing its own database row.
    """
    last_ticks = scheduler._last_tick  # noqa: SLF001 — intentional read
    return [
        {
            "name": kind.value,
            "crawler_name": crawler_class.__name__,
            "interval_seconds": interval_minutes * 60,
            "last_run": (
                last_ticks[kind].isoformat() if kind in last_ticks else None
            ),
        }
        for kind, (crawler_class, _kwarg, interval_minutes) in _CRAWLER_REGISTRY.items()
    ]


@router.post("/{crawler_name}/run")
async def trigger_crawler(
    crawler_name: str,
    request: Request,
    analyst: AnalystUser,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_session),
):
    """Manually trigger a crawler run (requires analyst or admin role)."""
    forwarded = request.headers.get("X-Forwarded-For")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")

    await audit_log(
        db,
        AuditAction.CRAWLER_TRIGGER,
        user=analyst,
        resource_type="crawler",
        resource_id=crawler_name,
        details={"trigger": "manual"},
        ip_address=ip,
        user_agent=request.headers.get("User-Agent", "unknown")[:500],
    )
    await db.commit()

    await activity_emit(
        ActivityType.SYSTEM,
        "api",
        f"Manual trigger: {crawler_name} crawler started by {analyst.username}",
        {"crawler": crawler_name, "trigger": "manual", "user": analyst.username},
    )
    background_tasks.add_task(scheduler.run_once, crawler_name)
    return {"status": "triggered", "crawler": crawler_name}
