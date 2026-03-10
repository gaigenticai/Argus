"""Crawler management and manual trigger endpoints."""

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, audit_log
from src.core.scheduler import Scheduler
from src.core.activity import ActivityType, emit as activity_emit
from src.models.auth import AuditAction
from src.storage.database import get_session

router = APIRouter(prefix="/crawlers", tags=["crawlers"])

scheduler = Scheduler()


@router.get("/")
async def list_crawlers():
    """List all registered crawlers and their status."""
    return [
        {
            "name": s.crawler_class.__name__,
            "crawler_name": s.crawler_class.name if hasattr(s.crawler_class, 'name') else s.crawler_class.__name__,
            "interval_seconds": s.interval,
            "last_run": s.last_run.isoformat() if s.last_run else None,
        }
        for s in scheduler.schedules
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
