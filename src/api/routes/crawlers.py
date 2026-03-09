"""Crawler management and manual trigger endpoints."""

from fastapi import APIRouter, BackgroundTasks

from src.core.scheduler import Scheduler

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
async def trigger_crawler(crawler_name: str, background_tasks: BackgroundTasks):
    """Manually trigger a crawler run."""
    background_tasks.add_task(scheduler.run_once, crawler_name)
    return {"status": "triggered", "crawler": crawler_name}
