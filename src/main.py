"""Argus — main entry point."""

import asyncio
import logging
import signal
import sys

import uvicorn

from src.config.settings import settings
from src.core.scheduler import Scheduler
from src.feeds.scheduler import FeedScheduler
from src.storage.database import init_db, close_db

logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("argus")


async def run_scheduler():
    """Run the crawler scheduler."""
    await init_db()
    scheduler = Scheduler()
    await scheduler.start()


async def run_feed_scheduler():
    """Run the threat intel feed scheduler."""
    await init_db()
    from src.feeds.seed_layers import seed_default_layers
    from src.storage.database import async_session_factory
    async with async_session_factory() as session:
        await seed_default_layers(session)
        await session.commit()
    feed_scheduler = FeedScheduler()
    await feed_scheduler.start()


def run_api():
    """Run the FastAPI server."""
    uvicorn.run(
        "src.api.app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )


async def run_all():
    """Run API server, crawler scheduler, and feed scheduler together."""
    await init_db()

    # Seed threat map layers
    from src.feeds.seed_layers import seed_default_layers
    from src.storage.database import async_session_factory
    async with async_session_factory() as session:
        await seed_default_layers(session)
        await session.commit()

    scheduler = Scheduler()
    scheduler_task = asyncio.create_task(scheduler.start())

    feed_scheduler = FeedScheduler()
    feed_scheduler_task = asyncio.create_task(feed_scheduler.start())

    # Run uvicorn in a separate thread since it blocks
    import threading
    api_thread = threading.Thread(target=run_api, daemon=True)
    api_thread.start()

    logger.info("Argus is online. All-seeing eye activated.")

    # Wait for shutdown signal
    stop = asyncio.Event()

    def _signal_handler():
        logger.info("Shutdown signal received")
        stop.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _signal_handler)

    await stop.wait()
    await scheduler.stop()
    await feed_scheduler.stop()
    await close_db()


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"

    if mode == "api":
        run_api()
    elif mode == "scheduler":
        asyncio.run(run_scheduler())
    elif mode == "feeds":
        asyncio.run(run_feed_scheduler())
    elif mode == "all":
        asyncio.run(run_all())
    else:
        print(f"Usage: python -m src.main [api|scheduler|feeds|all]")
        sys.exit(1)


if __name__ == "__main__":
    main()
