"""Argus — main entry point."""

import asyncio
import logging
import signal
import sys

import uvicorn

from src.config.settings import settings
from src.core.scheduler import Scheduler
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
    """Run API server and crawler scheduler together."""
    await init_db()

    scheduler = Scheduler()
    scheduler_task = asyncio.create_task(scheduler.start())

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
    await close_db()


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"

    if mode == "api":
        run_api()
    elif mode == "scheduler":
        asyncio.run(run_scheduler())
    elif mode == "all":
        asyncio.run(run_all())
    else:
        print(f"Usage: python -m src.main [api|scheduler|all]")
        sys.exit(1)


if __name__ == "__main__":
    main()
