"""Activity feed — SSE streaming + REST history endpoint."""

from __future__ import annotations


import asyncio

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from src.core.activity import activity_bus

router = APIRouter(prefix="/activity", tags=["Auth & Identity"])


@router.get("/stream")
async def activity_stream():
    """Server-Sent Events stream of real-time activity events."""

    async def event_generator():
        queue = activity_bus.subscribe()
        try:
            # Send recent history first so the UI isn't empty on connect
            for event_dict in activity_bus.get_history(50):
                import json
                yield f"data: {json.dumps(event_dict)}\n\n"

            # Stream live events
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield event.to_sse()
                except asyncio.TimeoutError:
                    # Send keepalive comment to prevent connection timeout
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            activity_bus.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/history")
async def activity_history(limit: int = 100):
    """Return recent activity events (for initial page load / fallback)."""
    return activity_bus.get_history(min(limit, 500))
