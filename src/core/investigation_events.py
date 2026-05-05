"""Per-investigation pub-sub bus for live trace streaming.

Distinct from :mod:`src.core.activity` which is a single global stream.
Investigation events are keyed by ``investigation_id`` so multiple
analysts watching different runs don't get cross-talk, and an SSE
client subscribing for run X never sees events from run Y.

Events are best-effort: if a queue is full (subscriber too slow) we
drop events for that subscriber rather than back-pressure the agent.
The agent run is the source of truth — the dashboard will reload the
final trace from Postgres on completion regardless.

Event shape::

    {
        "kind": "step" | "stopped" | "started" | "plan",
        "investigation_id": "<uuid>",
        "iteration": int,
        "tool": str | None,
        "thought": str | None,
        "args": dict | None,
        "result": Any,
        "duration_ms": int | None,
        "stop_reason": str | None,
        "status": str | None,
    }
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

logger = logging.getLogger("argus.investigation_events")


class InvestigationEventBus:
    """Per-investigation-id queue registry.

    One bus per process. Subscribers register against an
    ``investigation_id`` and receive only events for that run.
    Capped per-subscriber so a slow client can't cause unbounded
    memory growth.
    """

    def __init__(self, queue_size: int = 100):
        self._subs: dict[uuid.UUID, list[asyncio.Queue]] = {}
        self._queue_size = queue_size
        self._lock = asyncio.Lock()

    def subscribe(self, investigation_id: uuid.UUID) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self._queue_size)
        self._subs.setdefault(investigation_id, []).append(q)
        return q

    def unsubscribe(self, investigation_id: uuid.UUID, q: asyncio.Queue) -> None:
        subs = self._subs.get(investigation_id) or []
        if q in subs:
            subs.remove(q)
        if not subs and investigation_id in self._subs:
            del self._subs[investigation_id]

    async def emit(self, investigation_id: uuid.UUID, event: dict[str, Any]) -> None:
        """Publish an event. ``investigation_id`` injected if missing."""
        event.setdefault("investigation_id", str(investigation_id))
        subs = list(self._subs.get(investigation_id) or [])
        for q in subs:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Slow subscriber. Drop oldest to make room — the
                # client will see a gap in the trace but can recover
                # from the final reload.
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass

    @staticmethod
    def to_sse(event: dict[str, Any]) -> str:
        """Encode an event as a single SSE message."""
        return f"data: {json.dumps(event, default=str)}\n\n"


# Process-level singleton.
bus = InvestigationEventBus()
