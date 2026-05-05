"""Per-brand-action pub-sub bus for live trace streaming.

Mirror of :mod:`src.core.investigation_events` — the two engines have
the same observability needs (live ReAct trace, plan-approval pause,
final stop event) so the bus interface is identical. Kept in a
separate module so a slow Investigation subscriber can't back-pressure
brand-action events and vice versa.

Event shape::

    {
        "kind": "step" | "stopped" | "started" | "plan",
        "brand_action_id": "<uuid>",
        "iteration": int,
        "tool": str | None,
        "thought": str | None,
        "args": dict | None,
        "result": Any,
        "duration_ms": int | None,
        "status": str | None,
        "recommendation": str | None,
        "confidence": float | None,
    }
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

logger = logging.getLogger("argus.brand_action_events")


class BrandActionEventBus:
    """Per-id queue registry. One bus per process. Slow subscribers
    drop oldest event rather than back-pressure the agent."""

    def __init__(self, queue_size: int = 100):
        self._subs: dict[uuid.UUID, list[asyncio.Queue]] = {}
        self._queue_size = queue_size

    def subscribe(self, brand_action_id: uuid.UUID) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self._queue_size)
        self._subs.setdefault(brand_action_id, []).append(q)
        return q

    def unsubscribe(self, brand_action_id: uuid.UUID, q: asyncio.Queue) -> None:
        subs = self._subs.get(brand_action_id) or []
        if q in subs:
            subs.remove(q)
        if not subs and brand_action_id in self._subs:
            del self._subs[brand_action_id]

    async def emit(self, brand_action_id: uuid.UUID, event: dict[str, Any]) -> None:
        event.setdefault("brand_action_id", str(brand_action_id))
        for q in list(self._subs.get(brand_action_id) or []):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass

    @staticmethod
    def to_sse(event: dict[str, Any]) -> str:
        return f"data: {json.dumps(event, default=str)}\n\n"


bus = BrandActionEventBus()
