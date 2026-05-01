"""Real-time activity event bus — streams agent/crawler/scanner progress to the UI.

Uses an asyncio queue + SSE pattern so the dashboard can show live progress
of every tool invocation, triage decision, and crawler step as it happens.
"""

from __future__ import annotations


import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger("argus.activity")


class ActivityType(str, Enum):
    CRAWLER_START = "crawler_start"
    CRAWLER_FETCH = "crawler_fetch"
    CRAWLER_RESULT = "crawler_result"
    CRAWLER_COMPLETE = "crawler_complete"
    CRAWLER_ERROR = "crawler_error"
    TRIAGE_START = "triage_start"
    TRIAGE_LLM_CALL = "triage_llm_call"
    TRIAGE_RESULT = "triage_result"
    TRIAGE_NO_THREAT = "triage_no_threat"
    PIPELINE_STORE = "pipeline_store"
    PIPELINE_DUPLICATE = "pipeline_duplicate"
    PIPELINE_ALERT = "pipeline_alert"
    SCAN_START = "scan_start"
    SCAN_SUBDOMAIN = "scan_subdomain"
    SCAN_EXPOSURE = "scan_exposure"
    SCAN_COMPLETE = "scan_complete"
    NOTIFICATION_SEND = "notification_send"
    NOTIFICATION_RESULT = "notification_result"
    SYSTEM = "system"
    SECURITY_BLOCKED = "security_blocked"
    FEED_START = "feed_start"
    FEED_RESULT = "feed_result"
    FEED_COMPLETE = "feed_complete"
    FEED_ERROR = "feed_error"
    FEED_GEOLOCATE = "feed_geolocate"
    THREAT_STATUS_UPDATE = "threat_status_update"


class ActivityEvent:
    """A single activity event."""

    __slots__ = ("id", "timestamp", "event_type", "agent", "message", "details", "severity")

    def __init__(
        self,
        event_type: ActivityType,
        agent: str,
        message: str,
        details: dict[str, Any] | None = None,
        severity: str = "info",
    ):
        self.id = str(uuid.uuid4())[:8]
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.event_type = event_type.value
        self.agent = agent
        self.message = message
        self.details = details or {}
        self.severity = severity

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "agent": self.agent,
            "message": self.message,
            "details": self.details,
            "severity": self.severity,
        }

    def to_sse(self) -> str:
        return f"data: {json.dumps(self.to_dict())}\n\n"


class ActivityBus:
    """Pub-sub event bus for activity events.

    Subscribers get an asyncio.Queue that receives all events.
    A ring buffer keeps the last N events for new subscribers.
    """

    def __init__(self, history_size: int = 200):
        self._subscribers: list[asyncio.Queue] = []
        self._history: list[ActivityEvent] = []
        self._history_size = history_size
        self._lock = asyncio.Lock()

    async def emit(self, event: ActivityEvent) -> None:
        """Publish an event to all subscribers."""
        async with self._lock:
            self._history.append(event)
            if len(self._history) > self._history_size:
                self._history = self._history[-self._history_size:]

        dead: list[asyncio.Queue] = []
        for q in self._subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._subscribers.remove(q)

        logger.debug("[activity] %s | %s | %s", event.agent, event.event_type, event.message)

    def subscribe(self) -> asyncio.Queue:
        """Create a new subscriber queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """Remove a subscriber."""
        if q in self._subscribers:
            self._subscribers.remove(q)

    def get_history(self, limit: int = 50) -> list[dict]:
        """Return recent events."""
        return [e.to_dict() for e in self._history[-limit:]]


# Singleton
activity_bus = ActivityBus()


# ── Convenience emitters ──────────────────────────────────────

async def emit(
    event_type: ActivityType,
    agent: str,
    message: str,
    details: dict[str, Any] | None = None,
    severity: str = "info",
) -> None:
    """Emit an activity event."""
    event = ActivityEvent(event_type, agent, message, details, severity)
    await activity_bus.emit(event)
