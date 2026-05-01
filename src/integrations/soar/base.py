"""Base SOAR connector abstraction (P3 #3.7).

Mirrors :mod:`src.integrations.siem.base` but with the SOAR-specific
shape: each push creates an *incident* / *case* / *container* in the
target platform, not just a log event.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SoarPushResult:
    success: bool
    pushed_count: int = 0
    remote_ids: list[str] | None = None
    note: str | None = None
    error: str | None = None
    raw: dict | None = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "pushed_count": self.pushed_count,
            "remote_ids": self.remote_ids or [],
            "note": self.note,
            "error": self.error,
        }


def _alert_to_incident(alert) -> dict[str, Any]:
    """Common incident-shape pushed to SOAR. Each connector adapts to
    the platform's native field names inside push_events()."""
    return {
        "id": str(getattr(alert, "id", "")),
        "title": getattr(alert, "title", ""),
        "summary": getattr(alert, "summary", ""),
        "severity": getattr(alert, "severity", "medium"),
        "category": getattr(alert, "category", "unknown"),
        "status": getattr(alert, "status", "new"),
        "confidence": float(getattr(alert, "confidence", 0.0) or 0.0),
        "created_at": (
            getattr(alert, "created_at", None).isoformat()
            if getattr(alert, "created_at", None) else None
        ),
        "source": "argus",
    }


class SoarConnector(ABC):
    """Abstract SOAR push connector."""

    name: str = "abstract"
    label: str = "Abstract"

    @abstractmethod
    def is_configured(self) -> bool:
        ...

    @abstractmethod
    async def push_events(
        self, events: list[dict[str, Any]],
    ) -> SoarPushResult:
        ...

    @abstractmethod
    async def health_check(self) -> SoarPushResult:
        ...

    async def push_alert(self, alert) -> SoarPushResult:
        if not self.is_configured():
            return SoarPushResult(
                success=False, note=f"{self.name} not configured",
            )
        return await self.push_events([_alert_to_incident(alert)])

    async def push_alerts(self, alerts: list) -> SoarPushResult:
        if not self.is_configured():
            return SoarPushResult(
                success=False, note=f"{self.name} not configured",
            )
        events = [_alert_to_incident(a) for a in alerts]
        return await self.push_events(events)
