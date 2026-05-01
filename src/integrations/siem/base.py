"""Base SIEM connector abstraction (P2 #2.7)."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PushResult:
    """Outcome of a single push operation."""

    success: bool
    pushed_count: int = 0
    note: str | None = None
    error: str | None = None
    raw: dict | None = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "pushed_count": self.pushed_count,
            "note": self.note,
            "error": self.error,
        }


def _alert_to_event(alert) -> dict[str, Any]:
    """Common event shape pushed to every SIEM. Each connector adapts
    this to its native schema before sending."""
    return {
        "id": str(getattr(alert, "id", "")),
        "organization_id": str(getattr(alert, "organization_id", "")),
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


def _ioc_to_event(ioc) -> dict[str, Any]:
    return {
        "id": str(getattr(ioc, "id", "")),
        "ioc_type": getattr(ioc, "ioc_type", ""),
        "value": getattr(ioc, "value", ""),
        "confidence": float(getattr(ioc, "confidence", 0.0) or 0.0),
        "first_seen": (
            getattr(ioc, "first_seen", None).isoformat()
            if getattr(ioc, "first_seen", None) else None
        ),
        "last_seen": (
            getattr(ioc, "last_seen", None).isoformat()
            if getattr(ioc, "last_seen", None) else None
        ),
        "tags": list(getattr(ioc, "tags", None) or []),
        "source": "argus",
    }


class SiemConnector(ABC):
    """Abstract SIEM push connector."""

    name: str = "abstract"
    label: str = "Abstract"

    @abstractmethod
    def is_configured(self) -> bool:
        ...

    @abstractmethod
    async def push_events(
        self, events: list[dict[str, Any]],
    ) -> PushResult:
        """Send a batch of events. Each event is a flat dict; concrete
        connectors translate to the platform-specific shape inside."""

    @abstractmethod
    async def health_check(self) -> PushResult:
        ...

    async def push_alert(self, alert) -> PushResult:
        if not self.is_configured():
            return PushResult(success=False, note=f"{self.name} not configured")
        return await self.push_events([_alert_to_event(alert)])

    async def push_ioc(self, ioc) -> PushResult:
        if not self.is_configured():
            return PushResult(success=False, note=f"{self.name} not configured")
        return await self.push_events([_ioc_to_event(ioc)])

    async def push_alerts(self, alerts: list) -> PushResult:
        if not self.is_configured():
            return PushResult(success=False, note=f"{self.name} not configured")
        events = [_alert_to_event(a) for a in alerts]
        return await self.push_events(events)

    async def push_iocs(self, iocs: list) -> PushResult:
        if not self.is_configured():
            return PushResult(success=False, note=f"{self.name} not configured")
        events = [_ioc_to_event(i) for i in iocs]
        return await self.push_events(events)
