"""Base email-gateway connector abstraction (P3 #3.3)."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EmailThreatEvent:
    """Normalised phishing/malware event pulled from the gateway."""
    gateway: str
    event_id: str
    classification: str          # "phish" | "malware" | "spam" | "other"
    sender: str | None = None
    recipient: str | None = None
    subject: str | None = None
    threat_url: str | None = None
    threat_hash: str | None = None
    occurred_at: str | None = None
    raw: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "gateway": self.gateway,
            "event_id": self.event_id,
            "classification": self.classification,
            "sender": self.sender,
            "recipient": self.recipient,
            "subject": self.subject,
            "threat_url": self.threat_url,
            "threat_hash": self.threat_hash,
            "occurred_at": self.occurred_at,
        }


@dataclass
class EmailBlocklistItem:
    type: str   # url | domain | sender | hash
    value: str
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "value": self.value,
                "description": self.description}


@dataclass
class EmailGatewayResult:
    gateway: str
    success: bool
    events: list[EmailThreatEvent] = field(default_factory=list)
    pushed_count: int = 0
    remote_ids: list[str] = field(default_factory=list)
    note: str | None = None
    error: str | None = None
    raw: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "gateway": self.gateway,
            "success": self.success,
            "events": [e.to_dict() for e in self.events],
            "event_count": len(self.events),
            "pushed_count": self.pushed_count,
            "remote_ids": self.remote_ids,
            "note": self.note,
            "error": self.error,
        }


class EmailGatewayConnector(ABC):
    name: str = "abstract"
    label: str = "Abstract"

    @abstractmethod
    def is_configured(self) -> bool:
        ...

    @abstractmethod
    async def fetch_threats(
        self, *, since_iso: str | None = None,
    ) -> EmailGatewayResult:
        ...

    @abstractmethod
    async def push_blocklist(
        self, items: list[EmailBlocklistItem],
    ) -> EmailGatewayResult:
        ...

    @abstractmethod
    async def health_check(self) -> EmailGatewayResult:
        ...
