"""Base EDR connector abstraction (P3 #3.2)."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EdrIoc:
    """One IOC pushed to an EDR's blocklist / detection surface."""
    type: str       # ipv4 | ipv6 | domain | url | sha256 | sha1 | md5
    value: str
    severity: str = "medium"   # low | medium | high | critical
    action: str = "detect"     # detect | prevent | allow
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type, "value": self.value,
            "severity": self.severity, "action": self.action,
            "description": self.description,
        }


@dataclass
class EdrPushResult:
    edr: str
    success: bool
    pushed_count: int = 0
    remote_ids: list[str] = field(default_factory=list)
    note: str | None = None
    error: str | None = None
    raw: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "edr": self.edr, "success": self.success,
            "pushed_count": self.pushed_count,
            "remote_ids": self.remote_ids,
            "note": self.note, "error": self.error,
        }


class EdrConnector(ABC):
    name: str = "abstract"
    label: str = "Abstract"

    @abstractmethod
    def is_configured(self) -> bool:
        ...

    @abstractmethod
    async def push_iocs(self, iocs: list[EdrIoc]) -> EdrPushResult:
        ...

    @abstractmethod
    async def health_check(self) -> EdrPushResult:
        ...

    async def isolate_host(self, *, host_id: str) -> EdrPushResult:
        """Default: not implemented. Vendors that support remote
        isolation (CrowdStrike RTR, SentinelOne Singularity, MDE
        Live Response) override."""
        return EdrPushResult(
            edr=self.name, success=False,
            note="host isolation not implemented for this connector",
        )
