"""Base breach-credential provider abstraction (P3 #3.9)."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BreachHit:
    """One breach record across providers, normalised for the dashboard."""

    provider: str           # "hibp" | "intelx" | "dehashed"
    breach_name: str        # e.g. "Adobe", "LinkedIn-2012"
    email: str | None = None
    username: str | None = None
    password_hash: str | None = None
    cleartext_password: str | None = None
    breach_date: str | None = None
    description: str | None = None
    data_classes: list[str] = field(default_factory=list)
    raw: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        # Avoid leaking cleartext passwords to the API surface — the
        # dashboard renders ``****`` and shows the analyst a copy
        # button that fetches the raw value through a separate
        # admin-gated endpoint.
        out = {
            "provider": self.provider,
            "breach_name": self.breach_name,
            "email": self.email,
            "username": self.username,
            "password_hash": self.password_hash,
            "cleartext_password_present": bool(self.cleartext_password),
            "breach_date": self.breach_date,
            "description": self.description,
            "data_classes": list(self.data_classes or []),
        }
        return out


@dataclass
class ProviderResult:
    provider: str
    success: bool
    hits: list[BreachHit]
    note: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "success": self.success,
            "hits": [h.to_dict() for h in self.hits],
            "hit_count": len(self.hits),
            "note": self.note,
            "error": self.error,
        }


class BreachProvider(ABC):
    name: str = "abstract"
    label: str = "Abstract"

    @abstractmethod
    def is_configured(self) -> bool:
        ...

    @abstractmethod
    async def search_email(self, email: str) -> ProviderResult:
        ...

    async def search_password_hash(
        self, sha1_hash: str,
    ) -> ProviderResult:
        """Optional. Most providers support k-anonymity password
        lookup; default to "not implemented" when a provider doesn't."""
        return ProviderResult(
            provider=self.name, success=False, hits=[],
            note="password-hash search not implemented for this provider",
        )
