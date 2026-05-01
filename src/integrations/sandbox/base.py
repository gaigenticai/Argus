"""Base sandbox connector abstraction (P3 #3.6)."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SignatureHit:
    """One signature / detection rule that fired during analysis."""
    name: str
    severity: str | None = None    # "low" | "medium" | "high" | "critical"
    description: str | None = None
    attack: list[str] = field(default_factory=list)   # MITRE ATT&CK ids

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "attack": self.attack,
        }


@dataclass
class AnalysisReport:
    """Normalised sandbox report produced by every connector."""
    sandbox: str
    analysis_id: str
    sample_sha256: str | None
    verdict: str            # "malicious" | "suspicious" | "clean" | "unknown"
    score: float            # 0-1
    signatures: list[SignatureHit] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    artifacts_url: str | None = None
    raw: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sandbox": self.sandbox,
            "analysis_id": self.analysis_id,
            "sample_sha256": self.sample_sha256,
            "verdict": self.verdict,
            "score": round(self.score, 3),
            "signatures": [s.to_dict() for s in self.signatures],
            "tags": list(self.tags or []),
            "attack_techniques": list(self.attack_techniques or []),
            "artifacts_url": self.artifacts_url,
        }


@dataclass
class SandboxResult:
    """Wraps one connector call. ``data`` is a SubmitResult-shaped dict
    on submit, an :class:`AnalysisReport` on get_report, or None on
    health-checks."""
    sandbox: str
    success: bool
    data: Any = None
    note: str | None = None
    error: str | None = None
    raw: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "sandbox": self.sandbox,
            "success": self.success,
            "note": self.note,
            "error": self.error,
        }
        if isinstance(self.data, AnalysisReport):
            out["report"] = self.data.to_dict()
        elif isinstance(self.data, dict):
            out["data"] = self.data
        elif self.data is not None:
            out["data"] = self.data
        return out


_MAX_SAMPLE_BYTES = 64 * 1024 * 1024   # 64 MB upload ceiling


class SandboxConnector(ABC):
    """Abstract sandbox connector."""

    name: str = "abstract"
    label: str = "Abstract"

    @abstractmethod
    def is_configured(self) -> bool:
        ...

    @abstractmethod
    async def submit_file(
        self, *, sample_bytes: bytes, filename: str,
    ) -> SandboxResult:
        """Upload a binary sample. Returns ``data={"analysis_id": ...,
        "sample_sha256": ...}`` on success."""

    @abstractmethod
    async def get_report(self, analysis_id: str) -> SandboxResult:
        """Poll for a finished analysis. Returns
        ``data=AnalysisReport`` on success; the caller decides
        whether to retry."""

    @abstractmethod
    async def health_check(self) -> SandboxResult:
        ...

    @staticmethod
    def _check_size(sample_bytes: bytes) -> str | None:
        if len(sample_bytes) > _MAX_SAMPLE_BYTES:
            return f"sample exceeds {_MAX_SAMPLE_BYTES} byte upload ceiling"
        return None
