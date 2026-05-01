"""Sandbox detonation connectors (P3 #3.6).

Four sandbox providers behind a uniform submit / poll / report
interface. Argus uploads a sample (or a hash for cloud-only
re-analysis), the connector returns an ``analysis_id`` immediately,
and ``get_report`` is polled by the case copilot until a verdict
lands. Reports are normalised into :class:`AnalysisReport` so the
case timeline doesn't have to know which sandbox produced them.

  cape          CAPEv2 — operator self-hosted, free / open-source
  joe           Joe Sandbox Cloud — commercial BYOK
  hybrid        Hybrid-Analysis (Falcon Sandbox) — commercial BYOK
  virustotal    VirusTotal Premium / Enterprise — strict BYOK
                (free-tier ToS forbids commercial-product use; we
                deliberately refuse to run without a paid key)

All four:
  - read their config from env vars
  - degrade to ``unconfigured`` when keys are missing
  - go through ``src.core.http_circuit`` so a sandbox outage doesn't
    tar-pit the case copilot
  - report errors uniformly into ``SandboxResult.error``
"""

from __future__ import annotations

from .base import (
    AnalysisReport,
    SandboxConnector,
    SandboxResult,
    SignatureHit,
)
from .cape import CapeConnector
from .joe import JoeSandboxConnector
from .hybrid import HybridAnalysisConnector
from .virustotal import VirusTotalConnector


CONNECTORS: dict[str, type[SandboxConnector]] = {
    "cape":       CapeConnector,
    "joe":        JoeSandboxConnector,
    "hybrid":     HybridAnalysisConnector,
    "virustotal": VirusTotalConnector,
}


def get_connector(name: str) -> SandboxConnector | None:
    cls = CONNECTORS.get(name)
    if cls is None:
        return None
    return cls()


def list_available() -> list[dict]:
    out = []
    for name, cls in CONNECTORS.items():
        inst = cls()
        out.append({
            "name": name,
            "label": cls.label,
            "configured": inst.is_configured(),
        })
    return out


__all__ = [
    "AnalysisReport",
    "SandboxConnector",
    "SandboxResult",
    "SignatureHit",
    "CapeConnector",
    "JoeSandboxConnector",
    "HybridAnalysisConnector",
    "VirusTotalConnector",
    "CONNECTORS",
    "get_connector",
    "list_available",
]
