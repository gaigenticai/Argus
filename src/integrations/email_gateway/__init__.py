"""Email-gateway push + pull connectors (P3 #3.3).

Three vendors covering ~80% of regulated-buyer mail-security
estates:

  proofpoint  Proofpoint TAP (Targeted Attack Protection) — URL/threat
              fetch + URL blocklist push
  mimecast    Mimecast — message-monitor pull + URL Protect blocklist
  abnormal    Abnormal Security — case enrichment + abuse-mailbox
              sync

Each connector exposes:
  - is_configured()
  - fetch_threats(since_iso)   pull recent phishing / malware events
                                 to enrich Argus alerts
  - push_blocklist(items)      add URLs / domains / hashes to the
                                 vendor's blocklist
  - health_check()
"""

from __future__ import annotations

from .base import (
    EmailGatewayConnector,
    EmailThreatEvent,
    EmailGatewayResult,
    EmailBlocklistItem,
)
from .proofpoint import ProofpointTapConnector
from .mimecast import MimecastConnector
from .abnormal import AbnormalConnector


CONNECTORS: dict[str, type[EmailGatewayConnector]] = {
    "proofpoint": ProofpointTapConnector,
    "mimecast":   MimecastConnector,
    "abnormal":   AbnormalConnector,
}


def get_connector(name: str) -> EmailGatewayConnector | None:
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
            "supports_blocklist_push": getattr(
                cls, "supports_blocklist_push", True,
            ),
        })
    return out


__all__ = [
    "EmailGatewayConnector",
    "EmailThreatEvent",
    "EmailGatewayResult",
    "EmailBlocklistItem",
    "ProofpointTapConnector",
    "MimecastConnector",
    "AbnormalConnector",
    "CONNECTORS",
    "get_connector",
    "list_available",
]
