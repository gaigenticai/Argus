"""EDR push connectors (P3 #3.2).

Three EDR vendors behind a uniform interface focused on the v1
operations Argus actually drives:

  push_iocs    Upload Argus IOCs to the EDR's IOC / blocklist
               surface so the agent blocks/alerts on first sighting.
  isolate      Optional — kick off a host-isolation action when the
               case copilot recommends it. (Surface implemented;
               operator must enable via per-platform config.)
  status       Connector health + endpoint count.

  crowdstrike  CrowdStrike Falcon (cloud) — OAuth2 + IOC Management API
  sentinelone  SentinelOne Singularity — token + Threat-Intel IOC API
  mde          Microsoft Defender for Endpoint — Graph API + Custom IOC

For full IR (RTR / live-response, Threat Hunting Insights, Falcon
queries) operators use the vendor's console — Argus's job is the IOC
blocklist push, the host inventory pivot, and the isolate action.
"""

from __future__ import annotations

from .base import EdrConnector, EdrPushResult, EdrIoc
from .crowdstrike import CrowdStrikeConnector
from .sentinelone import SentinelOneConnector
from .mde import MicrosoftDefenderConnector


CONNECTORS: dict[str, type[EdrConnector]] = {
    "crowdstrike": CrowdStrikeConnector,
    "sentinelone": SentinelOneConnector,
    "mde":         MicrosoftDefenderConnector,
}


def get_connector(name: str) -> EdrConnector | None:
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
    "EdrConnector", "EdrPushResult", "EdrIoc",
    "CrowdStrikeConnector", "SentinelOneConnector",
    "MicrosoftDefenderConnector",
    "CONNECTORS", "get_connector", "list_available",
]
