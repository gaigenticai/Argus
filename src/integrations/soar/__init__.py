"""SOAR push connectors (P3 #3.7).

Four connectors mirroring Argus alerts / IOCs into the customer's
SOAR platform — same shape as the SIEM connectors (P2 #2.7) so
operators get a uniform "configure once" experience:

  xsoar         Cortex XSOAR (Palo Alto) — incidents API
  tines         Tines — webhook receiver
  splunk_soar   Splunk SOAR (Phantom) — container ingest API
  cortex        Cortex (TheHive Project) — analyzer/responder framework
                (Apache-2.0 OSS, 200+ analyzers; covers the SOAR niche
                without a paid license)

Each connector reads its own env vars, falls back to a structured
"not configured" no-op when credentials are missing, and goes
through ``src.core.http_circuit`` so a customer outage doesn't
tar-pit the alert pipeline.
"""

from __future__ import annotations

from .base import SoarConnector, SoarPushResult
from .xsoar import XsoarConnector
from .tines import TinesConnector
from .splunk_soar import SplunkSoarConnector
from .cortex import CortexConnector


CONNECTORS: dict[str, type[SoarConnector]] = {
    "xsoar":       XsoarConnector,
    "tines":       TinesConnector,
    "splunk_soar": SplunkSoarConnector,
    "cortex":      CortexConnector,
}


def get_connector(name: str) -> SoarConnector | None:
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
    "SoarConnector",
    "SoarPushResult",
    "XsoarConnector",
    "TinesConnector",
    "SplunkSoarConnector",
    "CortexConnector",
    "CONNECTORS",
    "get_connector",
    "list_available",
]
