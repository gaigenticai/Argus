"""SIEM push connectors (P2 #2.7).

Six connectors mirroring Argus alerts / IOCs into the customer's
existing SIEM:

  splunk_hec    Splunk HTTP Event Collector — JSON event stream
  sentinel      Microsoft Sentinel Logs Ingestion API
  elastic       Elastic bulk-index API (ECS-shaped events)
  qradar        IBM QRadar Reference Set bulk-add + AQL helper
  wazuh_siem    Wazuh Indexer (OpenSearch) bulk-index — OSS, free
  graylog       Graylog GELF push (HTTP) — Graylog Open / Enterprise

Each connector:
  - reads its config from env vars (operator-set)
  - exposes is_configured(), push_events(), push_alert() / push_alerts(),
    push_ioc() / push_iocs(), health_check()
  - degrades gracefully when unconfigured (returns
    PushResult(success=False, note="not configured"))
  - uses src.core.http_circuit so a customer SIEM outage doesn't tar-pit
    the alert pipeline

The PUSH side is the v1 surface — bidirectional pull (consume customer
alerts back into Argus) is deferred.
"""

from __future__ import annotations

from .base import (
    PushResult,
    SiemConnector,
)
from .splunk_hec import SplunkHecConnector
from .sentinel import SentinelConnector
from .elastic import ElasticConnector
from .qradar import QRadarConnector
from .wazuh_siem import WazuhSiemConnector
from .graylog import GraylogConnector

# Connector registry — operators reference connectors by name in API
# routes; we keep the mapping centralised so adding the next SIEM is
# one entry away.
CONNECTORS: dict[str, type[SiemConnector]] = {
    "splunk_hec": SplunkHecConnector,
    "sentinel":   SentinelConnector,
    "elastic":    ElasticConnector,
    "qradar":     QRadarConnector,
    "wazuh_siem": WazuhSiemConnector,
    "graylog":    GraylogConnector,
}


def get_connector(name: str) -> SiemConnector | None:
    cls = CONNECTORS.get(name)
    if cls is None:
        return None
    return cls()


def list_available() -> list[dict]:
    """Return availability metadata for every connector — used by the
    dashboard to render the SIEM-integration matrix."""
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
    "PushResult",
    "SiemConnector",
    "SplunkHecConnector",
    "SentinelConnector",
    "ElasticConnector",
    "QRadarConnector",
    "WazuhSiemConnector",
    "GraylogConnector",
    "CONNECTORS",
    "get_connector",
    "list_available",
]
