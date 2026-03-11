"""Suricata Eve JSON log ingestor — no API, operates on log data directly."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class SuricataIngestor:
    """Parses Suricata Eve JSON events and correlates them with known IOCs.

    This integration does NOT inherit from BaseIntegration because Suricata
    is a network IDS/IPS that produces local Eve JSON log files rather than
    exposing an HTTP API.  Data is fed in as parsed JSON dicts.
    """

    def parse_eve_json(self, events: list[dict]) -> list[dict]:
        """Extract alert-type events from raw Eve JSON entries.

        Args:
            events: Raw Eve JSON records (each is one JSON object from
                ``eve.json``).

        Returns:
            A filtered and normalised list containing only alert events,
            each with the fields Argus cares about.
        """
        alerts: list[dict] = []

        for event in events:
            if event.get("event_type") != "alert":
                continue

            alert_meta = event.get("alert", {})
            alerts.append(
                {
                    "timestamp": event.get("timestamp"),
                    "src_ip": event.get("src_ip"),
                    "src_port": event.get("src_port"),
                    "dest_ip": event.get("dest_ip"),
                    "dest_port": event.get("dest_port"),
                    "proto": event.get("proto"),
                    "signature_id": alert_meta.get("signature_id"),
                    "signature": alert_meta.get("signature"),
                    "category": alert_meta.get("category"),
                    "severity": alert_meta.get("severity"),
                    "action": alert_meta.get("action"),
                    "flow_id": event.get("flow_id"),
                    "in_iface": event.get("in_iface"),
                }
            )

        logger.info(
            "[suricata] Parsed %d alert(s) from %d Eve JSON event(s)",
            len(alerts),
            len(events),
        )
        return alerts

    def correlate_with_iocs(
        self,
        eve_alerts: list[dict],
        ioc_values: set[str],
    ) -> list[dict]:
        """Match alert source/destination IPs against a set of known IOC values.

        Args:
            eve_alerts: Alert dicts as returned by :meth:`parse_eve_json`.
            ioc_values: A set of IOC indicator values (IP addresses, domains,
                etc.) to match against.

        Returns:
            A list of matched alerts, each enriched with an ``ioc_matches``
            field listing which IOC values were hit and which direction
            (source or destination) matched.
        """
        matched: list[dict] = []

        for alert in eve_alerts:
            src_ip = alert.get("src_ip")
            dest_ip = alert.get("dest_ip")
            hits: list[dict] = []

            if src_ip and src_ip in ioc_values:
                hits.append({"value": src_ip, "direction": "source"})
            if dest_ip and dest_ip in ioc_values:
                hits.append({"value": dest_ip, "direction": "destination"})

            if hits:
                enriched = {
                    **alert,
                    "ioc_matches": hits,
                    "correlated_at": datetime.now(timezone.utc).isoformat(),
                }
                matched.append(enriched)

        logger.info(
            "[suricata] Correlated %d alert(s) with IOCs (%d IOC values checked)",
            len(matched),
            len(ioc_values),
        )
        return matched
