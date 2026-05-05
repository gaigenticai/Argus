"""Inbound polling for OSS self-hosted services.

Wraps the existing integration clients (MISP, OpenCTI, Wazuh) as
``BaseFeed`` subclasses so they ride the standard FeedScheduler:
health rows, retry classification, dedup, geolocation — all for free.

Each subclass returns ``last_unconfigured_reason`` when the operator
hasn't set the URL+key yet, which surfaces in the dashboard as
``unconfigured`` instead of a noisy ``network_error``.
"""

from __future__ import annotations


import logging
import os
from typing import AsyncIterator

from src.core import integration_keys as _integration_keys
from src.feeds.base import BaseFeed, FeedEntry

logger = logging.getLogger(__name__)


def _resolve(name: str, *, env_var: str) -> str:
    return (
        _integration_keys.get(name, env_fallback=env_var) or ""
    ).strip()


class MispOperatorFeed(BaseFeed):
    """Polls the operator's own MISP instance every 30 min."""

    name = "misp_operator"
    layer = "intel"
    default_interval_seconds = 1800

    async def poll(self) -> AsyncIterator[FeedEntry]:  # type: ignore[override]
        url = _resolve("misp_url", env_var="ARGUS_MISP_URL")
        key = _resolve("misp", env_var="ARGUS_MISP_KEY")
        if not url or not key:
            self.last_unconfigured_reason = (
                "MISP server URL + API key not set — see Settings → "
                "Services → MISP (operator-hosted) for install + setup."
            )
            return

        # Make sure the integration_keys cache values reach pymisp via
        # env (the existing client reads ARGUS_MISP_URL / KEY from env
        # at module scope). Operators who set these via DB still expect
        # the worker tick to succeed, so we mirror them in-process.
        os.environ["ARGUS_MISP_URL"] = url
        os.environ["ARGUS_MISP_KEY"] = key

        try:
            from src.integrations import misp as _misp
        except Exception as exc:  # noqa: BLE001
            self.last_failure_reason = f"pymisp import failed: {exc}"
            self.last_failure_classification = "parse_error"
            return

        try:
            events = _misp.fetch_recent_events(days=1, limit=200)
        except Exception as exc:  # noqa: BLE001
            self.last_failure_reason = f"MISP search failed: {exc}"
            self.last_failure_classification = "network_error"
            return

        emitted = 0
        for ev in events:
            try:
                attrs = _misp.fetch_event_attributes(
                    ev.uuid, to_ids_only=True,
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "[%s] attributes fetch failed for %s: %s",
                    self.name, ev.uuid, exc,
                )
                continue
            for a in attrs:
                # MISP attribute types map to our entry_type roughly;
                # default to "indicator" so the iocs page can still
                # render unknown types as a generic IOC.
                etype = _misp_type_to_entry(a.type)
                yield FeedEntry(
                    feed_name=self.name,
                    layer=self.layer,
                    entry_type=etype,
                    value=str(a.value),
                    label=f"MISP[{ev.info[:60]}]",
                    description=(
                        f"MISP event {ev.uuid} (TLP/tags: "
                        f"{', '.join(ev.tags)[:120]})"
                    ),
                    severity=_misp_severity(ev.threat_level_id),
                    confidence=0.8,
                    feed_metadata={
                        "source": "misp_operator",
                        "event_uuid": ev.uuid,
                        "attribute_type": a.type,
                        "category": getattr(a, "category", None),
                    },
                    expires_hours=720,
                )
                emitted += 1
        logger.info("[%s] ingested %d MISP attributes", self.name, emitted)


def _misp_type_to_entry(misp_type: str) -> str:
    t = (misp_type or "").lower()
    if t in ("ip-src", "ip-dst", "ip-src|port", "ip-dst|port"):
        return "ip"
    if t in ("domain", "hostname"):
        return "domain"
    if t.startswith("url"):
        return "url"
    if t in ("md5", "sha1", "sha256", "sha512", "filename|md5", "filename|sha256"):
        return "hash"
    if t == "vulnerability":
        return "cve"
    return "indicator"


def _misp_severity(level: str | None) -> str:
    # MISP threat_level_id: 1=high, 2=medium, 3=low, 4=undefined
    return {"1": "high", "2": "medium", "3": "low"}.get(
        str(level or ""), "medium",
    )


class OpenCTIOperatorFeed(BaseFeed):
    """Polls the operator's own OpenCTI instance every 30 min."""

    name = "opencti_operator"
    layer = "intel"
    default_interval_seconds = 1800

    async def poll(self) -> AsyncIterator[FeedEntry]:  # type: ignore[override]
        url = _resolve("opencti_url", env_var="ARGUS_OPENCTI_URL")
        token = _resolve("opencti", env_var="ARGUS_OPENCTI_TOKEN")
        if not url or not token:
            self.last_unconfigured_reason = (
                "OpenCTI URL + API token not set — see Settings → "
                "Services → OpenCTI for install + setup."
            )
            return

        try:
            from src.integrations.opencti.client import OpenCTIClient
        except Exception as exc:  # noqa: BLE001
            self.last_failure_reason = f"OpenCTI import failed: {exc}"
            self.last_failure_classification = "parse_error"
            return

        client = OpenCTIClient(api_url=url, api_key=token)
        try:
            result = await client.sync()
        except Exception as exc:  # noqa: BLE001
            self.last_failure_reason = f"OpenCTI sync failed: {exc}"
            self.last_failure_classification = "network_error"
            return

        for ind in result.get("indicators", []) or []:
            value = ind.get("pattern") or ind.get("name")
            if not value:
                continue
            yield FeedEntry(
                feed_name=self.name,
                layer=self.layer,
                entry_type="indicator",
                value=str(value)[:512],
                label=f"OpenCTI[{(ind.get('name') or '')[:60]}]",
                description=ind.get("description"),
                severity=_opencti_severity(ind.get("x_opencti_score")),
                confidence=0.8,
                feed_metadata={
                    "source": "opencti_operator",
                    "id": ind.get("id"),
                    "pattern_type": ind.get("pattern_type"),
                    "valid_from": ind.get("valid_from"),
                    "score": ind.get("x_opencti_score"),
                },
                expires_hours=720,
            )


def _opencti_severity(score: object) -> str:
    try:
        s = int(score or 0)
    except (TypeError, ValueError):
        s = 0
    if s >= 80:
        return "critical"
    if s >= 60:
        return "high"
    if s >= 40:
        return "medium"
    return "low"


class WazuhFeed(BaseFeed):
    """Polls the operator's Wazuh manager every 10 min for fresh alerts."""

    name = "wazuh_manager"
    layer = "edr"
    default_interval_seconds = 600

    async def poll(self) -> AsyncIterator[FeedEntry]:  # type: ignore[override]
        url = _resolve("wazuh_url", env_var="ARGUS_WAZUH_URL")
        creds = _resolve("wazuh", env_var="ARGUS_WAZUH_API_KEY")
        if not url or not creds:
            self.last_unconfigured_reason = (
                "Wazuh URL + user:password not set — see Settings → "
                "Services → Wazuh (OSS — self-hosted) for install."
            )
            return

        try:
            from src.integrations.wazuh.client import WazuhClient
        except Exception as exc:  # noqa: BLE001
            self.last_failure_reason = f"Wazuh import failed: {exc}"
            self.last_failure_classification = "parse_error"
            return

        client = WazuhClient(api_url=url, api_key=creds)
        try:
            alerts = await client.get_alerts(limit=200)
        except Exception as exc:  # noqa: BLE001
            self.last_failure_reason = f"Wazuh get_alerts failed: {exc}"
            self.last_failure_classification = "network_error"
            return

        for a in alerts or []:
            rule = (a.get("rule") or {}) if isinstance(a, dict) else {}
            agent = (a.get("agent") or {}) if isinstance(a, dict) else {}
            value = (
                a.get("id")
                or a.get("_id")
                or rule.get("id")
                or "wazuh-alert"
            )
            yield FeedEntry(
                feed_name=self.name,
                layer=self.layer,
                entry_type="alert",
                value=str(value)[:512],
                label=f"Wazuh[{rule.get('description', '')[:60]}]",
                description=rule.get("description"),
                severity=_wazuh_severity(rule.get("level")),
                confidence=0.85,
                feed_metadata={
                    "source": "wazuh_manager",
                    "agent_id": agent.get("id"),
                    "agent_name": agent.get("name"),
                    "rule_id": rule.get("id"),
                    "rule_level": rule.get("level"),
                    "rule_groups": rule.get("groups"),
                },
                expires_hours=168,
            )


def _wazuh_severity(level: object) -> str:
    try:
        lvl = int(level or 0)
    except (TypeError, ValueError):
        lvl = 0
    if lvl >= 12:
        return "critical"
    if lvl >= 8:
        return "high"
    if lvl >= 4:
        return "medium"
    return "low"


# ────────────────────────────────────────────────────────────────────
# Probe feeds for the on-demand integrations.
#
# Caldera, Velociraptor, and CAPEv2 are not steady-state IOC feeds
# (Caldera = adversary ops, Velociraptor = endpoint hunts, CAPE =
# sample detonation). They're operator-triggered surfaces. To keep
# the dashboard honest about whether they're reachable + configured,
# we run a light hourly probe that hits each integration's status
# endpoint when configured. The probe yields zero ingestion rows but
# the FeedHealth row tells the operator: ``configured + reachable``,
# ``unconfigured``, or ``broken — here's why``.
# ────────────────────────────────────────────────────────────────────


class CalderaProbeFeed(BaseFeed):
    name = "caldera_probe"
    layer = "adversary_emulation"
    default_interval_seconds = 3600

    async def poll(self) -> AsyncIterator[FeedEntry]:  # type: ignore[override]
        url = _resolve("caldera_url", env_var="ARGUS_CALDERA_URL")
        key = _resolve("caldera", env_var="ARGUS_CALDERA_API_KEY")
        if not url or not key:
            self.last_unconfigured_reason = (
                "Caldera URL + API key not set — see Settings → "
                "Services → MITRE Caldera for install + setup."
            )
            return
        os.environ["ARGUS_CALDERA_URL"] = url
        os.environ["ARGUS_CALDERA_API_KEY"] = key
        try:
            from src.integrations.adversary_emulation import caldera as _cal
            res = await _cal.health_check()
        except Exception as exc:  # noqa: BLE001
            self.last_failure_reason = f"Caldera probe failed: {exc}"
            self.last_failure_classification = "network_error"
            return
        if not getattr(res, "ok", False):
            self.last_failure_reason = (
                getattr(res, "error", "") or "health_check returned not-ok"
            )[:200]
            self.last_failure_classification = "network_error"
            return
        # No yield — successful probe lands as feed_health=ok with 0 rows.
        return
        yield  # pragma: no cover — required for AsyncIterator typing


class VelociraptorProbeFeed(BaseFeed):
    name = "velociraptor_probe"
    layer = "forensics"
    default_interval_seconds = 3600

    async def poll(self) -> AsyncIterator[FeedEntry]:  # type: ignore[override]
        url = _resolve("velociraptor_url", env_var="ARGUS_VELOCIRAPTOR_URL")
        token = _resolve("velociraptor", env_var="ARGUS_VELOCIRAPTOR_TOKEN")
        if not url or not token:
            self.last_unconfigured_reason = (
                "Velociraptor URL + API token not set — see Settings "
                "→ Services → Velociraptor for install + setup."
            )
            return
        os.environ["ARGUS_VELOCIRAPTOR_URL"] = url
        os.environ["ARGUS_VELOCIRAPTOR_TOKEN"] = token
        try:
            from src.integrations.forensics import velociraptor as _v
            res = await _v.list_clients(limit=1)
        except Exception as exc:  # noqa: BLE001
            self.last_failure_reason = f"Velociraptor probe failed: {exc}"
            self.last_failure_classification = "network_error"
            return
        if not getattr(res, "ok", True) is True and getattr(res, "error", None):
            self.last_failure_reason = res.error[:200]
            self.last_failure_classification = "network_error"
            return
        return
        yield  # pragma: no cover


class CapeProbeFeed(BaseFeed):
    name = "cape_probe"
    layer = "sandbox"
    default_interval_seconds = 3600

    async def poll(self) -> AsyncIterator[FeedEntry]:  # type: ignore[override]
        url = _resolve("cape_url", env_var="ARGUS_CAPE_URL")
        if not url:
            self.last_unconfigured_reason = (
                "CAPE URL not set — see Settings → Services → CAPEv2."
            )
            return
        api_key = _resolve("cape", env_var="ARGUS_CAPE_API_KEY")
        try:
            from src.integrations.sandbox.cape import CapeConnector
            client = CapeConnector(base_url=url, api_key=api_key or None)
            res = await client.health_check()
        except Exception as exc:  # noqa: BLE001
            self.last_failure_reason = f"CAPE probe failed: {exc}"
            self.last_failure_classification = "network_error"
            return
        if not getattr(res, "ok", False):
            self.last_failure_reason = (
                getattr(res, "error", "") or "health_check returned not-ok"
            )[:200]
            self.last_failure_classification = "network_error"
            return
        return
        yield  # pragma: no cover
