"""Auto-fan-out of alerts to every configured outbound integration.

When an alert is dispatched, the platform forwards it to every
SIEM / SOAR / EDR / Shuffle integration that has live credentials —
without the operator having to add a webhook endpoint by hand. This
is what gives the OSS-self-hosted promise teeth: the operator drops a
URL + token into Settings and alerts immediately start flowing.

Failure mode: each fan-out target is best-effort and isolated. A
broken Shuffle does not block OpenSearch, and vice versa. Errors are
logged but never bubble up, so the originating alert pipeline stays
healthy.
"""

from __future__ import annotations


import logging
from typing import Any

from src.core import integration_keys as _integration_keys

logger = logging.getLogger(__name__)


async def fanout_alert(alert: Any) -> dict[str, str]:
    """Forward an alert to every configured outbound integration.

    Returns a dict ``{integration_name: outcome}`` for telemetry.
    Outcomes are one of: ``ok``, ``unconfigured``, ``error: <msg>``.
    """
    results: dict[str, str] = {}

    # ── SIEM forwarders ────────────────────────────────────────────
    try:
        from src.integrations.siem import CONNECTORS as _SIEM
        for name, cls in _SIEM.items():
            try:
                inst = cls()
                if not inst.is_configured():
                    results[f"siem.{name}"] = "unconfigured"
                    continue
                push_result = await inst.push_alert(alert)
                results[f"siem.{name}"] = (
                    "ok" if getattr(push_result, "success", False)
                    else f"error: {getattr(push_result, 'note', 'unknown')}"
                )
            except Exception as exc:  # noqa: BLE001
                results[f"siem.{name}"] = f"error: {exc}"
                logger.debug("siem.%s push failed: %s", name, exc)
    except Exception as exc:  # noqa: BLE001
        logger.debug("siem fanout import failed: %s", exc)

    # ── SOAR connectors ────────────────────────────────────────────
    try:
        from src.integrations.soar.tines import TinesConnector
        from src.integrations.soar.xsoar import XsoarConnector
        from src.integrations.soar.splunk_soar import SplunkSoarConnector
        from src.integrations.soar.cortex import CortexConnector
        for cls in (TinesConnector, XsoarConnector, SplunkSoarConnector, CortexConnector):
            try:
                inst = cls()
                if not inst.is_configured():
                    results[f"soar.{cls.__name__}"] = "unconfigured"
                    continue
                event = _alert_to_event_dict(alert)
                push_result = await inst.push_events([event])
                results[f"soar.{cls.__name__}"] = (
                    "ok" if getattr(push_result, "success", False)
                    else f"error: {getattr(push_result, 'note', 'unknown')}"
                )
            except Exception as exc:  # noqa: BLE001
                results[f"soar.{cls.__name__}"] = f"error: {exc}"
                logger.debug("soar.%s push failed: %s", cls.__name__, exc)
    except Exception as exc:  # noqa: BLE001
        logger.debug("soar fanout import failed: %s", exc)

    # ── Shuffle SOAR (OSS) ─────────────────────────────────────────
    shuffle_url = (
        _integration_keys.get("shuffle_url", env_fallback="ARGUS_SHUFFLE_URL")
        or ""
    ).strip()
    shuffle_key = (
        _integration_keys.get("shuffle", env_fallback="ARGUS_SHUFFLE_API_KEY")
        or ""
    ).strip()
    if shuffle_url and shuffle_key:
        # Operator must create a workflow in Shuffle and paste its ID
        # into ``ARGUS_SHUFFLE_DEFAULT_WORKFLOW_ID`` (or via integration
        # keys cache under name ``shuffle_workflow``). Without it we
        # have nothing to trigger.
        workflow_id = (
            _integration_keys.get(
                "shuffle_workflow",
                env_fallback="ARGUS_SHUFFLE_DEFAULT_WORKFLOW_ID",
            ) or ""
        ).strip()
        if not workflow_id:
            results["shuffle"] = "unconfigured: no default workflow id"
        else:
            try:
                from src.integrations.shuffle.client import ShuffleIntegration
                client = ShuffleIntegration(api_url=shuffle_url, api_key=shuffle_key)
                await client.trigger_workflow(
                    workflow_id=workflow_id,
                    alert_data=_alert_to_event_dict(alert),
                )
                results["shuffle"] = "ok"
            except Exception as exc:  # noqa: BLE001
                results["shuffle"] = f"error: {exc}"
                logger.debug("shuffle fanout failed: %s", exc)
    else:
        results["shuffle"] = "unconfigured"

    # ── EDR push (CrowdStrike / MDE / S1) ──────────────────────────
    # EDR integrations push IOCs (not alerts) — handled by the
    # ``ioc_push`` hook in the IOC ingestion path, not here.
    return results


def _alert_to_event_dict(alert: Any) -> dict[str, Any]:
    """Normalise an Alert ORM (or dict) into a flat event dict.

    SOAR connectors expect a dict; SIEM connectors handle the Alert
    object directly via the ``push_alert`` adapter on the base class.
    """
    if isinstance(alert, dict):
        return dict(alert)
    out: dict[str, Any] = {}
    for attr in (
        "id", "alert_type", "severity", "title", "description",
        "organization_id", "created_at", "metadata", "source",
    ):
        v = getattr(alert, attr, None)
        if v is None:
            continue
        out[attr] = (
            v.isoformat() if hasattr(v, "isoformat") else
            (str(v) if not isinstance(v, (dict, list, int, float, bool, str)) else v)
        )
    return out
