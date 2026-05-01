"""MITRE ATT&CK Navigator v4.5 layer builder (P2 #2.6).

Generic emitter consumed by both the per-actor layer (P1 #1.4 — see
:mod:`src.intel.iran_apt_pack.build_navigator_layer`) and the per-alert
layer this module introduces.

The per-alert layer combines two sources:

  1. ``AttackTechniqueAttachment`` rows where ``entity_type='alert'``
     and ``entity_id=<alert.id>`` — these come from the triage agent,
     case copilot, manual analyst tagging, or the Iran-APT auto-apply
     hook in :func:`src.intel.iran_apt_pack.attach_actor_ttps_to_alert`.

  2. Every threat actor sighted on the alert (via :class:`ActorSighting`
     where ``alert_id=<alert.id>``) — the actor's ``known_ttps`` field
     contributes the curated TTP set for that actor.

Each technique entry carries provenance in its ``comment`` field so
the analyst sees *why* a square is highlighted: ``triage_agent``,
``mitre_group_link (APT34)``, ``manual``, etc.
"""

from __future__ import annotations

import uuid
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


_NAVIGATOR_VERSION = "4.5"
_ATTACK_VERSION = "14"


def _technique_entry(
    technique_id: str, *, comment: str, score: int = 1,
) -> dict[str, Any]:
    return {
        "techniqueID": technique_id,
        "score": score,
        "color": "",
        "comment": comment,
        "enabled": True,
        "metadata": [],
        "showSubtechniques": "." in technique_id,
    }


def build_layer(
    *,
    name: str,
    description: str,
    techniques_enterprise: Iterable[tuple[str, str]] = (),
    techniques_ics: Iterable[tuple[str, str]] = (),
    matrix: str = "enterprise",
    metadata: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a MITRE ATT&CK Navigator v4.5 layer JSON document.

    ``techniques_*`` are iterables of ``(technique_external_id,
    comment)`` pairs — the comment is shown when an analyst hovers the
    highlighted square in Navigator and is the audit trail for which
    rule / actor / agent put that technique on the layer.

    Multiple comments for the same technique ID are merged into a
    single ``comment`` separated by " | " so the layer doesn't ship
    duplicate squares.
    """
    if matrix == "ics":
        domain = "ics-attack"
        source = techniques_ics
    else:
        domain = "enterprise-attack"
        source = techniques_enterprise

    # Merge duplicate technique IDs while preserving the order of first
    # appearance.
    merged: dict[str, list[str]] = {}
    for tid, comment in source:
        if not tid:
            continue
        if tid in merged:
            if comment and comment not in merged[tid]:
                merged[tid].append(comment)
        else:
            merged[tid] = [comment] if comment else []

    techniques = [
        _technique_entry(tid, comment=" | ".join(comments) or "Argus")
        for tid, comments in merged.items()
    ]

    md_pairs = [{"name": k, "value": str(v)} for k, v in (metadata or {}).items()]

    layer: dict[str, Any] = {
        "name": name,
        "versions": {
            "attack": _ATTACK_VERSION,
            "navigator": _NAVIGATOR_VERSION,
            "layer": _NAVIGATOR_VERSION,
        },
        "domain": domain,
        "description": description,
        "sorting": 0,
        "viewMode": 0,
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#fff5e6", "#ff4f00"],
            "minValue": 0,
            "maxValue": 1,
        },
        "legendItems": [{"label": name, "color": "#ff4f00"}],
        "metadata": md_pairs,
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
    if matrix != "ics":
        layer["filters"] = {
            "platforms": [
                "Linux", "macOS", "Windows", "Network", "Containers",
                "Office 365", "Azure AD", "SaaS", "IaaS",
            ],
        }
    return layer


def _split_by_matrix(techniques: Iterable[tuple[str, str]]) -> tuple[
    list[tuple[str, str]], list[tuple[str, str]],
]:
    """ICS technique IDs are T0xxx; enterprise are T1xxx (with optional
    sub-technique ``.001``)."""
    enterprise: list[tuple[str, str]] = []
    ics: list[tuple[str, str]] = []
    for tid, comment in techniques:
        if (tid or "").startswith("T0"):
            ics.append((tid, comment))
        else:
            enterprise.append((tid, comment))
    return enterprise, ics


async def build_alert_layer(
    session: AsyncSession,
    *,
    alert_id: uuid.UUID,
    matrix: str = "enterprise",
) -> dict[str, Any] | None:
    """Build the per-alert Navigator layer.

    Returns ``None`` if the alert doesn't exist; otherwise always
    returns a valid layer (possibly with zero techniques).
    """
    from src.models.intel import ActorSighting, ThreatActor
    from src.models.mitre import AttackTechniqueAttachment
    from src.models.threat import Alert

    alert = await session.get(Alert, alert_id)
    if alert is None:
        return None

    # 1. Direct technique attachments on the alert (triage agent, manual,
    #    case-copilot, or the iran-pack auto-apply).
    attachments = (await session.execute(
        select(AttackTechniqueAttachment).where(
            AttackTechniqueAttachment.entity_type == "alert",
            AttackTechniqueAttachment.entity_id == alert_id,
        )
    )).scalars().all()

    techniques: list[tuple[str, str]] = []
    for att in attachments:
        comment = f"{att.source}"
        if att.note:
            comment += f": {att.note[:120]}"
        techniques.append((att.technique_external_id, comment))

    # 2. Sighted actors on this alert — their curated TTPs.
    sightings = (await session.execute(
        select(ActorSighting).where(ActorSighting.alert_id == alert_id)
    )).scalars().all()
    actor_ids = list({s.threat_actor_id for s in sightings})
    actors: list[ThreatActor] = []
    if actor_ids:
        actors = list(
            (await session.execute(
                select(ThreatActor).where(ThreatActor.id.in_(actor_ids))
            )).scalars().all()
        )
    for actor in actors:
        prefix = f"actor:{actor.primary_alias}"
        for tid in actor.known_ttps or []:
            techniques.append((tid, prefix))

    enterprise, ics = _split_by_matrix(techniques)

    layer_name = f"Argus alert — {alert.title[:60]}"
    bits = [
        f"Alert {alert.id}",
        f"category={alert.category}",
        f"severity={alert.severity}",
        f"status={alert.status}",
    ]
    if actors:
        bits.append("actors=" + ", ".join(a.primary_alias for a in actors))
    description = " · ".join(bits)

    return build_layer(
        name=layer_name,
        description=description,
        techniques_enterprise=enterprise,
        techniques_ics=ics,
        matrix=matrix,
        metadata={
            "argus_alert_id": str(alert.id),
            "argus_alert_category": alert.category,
            "argus_alert_severity": alert.severity,
            "argus_organization_id": str(alert.organization_id),
        },
    )
