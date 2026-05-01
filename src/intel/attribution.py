"""Threat-actor attribution scoring (P2 #2.9).

Given an alert, rank candidate threat actors by confidence with a
breakdown of each contributing factor so the dashboard can answer the
CISO's "85% likely vs 40% likely?" question with evidence.

Five weighted signals (each 0–1, summed and capped at 1.0):

  direct_sighting        0.50 — an ``ActorSighting`` row directly
                                 linked to this alert
  ttp_overlap            0.25 — fraction of the alert's MITRE techniques
                                 (via AttackTechniqueAttachment) that
                                 appear in ``actor.known_ttps``
  ioc_overlap            0.15 — IOCs linked to the actor whose value
                                 appears in the alert's title/summary/
                                 details/matched_entities
  recency                0.05 — time since the actor's most-recent
                                 sighting (decays over 90 days)
  infrastructure_cluster 0.05 — actor's IOCs sharing apex domain or /24
                                 with any value in the alert's matched
                                 entities

The output is a list of :class:`AttributionScore` ranked DESC. Pure
read-only — no DB writes. Caller may persist the top hit on the alert
via ``alert.details['attribution']`` if desired.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# Decay window for sighting recency: a sighting older than 90 days
# contributes 0; a sighting today contributes 1.
_RECENCY_WINDOW_DAYS = 90


@dataclass
class AttributionFactor:
    name: str
    weight: float
    raw: float           # 0-1 raw score for this factor
    contribution: float  # raw * weight
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "weight": self.weight,
            "raw": round(self.raw, 3),
            "contribution": round(self.contribution, 3),
            "detail": self.detail,
        }


@dataclass
class AttributionScore:
    actor_id: uuid.UUID
    primary_alias: str
    aliases: list[str]
    confidence: float                    # capped at 1.0
    factors: list[AttributionFactor] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_id": str(self.actor_id),
            "primary_alias": self.primary_alias,
            "aliases": list(self.aliases or []),
            "confidence": round(self.confidence, 3),
            "factors": [f.to_dict() for f in self.factors],
        }


# ── Weighting ───────────────────────────────────────────────────────


_WEIGHTS: dict[str, float] = {
    "direct_sighting":        0.50,
    "ttp_overlap":            0.25,
    "ioc_overlap":            0.15,
    "recency":                0.05,
    "infrastructure_cluster": 0.05,
}


# ── Helpers ─────────────────────────────────────────────────────────


_DOMAIN_RE = re.compile(r"\b([a-z0-9-]+\.[a-z0-9.-]+)\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _apex(domain: str) -> str:
    """Crude apex-domain extraction (last-two-labels). Good enough for
    cluster-proximity matching without pulling tldextract."""
    parts = (domain or "").lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (domain or "").lower()


def _slash24(ip: str) -> str:
    """Return the /24 of an IPv4 address. Empty string for non-IPv4."""
    m = _IPV4_RE.search(ip or "")
    if not m:
        return ""
    octets = m.group(0).split(".")
    return ".".join(octets[:3]) + ".0/24"


def _alert_text_corpus(alert) -> str:
    """Concatenate the textual + JSONB fields the matcher searches against."""
    bits: list[str] = []
    for s in (alert.title, alert.summary, alert.agent_reasoning):
        if s:
            bits.append(s)
    for blob in (alert.details, alert.matched_entities):
        if isinstance(blob, dict):
            bits.append(_flatten_jsonb(blob))
    return "\n".join(bits)


def _flatten_jsonb(blob: dict | list | str | int | float | None) -> str:
    if blob is None:
        return ""
    if isinstance(blob, str):
        return blob
    if isinstance(blob, (int, float)):
        return str(blob)
    if isinstance(blob, list):
        return " ".join(_flatten_jsonb(x) for x in blob)
    if isinstance(blob, dict):
        return " ".join(_flatten_jsonb(v) for v in blob.values())
    return ""


# ── Per-factor scorers ──────────────────────────────────────────────


async def _score_direct_sighting(
    session: AsyncSession, *, alert_id: uuid.UUID, actor_id: uuid.UUID,
) -> AttributionFactor:
    from src.models.intel import ActorSighting

    cnt = (await session.execute(
        select(func.count(ActorSighting.id)).where(
            ActorSighting.alert_id == alert_id,
            ActorSighting.threat_actor_id == actor_id,
        )
    )).scalar_one()
    raw = 1.0 if cnt > 0 else 0.0
    return AttributionFactor(
        name="direct_sighting",
        weight=_WEIGHTS["direct_sighting"],
        raw=raw,
        contribution=raw * _WEIGHTS["direct_sighting"],
        detail=f"{cnt} sighting(s) on this alert",
    )


async def _score_ttp_overlap(
    session: AsyncSession, *, alert_id: uuid.UUID, actor,
) -> AttributionFactor:
    from src.models.mitre import AttackTechniqueAttachment

    rows = (await session.execute(
        select(AttackTechniqueAttachment.technique_external_id).where(
            AttackTechniqueAttachment.entity_type == "alert",
            AttackTechniqueAttachment.entity_id == alert_id,
        )
    )).scalars().all()
    alert_techs = {t for t in rows if t}
    actor_techs = set(actor.known_ttps or [])
    if not alert_techs or not actor_techs:
        raw = 0.0
        detail = "no overlap (alert has 0 ATT&CK tags or actor has 0 known TTPs)"
    else:
        # Match base + sub-technique:  T1566 ↔ T1566.001
        def _expand(t: str) -> set[str]:
            return {t, t.split(".")[0]}
        actor_expanded = set().union(*(_expand(t) for t in actor_techs))
        alert_expanded = set().union(*(_expand(t) for t in alert_techs))
        overlap = alert_techs & actor_techs | (alert_expanded & actor_expanded)
        # Score as overlap_count / alert_techs_count (recall-style).
        raw = min(len(overlap) / max(len(alert_techs), 1), 1.0)
        detail = (f"{len(overlap)} of {len(alert_techs)} alert techniques "
                  f"in actor's known_ttps")
    return AttributionFactor(
        name="ttp_overlap",
        weight=_WEIGHTS["ttp_overlap"],
        raw=raw,
        contribution=raw * _WEIGHTS["ttp_overlap"],
        detail=detail,
    )


async def _score_ioc_overlap(
    session: AsyncSession, *, alert, actor_id: uuid.UUID,
) -> tuple[AttributionFactor, AttributionFactor]:
    """Returns a (ioc_overlap, infrastructure_cluster) pair — both
    factors share the same DB read."""
    from src.models.intel import IOC

    actor_iocs = (await session.execute(
        select(IOC.value, IOC.ioc_type).where(IOC.threat_actor_id == actor_id)
    )).all()
    if not actor_iocs:
        zero = AttributionFactor(
            name="ioc_overlap", weight=_WEIGHTS["ioc_overlap"],
            raw=0.0, contribution=0.0,
            detail="actor has no IOCs",
        )
        zero_cluster = AttributionFactor(
            name="infrastructure_cluster",
            weight=_WEIGHTS["infrastructure_cluster"],
            raw=0.0, contribution=0.0, detail="actor has no IOCs",
        )
        return zero, zero_cluster

    text = _alert_text_corpus(alert).lower()
    if not text:
        zero = AttributionFactor(
            name="ioc_overlap", weight=_WEIGHTS["ioc_overlap"],
            raw=0.0, contribution=0.0,
            detail="alert has no searchable text",
        )
        zero_cluster = AttributionFactor(
            name="infrastructure_cluster",
            weight=_WEIGHTS["infrastructure_cluster"],
            raw=0.0, contribution=0.0,
            detail="alert has no searchable text",
        )
        return zero, zero_cluster

    direct_hits = 0
    cluster_hits = 0
    alert_apex_domains = {_apex(d.lower()) for d in _DOMAIN_RE.findall(text)}
    alert_subnets = {_slash24(ip) for ip in _IPV4_RE.findall(text)}
    alert_apex_domains.discard("")
    alert_subnets.discard("")

    for value, ioc_type in actor_iocs:
        if not value:
            continue
        v = value.lower()
        # Direct match anywhere in alert text.
        if v in text:
            direct_hits += 1
            continue
        if ioc_type == "domain":
            if _apex(v) in alert_apex_domains:
                cluster_hits += 1
        elif ioc_type in ("ip", "ipv4", "ip_address"):
            if _slash24(v) in alert_subnets:
                cluster_hits += 1

    direct_raw = min(direct_hits / max(len(actor_iocs), 1), 1.0)
    cluster_raw = min(cluster_hits / max(len(actor_iocs), 1), 1.0)

    return (
        AttributionFactor(
            name="ioc_overlap",
            weight=_WEIGHTS["ioc_overlap"],
            raw=direct_raw,
            contribution=direct_raw * _WEIGHTS["ioc_overlap"],
            detail=f"{direct_hits} of {len(actor_iocs)} actor IOCs appear in alert text",
        ),
        AttributionFactor(
            name="infrastructure_cluster",
            weight=_WEIGHTS["infrastructure_cluster"],
            raw=cluster_raw,
            contribution=cluster_raw * _WEIGHTS["infrastructure_cluster"],
            detail=(
                f"{cluster_hits} actor IOC(s) share apex domain or /24 with "
                "alert content"
            ),
        ),
    )


async def _score_recency(
    session: AsyncSession, *, actor_id: uuid.UUID,
) -> AttributionFactor:
    from src.models.intel import ActorSighting

    most_recent = (await session.execute(
        select(func.max(ActorSighting.created_at)).where(
            ActorSighting.threat_actor_id == actor_id,
        )
    )).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if most_recent is None:
        return AttributionFactor(
            name="recency", weight=_WEIGHTS["recency"],
            raw=0.0, contribution=0.0,
            detail="no sightings on record",
        )
    if most_recent.tzinfo is None:
        most_recent = most_recent.replace(tzinfo=timezone.utc)
    age_days = (now - most_recent).days
    raw = max(0.0, 1.0 - age_days / _RECENCY_WINDOW_DAYS)
    return AttributionFactor(
        name="recency", weight=_WEIGHTS["recency"],
        raw=raw, contribution=raw * _WEIGHTS["recency"],
        detail=f"most-recent sighting was {age_days}d ago",
    )


# ── Public entry point ──────────────────────────────────────────────


_DEFAULT_CANDIDATE_LIMIT = 25


async def score_alert(
    session: AsyncSession,
    *,
    alert_id: uuid.UUID,
    candidate_actor_ids: list[uuid.UUID] | None = None,
    limit: int = 10,
) -> list[AttributionScore]:
    """Rank threat actors by confidence for the given alert.

    ``candidate_actor_ids`` is optional — defaults to every actor the
    alert touches via either a sighting or an IOC (closest match first
    cuts the candidate pool drastically vs scoring against the entire
    catalogue).
    """
    from src.models.intel import ActorSighting, IOC, ThreatActor
    from src.models.threat import Alert

    alert = await session.get(Alert, alert_id)
    if alert is None:
        return []

    # Build candidate pool. Prefer the explicit list when provided.
    if candidate_actor_ids:
        candidate_ids = list(candidate_actor_ids)[: _DEFAULT_CANDIDATE_LIMIT]
    else:
        sighting_actor_ids = (await session.execute(
            select(ActorSighting.threat_actor_id).where(
                ActorSighting.alert_id == alert_id,
            )
        )).scalars().all()
        # Also pull actors whose IOCs match the alert's matched_entities
        # text — by far the strongest "this is who" signal short of a
        # direct sighting.
        text = _alert_text_corpus(alert).lower()
        ioc_actor_ids: list[uuid.UUID] = []
        if text:
            ioc_rows = (await session.execute(
                select(IOC.threat_actor_id, IOC.value).where(
                    IOC.threat_actor_id.is_not(None),
                )
            )).all()
            for actor_id, value in ioc_rows:
                if value and value.lower() in text:
                    ioc_actor_ids.append(actor_id)
        candidate_ids = list({*sighting_actor_ids, *ioc_actor_ids})
        if not candidate_ids:
            # Fall back to the top-K most-active actors so the dashboard
            # still surfaces *something* on every alert.
            top = (await session.execute(
                select(ThreatActor.id)
                .order_by(ThreatActor.risk_score.desc(),
                          ThreatActor.last_seen.desc())
                .limit(_DEFAULT_CANDIDATE_LIMIT)
            )).scalars().all()
            candidate_ids = list(top)
        else:
            candidate_ids = candidate_ids[: _DEFAULT_CANDIDATE_LIMIT]

    if not candidate_ids:
        return []

    actors = (await session.execute(
        select(ThreatActor).where(ThreatActor.id.in_(candidate_ids))
    )).scalars().all()

    out: list[AttributionScore] = []
    for actor in actors:
        f_direct = await _score_direct_sighting(
            session, alert_id=alert_id, actor_id=actor.id,
        )
        f_ttp = await _score_ttp_overlap(
            session, alert_id=alert_id, actor=actor,
        )
        f_ioc, f_cluster = await _score_ioc_overlap(
            session, alert=alert, actor_id=actor.id,
        )
        f_recency = await _score_recency(session, actor_id=actor.id)
        factors = [f_direct, f_ttp, f_ioc, f_cluster, f_recency]
        confidence = min(sum(f.contribution for f in factors), 1.0)
        out.append(AttributionScore(
            actor_id=actor.id,
            primary_alias=actor.primary_alias,
            aliases=list(actor.aliases or []),
            confidence=confidence,
            factors=factors,
        ))

    out.sort(key=lambda s: s.confidence, reverse=True)
    return out[:limit]
