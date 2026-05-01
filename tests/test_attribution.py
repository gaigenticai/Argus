"""Threat-actor attribution scoring (P2 #2.9) — integration tests.

Real Postgres. Verifies each of the five weighted signals fires
independently, the breakdown explains the confidence to the analyst,
and the ranking is stable when multiple candidate actors compete.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from src.intel.attribution import (
    AttributionScore,
    score_alert,
)
from src.intel.iran_apt_pack import seed_iran_apt_pack
from src.models.intel import ActorSighting, IOC, ThreatActor
from src.models.mitre import AttachmentSource, AttackTechniqueAttachment
from src.models.threat import Alert

pytestmark = pytest.mark.asyncio


async def _wipe_actors(session: AsyncSession):
    await session.execute(text("DELETE FROM iocs"))
    await session.execute(text("DELETE FROM actor_sightings"))
    await session.execute(text("DELETE FROM threat_actors"))
    await session.flush()


async def _seed_apt34(session: AsyncSession) -> ThreatActor:
    await seed_iran_apt_pack(session)
    apt34 = (await session.execute(
        select(ThreatActor).where(ThreatActor.primary_alias == "APT34")
    )).scalar_one()
    return apt34


async def _make_alert(
    session: AsyncSession, organization_id, *,
    title: str = "Attribution test alert",
    summary: str = "",
) -> Alert:
    a = Alert(
        organization_id=organization_id,
        category="phishing", severity="high",
        title=title, summary=summary or "Attribution test summary",
    )
    session.add(a)
    await session.flush()
    return a


# ── Direct sighting dominates ────────────────────────────────────────


async def test_direct_sighting_dominates(
    session: AsyncSession, organization,
):
    await _wipe_actors(session)
    apt34 = await _seed_apt34(session)
    alert = await _make_alert(session, organization["id"])
    session.add(ActorSighting(
        threat_actor_id=apt34.id, alert_id=alert.id,
        source_platform="test", alias_used="APT34",
    ))
    await session.flush()

    scores = await score_alert(session, alert_id=alert.id)
    assert scores
    top = scores[0]
    assert top.primary_alias == "APT34"
    direct = next(f for f in top.factors if f.name == "direct_sighting")
    assert direct.raw == 1.0
    assert top.confidence >= _expected_min_for_direct_sighting()


def _expected_min_for_direct_sighting() -> float:
    # weight on direct_sighting alone is 0.50; recency may add a tiny bit
    # if there's a sighting today. We expect at least 0.5 floor.
    return 0.50


# ── TTP overlap ──────────────────────────────────────────────────────


async def test_ttp_overlap_score(
    session: AsyncSession, organization,
):
    await _wipe_actors(session)
    apt34 = await _seed_apt34(session)
    alert = await _make_alert(session, organization["id"])

    # Attach two ATT&CK techniques. Both are in APT34's known_ttps so
    # overlap should be 100% → raw=1.0.
    for tid in ("T1566", "T1071.001"):
        session.add(AttackTechniqueAttachment(
            organization_id=organization["id"],
            entity_type="alert", entity_id=alert.id,
            matrix="enterprise", technique_external_id=tid,
            confidence=1.0, source=AttachmentSource.MANUAL.value,
        ))
    await session.flush()

    scores = await score_alert(session, alert_id=alert.id,
                                candidate_actor_ids=[apt34.id])
    ttp = next(f for f in scores[0].factors if f.name == "ttp_overlap")
    assert ttp.raw == pytest.approx(1.0)
    # No direct sighting — confidence ~ ttp(0.25) + recency(0..0.05)
    assert 0.25 <= scores[0].confidence <= 0.35


async def test_ttp_overlap_partial(
    session: AsyncSession, organization,
):
    await _wipe_actors(session)
    apt34 = await _seed_apt34(session)
    alert = await _make_alert(session, organization["id"])

    # 1-of-3 alert techniques is in APT34's known list.
    for tid in ("T1566", "T9999", "T8888"):
        session.add(AttackTechniqueAttachment(
            organization_id=organization["id"],
            entity_type="alert", entity_id=alert.id,
            matrix="enterprise", technique_external_id=tid,
            confidence=1.0, source=AttachmentSource.MANUAL.value,
        ))
    await session.flush()
    scores = await score_alert(
        session, alert_id=alert.id, candidate_actor_ids=[apt34.id],
    )
    ttp = next(f for f in scores[0].factors if f.name == "ttp_overlap")
    assert ttp.raw == pytest.approx(1 / 3, rel=0.05)


# ── IOC overlap ──────────────────────────────────────────────────────


async def test_ioc_overlap_direct_match(
    session: AsyncSession, organization,
):
    await _wipe_actors(session)
    apt34 = await _seed_apt34(session)
    now = datetime.now(timezone.utc)
    session.add(IOC(
        ioc_type="domain", value="evil-c2.example.com",
        confidence=0.9, first_seen=now, last_seen=now,
        threat_actor_id=apt34.id,
    ))
    alert = await _make_alert(
        session, organization["id"],
        summary="Investigation: callback to evil-c2.example.com captured",
    )
    await session.flush()
    scores = await score_alert(
        session, alert_id=alert.id, candidate_actor_ids=[apt34.id],
    )
    ioc = next(f for f in scores[0].factors if f.name == "ioc_overlap")
    assert ioc.raw > 0.0


async def test_infrastructure_cluster_apex_match(
    session: AsyncSession, organization,
):
    """Actor IOC is `evil.example.com`; alert mentions
    `subdomain.example.com`. Same apex → cluster signal fires."""
    await _wipe_actors(session)
    apt34 = await _seed_apt34(session)
    now = datetime.now(timezone.utc)
    session.add(IOC(
        ioc_type="domain", value="evil.example.com",
        confidence=0.9, first_seen=now, last_seen=now,
        threat_actor_id=apt34.id,
    ))
    alert = await _make_alert(
        session, organization["id"],
        summary="Beaconing observed to subdomain.example.com",
    )
    await session.flush()
    scores = await score_alert(
        session, alert_id=alert.id, candidate_actor_ids=[apt34.id],
    )
    cluster = next(f for f in scores[0].factors if f.name == "infrastructure_cluster")
    assert cluster.raw > 0.0


async def test_infrastructure_cluster_slash24_match(
    session: AsyncSession, organization,
):
    """Actor IOC is 198.51.100.7; alert mentions 198.51.100.42 — same /24."""
    await _wipe_actors(session)
    apt34 = await _seed_apt34(session)
    now = datetime.now(timezone.utc)
    session.add(IOC(
        ioc_type="ipv4", value="198.51.100.7",
        confidence=0.9, first_seen=now, last_seen=now,
        threat_actor_id=apt34.id,
    ))
    alert = await _make_alert(
        session, organization["id"],
        summary="Outbound connection to 198.51.100.42 observed",
    )
    await session.flush()
    scores = await score_alert(
        session, alert_id=alert.id, candidate_actor_ids=[apt34.id],
    )
    cluster = next(f for f in scores[0].factors if f.name == "infrastructure_cluster")
    assert cluster.raw > 0.0


# ── Recency ──────────────────────────────────────────────────────────


async def test_recency_decays_with_age(
    session: AsyncSession, organization,
):
    """Compare a fresh-sighting actor vs a 60-day-old-sighting actor:
    the fresher one's recency factor must be higher."""
    await _wipe_actors(session)
    await _seed_apt34(session)
    apt34 = (await session.execute(
        select(ThreatActor).where(ThreatActor.primary_alias == "APT34")
    )).scalar_one()
    apt35 = (await session.execute(
        select(ThreatActor).where(ThreatActor.primary_alias == "APT35")
    )).scalar_one()

    alert = await _make_alert(session, organization["id"])
    now = datetime.now(timezone.utc)

    fresh = ActorSighting(
        threat_actor_id=apt34.id, source_platform="test", alias_used="APT34",
    )
    stale = ActorSighting(
        threat_actor_id=apt35.id, source_platform="test", alias_used="APT35",
    )
    session.add(fresh)
    session.add(stale)
    await session.flush()

    # Backdate APT35's sighting via raw SQL — created_at has a
    # server_default = now() so a Python-side override is the only way.
    await session.execute(text(
        "UPDATE actor_sightings SET created_at = :ts WHERE id = :id"
    ), {"ts": now - timedelta(days=60), "id": stale.id})
    await session.flush()

    scores = await score_alert(
        session, alert_id=alert.id,
        candidate_actor_ids=[apt34.id, apt35.id],
    )
    by_alias = {s.primary_alias: s for s in scores}
    rec_apt34 = next(f for f in by_alias["APT34"].factors if f.name == "recency")
    rec_apt35 = next(f for f in by_alias["APT35"].factors if f.name == "recency")
    assert rec_apt34.raw > rec_apt35.raw


# ── Ranking + edge cases ────────────────────────────────────────────


async def test_ranking_descending_by_confidence(
    session: AsyncSession, organization,
):
    await _wipe_actors(session)
    await _seed_apt34(session)
    apt34 = (await session.execute(
        select(ThreatActor).where(ThreatActor.primary_alias == "APT34")
    )).scalar_one()
    apt35 = (await session.execute(
        select(ThreatActor).where(ThreatActor.primary_alias == "APT35")
    )).scalar_one()
    alert = await _make_alert(session, organization["id"])

    # APT34: direct sighting + TTP attachment that's in known_ttps.
    session.add(ActorSighting(
        threat_actor_id=apt34.id, alert_id=alert.id,
        source_platform="test", alias_used="APT34",
    ))
    session.add(AttackTechniqueAttachment(
        organization_id=organization["id"],
        entity_type="alert", entity_id=alert.id,
        matrix="enterprise", technique_external_id="T1566",
        confidence=1.0, source=AttachmentSource.MANUAL.value,
    ))
    await session.flush()

    scores = await score_alert(
        session, alert_id=alert.id,
        candidate_actor_ids=[apt34.id, apt35.id],
    )
    assert [s.primary_alias for s in scores][:2] == ["APT34", "APT35"] \
        or scores[0].confidence > scores[1].confidence
    assert scores[0].primary_alias == "APT34"


async def test_score_alert_unknown_alert_returns_empty(
    session: AsyncSession,
):
    assert await score_alert(session, alert_id=uuid.uuid4()) == []


async def test_to_dict_shape(
    session: AsyncSession, organization,
):
    await _wipe_actors(session)
    await _seed_apt34(session)
    alert = await _make_alert(session, organization["id"])
    scores = await score_alert(session, alert_id=alert.id, limit=1)
    assert scores
    d = scores[0].to_dict()
    assert set(d.keys()) >= {
        "actor_id", "primary_alias", "aliases", "confidence", "factors",
    }
    assert all(set(f.keys()) >= {"name", "weight", "raw", "contribution"}
               for f in d["factors"])


# ── HTTP route ──────────────────────────────────────────────────────


async def test_attribution_route(client, analyst_user, test_engine, make_alert):
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    from src.core.tenant import get_system_org_id

    factory = async_sessionmaker(test_engine, class_=AsyncSession,
                                  expire_on_commit=False)
    async with factory() as s:
        sys_org_id = await get_system_org_id(s)
    a_id = await make_alert(sys_org_id)
    r = await client.get(
        f"/api/v1/alerts/{a_id}/attribution",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "scores" in body
    assert isinstance(body["scores"], list)


async def test_attribution_route_404(client, analyst_user):
    bogus = "00000000-0000-0000-0000-000000000000"
    r = await client.get(
        f"/api/v1/alerts/{bogus}/attribution",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 404
