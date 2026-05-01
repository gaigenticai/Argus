"""Iran-nexus APT pack — integration tests (P1 #1.4).

Real Postgres, no mocks. Verifies idempotent seeding, Navigator layer
JSON shape, and the auto-apply hook from
``src.enrichment.actor_tracker.identify_or_create_actor`` to
``AttackTechniqueAttachment``.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.intel.iran_apt_pack import (
    IRAN_APT_PACK,
    attach_actor_ttps_to_alert,
    build_navigator_layer,
    seed_iran_apt_pack,
)
from src.models.intel import ThreatActor
from src.models.mitre import AttackTechniqueAttachment
from src.models.threat import Alert

pytestmark = pytest.mark.asyncio


# --- Seeder -----------------------------------------------------------


async def test_seed_iran_apt_pack_idempotent(session: AsyncSession):
    """First run creates 6 actors; second run updates the same rows."""
    # Wipe in case a prior test run committed actors.
    from sqlalchemy import text
    await session.execute(text(
        "DELETE FROM threat_actors WHERE primary_alias = ANY(:names)"
    ), {"names": [e["primary_alias"] for e in IRAN_APT_PACK]})
    await session.flush()

    counts1 = await seed_iran_apt_pack(session)
    counts2 = await seed_iran_apt_pack(session)

    assert counts1["created"] == len(IRAN_APT_PACK)
    assert counts1["updated"] == 0
    assert counts2["created"] == 0
    assert counts2["updated"] == len(IRAN_APT_PACK)

    # Every actor exists exactly once.
    for entry in IRAN_APT_PACK:
        actors = (await session.execute(
            select(ThreatActor).where(
                ThreatActor.primary_alias == entry["primary_alias"]
            )
        )).scalars().all()
        assert len(actors) == 1, (
            f"actor {entry['primary_alias']} has {len(actors)} rows"
        )
        actor = actors[0]
        # known_ttps populated, profile_data tags the pack.
        assert actor.known_ttps, f"{actor.primary_alias} has no TTPs"
        assert actor.profile_data["pack"] == "iran_nexus"


# --- Navigator layer --------------------------------------------------


async def test_navigator_layer_shape(session: AsyncSession):
    """Layer JSON has v4.5 schema fields and one entry per TTP."""
    from sqlalchemy import text
    await session.execute(text(
        "DELETE FROM threat_actors WHERE primary_alias = ANY(:names)"
    ), {"names": [e["primary_alias"] for e in IRAN_APT_PACK]})
    await session.flush()
    await seed_iran_apt_pack(session)
    await session.flush()

    apt34 = (await session.execute(
        select(ThreatActor).where(ThreatActor.primary_alias == "APT34")
    )).scalar_one()

    layer = build_navigator_layer(apt34, matrix="enterprise")

    assert layer["versions"]["layer"] == "4.5"
    assert layer["versions"]["navigator"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert layer["name"].startswith("Argus — APT34")
    assert "Iran" in layer["description"] or "Iranian" in layer["description"]

    # Every entry in profile_data.ttps_enterprise must appear exactly once
    # in the layer techniques list.
    ent_ttps = apt34.profile_data["ttps_enterprise"]
    layer_ids = [t["techniqueID"] for t in layer["techniques"]]
    assert sorted(layer_ids) == sorted(ent_ttps)
    assert all(t["score"] == 1 and t["enabled"] for t in layer["techniques"])

    # Sub-techniques signalled.
    for t in layer["techniques"]:
        assert t["showSubtechniques"] == ("." in t["techniqueID"])

    # Metadata carries actor + pack identity.
    md = {m["name"]: m["value"] for m in layer["metadata"]}
    assert md["argus_actor_id"] == str(apt34.id)
    assert md["argus_pack"] == "iran_nexus"


async def test_navigator_layer_ics_for_cyber_av3ngers(session: AsyncSession):
    """Cyber Av3ngers has ICS techniques — the ICS layer is populated."""
    from sqlalchemy import text
    await session.execute(text(
        "DELETE FROM threat_actors WHERE primary_alias = ANY(:names)"
    ), {"names": [e["primary_alias"] for e in IRAN_APT_PACK]})
    await session.flush()
    await seed_iran_apt_pack(session)
    await session.flush()

    cav = (await session.execute(
        select(ThreatActor).where(
            ThreatActor.primary_alias == "Cyber Av3ngers"
        )
    )).scalar_one()
    ics_layer = build_navigator_layer(cav, matrix="ics")
    assert ics_layer["domain"] == "ics-attack"
    ids = [t["techniqueID"] for t in ics_layer["techniques"]]
    assert all(i.startswith("T0") for i in ids), ids
    assert "T0809" in ids  # Data Destruction


# --- Auto-apply hook --------------------------------------------------


async def test_attach_actor_ttps_to_alert(
    session: AsyncSession, organization
):
    """Auto-apply attaches every TTP to the alert, idempotent on re-run."""
    from sqlalchemy import text
    await session.execute(text(
        "DELETE FROM threat_actors WHERE primary_alias = ANY(:names)"
    ), {"names": [e["primary_alias"] for e in IRAN_APT_PACK]})
    await session.flush()
    await seed_iran_apt_pack(session)
    await session.flush()

    apt34 = (await session.execute(
        select(ThreatActor).where(ThreatActor.primary_alias == "APT34")
    )).scalar_one()

    alert = Alert(
        organization_id=organization["id"],
        category="phishing",
        severity="high",
        title="ttp-attach-test",
        summary="auto-apply hook integration test",
    )
    session.add(alert)
    await session.flush()

    attached1 = await attach_actor_ttps_to_alert(
        session,
        organization_id=organization["id"],
        alert_id=alert.id,
        actor=apt34,
    )
    await session.flush()
    assert attached1 == len(apt34.known_ttps)

    rows = (await session.execute(
        select(AttackTechniqueAttachment).where(
            AttackTechniqueAttachment.entity_type == "alert",
            AttackTechniqueAttachment.entity_id == alert.id,
        )
    )).scalars().all()
    assert len(rows) == len(apt34.known_ttps)
    assert {r.technique_external_id for r in rows} == set(apt34.known_ttps)
    # Every attachment carries the curated pack source + actor note.
    for r in rows:
        assert r.source == "mitre_group_link"
        assert "APT34" in (r.note or "")

    # Idempotency — re-running attaches nothing.
    attached2 = await attach_actor_ttps_to_alert(
        session,
        organization_id=organization["id"],
        alert_id=alert.id,
        actor=apt34,
    )
    assert attached2 == 0


async def test_navigator_layer_unknown_actor_returns_empty(
    session: AsyncSession,
):
    """Actors with no known_ttps still produce a valid (empty) layer."""
    from datetime import datetime, timezone
    actor = ThreatActor(
        primary_alias=f"empty-{uuid.uuid4().hex[:6]}",
        aliases=[],
        languages=[],
        forums_active=[],
        pgp_fingerprints=[],
        known_ttps=[],
        risk_score=0.0,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        total_sightings=0,
    )
    session.add(actor)
    await session.flush()

    layer = build_navigator_layer(actor)
    assert layer["versions"]["layer"] == "4.5"
    assert layer["techniques"] == []
