"""Per-alert MITRE ATT&CK Navigator layer (P2 #2.6) — integration tests.

Real Postgres. Verifies that the layer combines (a) direct technique
attachments on the alert with (b) curated TTPs from any sighted actor,
and that each technique square preserves provenance in its comment.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.intel.iran_apt_pack import seed_iran_apt_pack
from src.intel.navigator_layer import build_alert_layer, build_layer
from src.models.intel import ActorSighting, ThreatActor
from src.models.mitre import AttachmentSource, AttackTechniqueAttachment
from src.models.threat import Alert
from sqlalchemy import select

pytestmark = pytest.mark.asyncio


# ── Generic builder unit tests ────────────────────────────────────────


def test_build_layer_dedupes_techniques_and_merges_comments():
    layer = build_layer(
        name="t",
        description="d",
        techniques_enterprise=[
            ("T1566", "triage_agent"),
            ("T1566", "actor:APT34"),
            ("T1190", "manual"),
        ],
    )
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert ids == ["T1566", "T1190"], ids
    t1566 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1566")
    assert "triage_agent" in t1566["comment"]
    assert "actor:APT34" in t1566["comment"]


def test_build_layer_ics_domain():
    layer = build_layer(
        name="t", description="d",
        techniques_ics=[("T0809", "actor:Cyber Av3ngers")],
        matrix="ics",
    )
    assert layer["domain"] == "ics-attack"
    assert "filters" not in layer  # ICS layers don't carry the platform filter


def test_build_layer_v45_versions():
    layer = build_layer(name="t", description="d")
    assert layer["versions"] == {
        "attack": "14", "navigator": "4.5", "layer": "4.5",
    }


# ── Per-alert layer integration ──────────────────────────────────────


async def _make_alert(session: AsyncSession, organization_id) -> Alert:
    a = Alert(
        organization_id=organization_id,
        category="phishing", severity="high",
        title="P2 navigator-layer test",
        summary="alert with mixed technique sources",
    )
    session.add(a)
    await session.flush()
    return a


async def test_alert_layer_combines_attachments_and_actor_ttps(
    session: AsyncSession, organization,
):
    # Seed Iran-APT pack so APT34 exists with curated TTPs.
    from sqlalchemy import text
    await session.execute(text(
        "DELETE FROM threat_actors WHERE primary_alias = ANY(:names)"
    ), {"names": ["APT34"]})
    await session.flush()
    await seed_iran_apt_pack(session)
    await session.flush()

    apt34 = (await session.execute(
        select(ThreatActor).where(ThreatActor.primary_alias == "APT34")
    )).scalar_one()

    alert = await _make_alert(session, organization["id"])

    # 1. Direct technique attachment from a (simulated) triage agent run.
    session.add(AttackTechniqueAttachment(
        organization_id=organization["id"],
        entity_type="alert", entity_id=alert.id,
        matrix="enterprise", technique_external_id="T1566",
        confidence=0.9, source=AttachmentSource.TRIAGE_AGENT.value,
        note="triage_agent matched 'phishing' keyword",
    ))
    # 2. Sighting linking the alert to APT34.
    session.add(ActorSighting(
        threat_actor_id=apt34.id, alert_id=alert.id,
        source_platform="test", alias_used="APT34",
    ))
    await session.flush()

    layer = await build_alert_layer(session, alert_id=alert.id)
    assert layer is not None
    assert layer["domain"] == "enterprise-attack"
    ids = [t["techniqueID"] for t in layer["techniques"]]

    # Triage attachment present.
    assert "T1566" in ids
    # Every APT34 enterprise technique present.
    apt34_ent = (apt34.profile_data or {}).get("ttps_enterprise") or apt34.known_ttps
    for tid in apt34_ent:
        if not tid.startswith("T0"):
            assert tid in ids, f"APT34 TTP {tid} missing from layer"

    # Provenance preserved on T1566 — both triage_agent + actor lineage.
    t1566 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1566")
    assert "triage_agent" in t1566["comment"], t1566["comment"]
    if "T1566" in (apt34.profile_data or {}).get("ttps_enterprise", []):
        assert "actor:APT34" in t1566["comment"]

    # Metadata carries the alert id + org id for audit trail.
    md = {m["name"]: m["value"] for m in layer["metadata"]}
    assert md["argus_alert_id"] == str(alert.id)
    assert md["argus_alert_category"] == "phishing"


async def test_alert_layer_returns_none_for_missing_alert(
    session: AsyncSession,
):
    layer = await build_alert_layer(session, alert_id=uuid.uuid4())
    assert layer is None


async def test_alert_layer_with_no_techniques_still_valid(
    session: AsyncSession, organization,
):
    """An alert with zero technique attachments + zero actor sightings
    still produces a valid v4.5 layer (techniques: [])."""
    alert = await _make_alert(session, organization["id"])
    layer = await build_alert_layer(session, alert_id=alert.id)
    assert layer is not None
    assert layer["versions"]["layer"] == "4.5"
    assert layer["techniques"] == []


async def test_alert_layer_ics_matrix_filters_correctly(
    session: AsyncSession, organization,
):
    alert = await _make_alert(session, organization["id"])
    # T0809 is ICS; T1566 is enterprise.
    session.add(AttackTechniqueAttachment(
        organization_id=organization["id"],
        entity_type="alert", entity_id=alert.id,
        matrix="ics", technique_external_id="T0809",
        confidence=1.0, source=AttachmentSource.MANUAL.value,
    ))
    session.add(AttackTechniqueAttachment(
        organization_id=organization["id"],
        entity_type="alert", entity_id=alert.id,
        matrix="enterprise", technique_external_id="T1566",
        confidence=1.0, source=AttachmentSource.MANUAL.value,
    ))
    await session.flush()

    ent = await build_alert_layer(session, alert_id=alert.id, matrix="enterprise")
    ics = await build_alert_layer(session, alert_id=alert.id, matrix="ics")
    assert [t["techniqueID"] for t in ent["techniques"]] == ["T1566"]
    assert [t["techniqueID"] for t in ics["techniques"]] == ["T0809"]


# ── HTTP route ───────────────────────────────────────────────────────


async def test_alert_navigator_route_streams_layer_json(
    client, analyst_user, test_engine, make_alert,
):
    """Resolve the system org via the cached resolver (matches what the
    route does) and create the alert under it — otherwise the route's
    tenant guard 404s on a foreign alert."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    from src.core.tenant import get_system_org_id

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        sys_org_id = await get_system_org_id(s)

    a_id = await make_alert(sys_org_id)
    r = await client.get(
        f"/api/v1/alerts/{a_id}/navigator-layer",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["versions"]["layer"] == "4.5"
    assert "argus-alert-" in r.headers.get("content-disposition", "")


async def test_alert_navigator_route_404_for_unknown_alert(
    client, analyst_user,
):
    bogus = "00000000-0000-0000-0000-000000000000"
    r = await client.get(
        f"/api/v1/alerts/{bogus}/navigator-layer",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 404
