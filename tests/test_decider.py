"""CISA Decider — auto-map text → ATT&CK techniques (P2 #2.2).

Pure-function tests on :func:`classify_text` plus a real-Postgres
test for :func:`apply_decider_to_alert` (idempotency, source tagging,
multi-keyword stacking).
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.intel.decider import (
    DeciderHit,
    apply_decider_to_alert,
    classify_text,
    corpus_version,
    rule_count,
)
from src.models.mitre import AttackTechniqueAttachment
from src.models.threat import Alert

pytestmark = pytest.mark.asyncio


# ── Pure scorer ───────────────────────────────────────────────────────


def test_corpus_health():
    assert rule_count() >= 60
    assert "-" in corpus_version()  # date-stamped


def test_phishing_attachment_classified():
    hits = classify_text(
        "Spearphishing wave with weaponised PDF attachment targeting executives"
    )
    ids = [h.technique_id for h in hits]
    assert "T1566.001" in ids


def test_ransomware_recovery_inhibition_top_two():
    hits = classify_text(
        "LockBit encrypts files, drops ransom note, then runs vssadmin "
        "delete shadows to inhibit recovery"
    )
    top_two = {h.technique_id for h in hits[:2]}
    assert {"T1486", "T1490"} <= top_two


def test_lsass_dump_top_hit():
    hits = classify_text(
        "Mimikatz used to dump LSASS memory; password spraying detected"
    )
    assert hits[0].technique_id == "T1003.001"


def test_dns_c2_recognised():
    hits = classify_text(
        "MuddyWater C2 over DNS tunneling with base64-encoded payloads"
    )
    ids = [h.technique_id for h in hits]
    assert "T1071.004" in ids


def test_innocent_text_no_hits():
    assert classify_text("Q1 financial report attached") == []


def test_top_n_respected():
    text = (
        "Phishing wave delivering weaponised PDF attachment; powershell -enc "
        "loader encrypts files via lockbit; vssadmin delete shadows; "
        "lsass dump via mimikatz; dns c2 over base64-encoded traffic"
    )
    assert len(classify_text(text, top_n=2)) == 2
    assert len(classify_text(text, top_n=5)) <= 5


def test_word_boundary_no_substring_overmatch():
    """'phish' inside 'pharmaceutical' must not match the T1566 rule."""
    hits = classify_text("Q1 pharmaceutical sector report")
    assert all(h.technique_id != "T1566" for h in hits)


def test_to_dict_shape():
    hit = classify_text("password spraying detected")[0]
    d = hit.to_dict()
    assert set(d.keys()) == {"technique_id", "technique_name",
                              "confidence", "matched_keywords"}


# ── DB integration ────────────────────────────────────────────────────


async def _make_alert(session: AsyncSession, organization_id, *, title: str,
                       summary: str = "", reasoning: str = "") -> Alert:
    a = Alert(
        organization_id=organization_id,
        category="phishing", severity="high",
        title=title, summary=summary, agent_reasoning=reasoning,
    )
    session.add(a)
    await session.flush()
    return a


async def test_apply_decider_attaches_techniques(
    session: AsyncSession, organization,
):
    alert = await _make_alert(
        session, organization["id"],
        title="Mimikatz LSASS dump observed",
        summary="lsass.exe memory dumped via comsvcs.dll; password spraying followed",
    )
    inserted = await apply_decider_to_alert(session, alert_id=alert.id, top_n=3)
    await session.flush()

    rows = (await session.execute(
        select(AttackTechniqueAttachment).where(
            AttackTechniqueAttachment.entity_id == alert.id,
        )
    )).scalars().all()
    assert inserted >= 1
    assert {r.technique_external_id for r in rows} >= {"T1003.001"}
    # Source stamped triage_agent + provenance in note.
    assert all(r.source == "triage_agent" for r in rows)
    assert all("Decider" in (r.note or "") for r in rows)


async def test_apply_decider_idempotent(
    session: AsyncSession, organization,
):
    alert = await _make_alert(
        session, organization["id"],
        title="LockBit encrypts files via vssadmin delete shadows",
    )
    n1 = await apply_decider_to_alert(session, alert_id=alert.id)
    await session.flush()
    n2 = await apply_decider_to_alert(session, alert_id=alert.id)
    await session.flush()
    assert n1 > 0
    assert n2 == 0


async def test_apply_decider_no_text_returns_zero(
    session: AsyncSession, organization,
):
    alert = await _make_alert(
        session, organization["id"], title="x", summary="",
    )
    inserted = await apply_decider_to_alert(session, alert_id=alert.id)
    # 'x' is too short to match anything; classifier returns no hits;
    # nothing to insert.
    assert inserted == 0


# ── HTTP route ────────────────────────────────────────────────────────


async def test_decider_classify_route(client, analyst_user):
    r = await client.post(
        "/api/v1/intel/decider/classify",
        json={"text": "LockBit encrypts files, ransom note dropped"},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert "corpus_version" in data
    assert data["rule_count"] >= 60
    ids = [h["technique_id"] for h in data["hits"]]
    assert "T1486" in ids


async def test_decider_classify_requires_auth(client):
    r = await client.post(
        "/api/v1/intel/decider/classify",
        json={"text": "anything"},
    )
    assert r.status_code in (401, 403)
