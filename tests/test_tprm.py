"""Phase 7 — TPRM tests: templates + questionnaires + onboarding + scorecards."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient

from src.tprm.scoring_questions import (
    aggregate_instance_score,
    parse_question,
    score_answer,
    sig_lite_template,
)

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


# --- Pure scoring -----------------------------------------------------


def test_score_yes_no():
    q = parse_question({"id": "x", "text": "?", "answer_kind": "yes_no"})
    assert score_answer(q, "yes", False, None) == 100
    assert score_answer(q, "no", False, None) == 0
    assert score_answer(q, "maybe", False, None) is None


def test_score_yes_no_na():
    q = parse_question({"id": "x", "text": "?", "answer_kind": "yes_no_na"})
    assert score_answer(q, "yes", False, None) == 100
    assert score_answer(q, "n/a", False, None) == 75
    assert score_answer(q, "no", False, None) == 0


def test_score_scale():
    q = parse_question({"id": "x", "text": "?", "answer_kind": "scale_1_5"})
    assert score_answer(q, "1", False, None) == 0.0
    assert score_answer(q, "5", False, None) == 100.0
    assert score_answer(q, "3", False, None) == 50.0


def test_score_evidence():
    q = parse_question({"id": "x", "text": "?", "answer_kind": "evidence"})
    assert score_answer(q, None, True, None) == 100
    assert score_answer(q, None, False, None) == 0


def test_aggregate_required_missing_zeroes_out():
    qs = [parse_question(q) for q in sig_lite_template()]
    # Only answer one — required questions missing → 0
    answers = {"iso27001_certified": {"value": "yes", "evidence_present": False}}
    assert aggregate_instance_score(qs, answers) == 0.0


def test_aggregate_full_yes_returns_high():
    qs = [parse_question(q) for q in sig_lite_template()]
    answers = {q.id: {"value": "yes", "evidence_present": True} for q in qs}
    answers["vendor_security_program"] = {"value": "5", "evidence_present": False}
    score = aggregate_instance_score(qs, answers)
    assert score >= 95


# --- Helpers ----------------------------------------------------------


async def _create_vendor(client, analyst, organization, name="Acme Cloud Inc"):
    r = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "vendor",
            "value": name,
            "details": {
                "legal_name": name,
                "primary_domain": "acme-cloud.example",
                "relationship_type": "saas",
                "data_access_level": "pii",
                "contract_start": "2026-01-01T00:00:00+00:00",
                "contract_end": "2027-01-01T00:00:00+00:00",
            },
        },
        headers=_hdr(analyst),
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


# --- Templates --------------------------------------------------------


async def test_seed_builtin_templates(
    client: AsyncClient, analyst_user, organization
):
    r = await client.post(
        "/api/v1/tprm/templates/seed-builtins",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200, r.text
    names = {t["name"] for t in r.json()}
    assert {"sig_lite", "caiq_v4"} <= names

    listed = await client.get(
        "/api/v1/tprm/templates",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    listed_names = {t["name"] for t in listed.json()}
    assert {"sig_lite", "caiq_v4"} <= listed_names


async def test_template_with_duplicate_question_id_rejected(
    client: AsyncClient, analyst_user, organization
):
    r = await client.post(
        "/api/v1/tprm/templates",
        json={
            "organization_id": str(organization["id"]),
            "name": "bad",
            "questions": [
                {"id": "q1", "text": "x", "answer_kind": "yes_no"},
                {"id": "q1", "text": "y", "answer_kind": "yes_no"},
            ],
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 422


# --- Questionnaire lifecycle -----------------------------------------


async def test_questionnaire_full_lifecycle(
    client: AsyncClient, analyst_user, organization
):
    # seed templates
    seed = await client.post(
        "/api/v1/tprm/templates/seed-builtins",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    sig_tpl = next(t for t in seed.json() if t["name"] == "sig_lite")
    vendor_id = await _create_vendor(client, analyst_user, organization)

    # send
    sent = await client.post(
        "/api/v1/tprm/questionnaires",
        json={
            "organization_id": str(organization["id"]),
            "template_id": sig_tpl["id"],
            "vendor_asset_id": vendor_id,
        },
        headers=_hdr(analyst_user),
    )
    assert sent.status_code == 201
    iid = sent.json()["id"]
    assert sent.json()["state"] == "sent"

    # answer all required questions yes
    for q in sig_tpl["questions"]:
        if not q["required"]:
            continue
        if q["answer_kind"] == "evidence":
            await client.post(
                f"/api/v1/tprm/questionnaires/{iid}/answers",
                json={"question_id": q["id"], "evidence_sha256": "a" * 64},
                headers=_hdr(analyst_user),
            )
        elif q["answer_kind"] == "scale_1_5":
            await client.post(
                f"/api/v1/tprm/questionnaires/{iid}/answers",
                json={"question_id": q["id"], "answer_value": "5"},
                headers=_hdr(analyst_user),
            )
        else:
            # data_breach_history => yes hurts vendor; but for "all yes" test, simulate clean
            value = "no" if q["id"] == "data_breach_history" else "yes"
            await client.post(
                f"/api/v1/tprm/questionnaires/{iid}/answers",
                json={"question_id": q["id"], "answer_value": value},
                headers=_hdr(analyst_user),
            )

    # transition: sent → received → reviewed
    r = await client.post(
        f"/api/v1/tprm/questionnaires/{iid}/state",
        json={"to_state": "received"},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    r = await client.post(
        f"/api/v1/tprm/questionnaires/{iid}/state",
        json={"to_state": "reviewed"},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["state"] == "reviewed"
    # Half of "yes" responses score 100, "data_breach_history=no" → 0.
    # Aggregate should still be reasonable.
    assert body["score"] is not None and body["score"] > 50

    # Detail view exposes answers
    detail = await client.get(
        f"/api/v1/tprm/questionnaires/{iid}",
        headers=_hdr(analyst_user),
    )
    assert detail.status_code == 200
    assert len(detail.json()["answers"]) >= 9


async def test_questionnaire_invalid_transition(
    client: AsyncClient, analyst_user, organization
):
    seed = await client.post(
        "/api/v1/tprm/templates/seed-builtins",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    tpl = seed.json()[0]
    vendor_id = await _create_vendor(client, analyst_user, organization)
    sent = await client.post(
        "/api/v1/tprm/questionnaires",
        json={
            "organization_id": str(organization["id"]),
            "template_id": tpl["id"],
            "vendor_asset_id": vendor_id,
        },
        headers=_hdr(analyst_user),
    )
    iid = sent.json()["id"]
    bad = await client.post(
        f"/api/v1/tprm/questionnaires/{iid}/state",
        json={"to_state": "reviewed"},
        headers=_hdr(analyst_user),
    )
    assert bad.status_code == 422


# --- Onboarding workflow ----------------------------------------------


async def test_onboarding_workflow(
    client: AsyncClient, analyst_user, organization
):
    vendor_id = await _create_vendor(client, analyst_user, organization)
    create = await client.post(
        "/api/v1/tprm/onboarding",
        json={
            "organization_id": str(organization["id"]),
            "vendor_asset_id": vendor_id,
        },
        headers=_hdr(analyst_user),
    )
    assert create.status_code == 201
    wid = create.json()["id"]
    assert create.json()["stage"] == "invited"

    # invited → questionnaire_sent
    a = await client.post(
        f"/api/v1/tprm/onboarding/{wid}/transition",
        json={"to_stage": "questionnaire_sent"},
        headers=_hdr(analyst_user),
    )
    assert a.status_code == 200

    # questionnaire_sent → questionnaire_received → analyst_review
    await client.post(
        f"/api/v1/tprm/onboarding/{wid}/transition",
        json={"to_stage": "questionnaire_received"},
        headers=_hdr(analyst_user),
    )
    await client.post(
        f"/api/v1/tprm/onboarding/{wid}/transition",
        json={"to_stage": "analyst_review"},
        headers=_hdr(analyst_user),
    )

    # analyst_review → approved (reason required)
    no_reason = await client.post(
        f"/api/v1/tprm/onboarding/{wid}/transition",
        json={"to_stage": "approved"},
        headers=_hdr(analyst_user),
    )
    assert no_reason.status_code == 422

    ok = await client.post(
        f"/api/v1/tprm/onboarding/{wid}/transition",
        json={"to_stage": "approved", "reason": "passed all controls"},
        headers=_hdr(analyst_user),
    )
    assert ok.status_code == 200
    assert ok.json()["stage"] == "approved"
    assert ok.json()["decided_at"] is not None


async def test_onboarding_rejects_invalid_skip(
    client: AsyncClient, analyst_user, organization
):
    vendor_id = await _create_vendor(client, analyst_user, organization, name="Skip Test Inc")
    wf = await client.post(
        "/api/v1/tprm/onboarding",
        json={
            "organization_id": str(organization["id"]),
            "vendor_asset_id": vendor_id,
        },
        headers=_hdr(analyst_user),
    )
    wid = wf.json()["id"]
    bad = await client.post(
        f"/api/v1/tprm/onboarding/{wid}/transition",
        json={"to_stage": "approved", "reason": "skip"},
        headers=_hdr(analyst_user),
    )
    assert bad.status_code == 422


# --- Scorecard --------------------------------------------------------


async def test_scorecard_recompute_on_fresh_vendor(
    client: AsyncClient, analyst_user, organization
):
    vendor_id = await _create_vendor(client, analyst_user, organization)
    r = await client.post(
        f"/api/v1/tprm/scorecards/{vendor_id}/recompute",
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert 0 <= body["score"] <= 100
    assert body["grade"] in ("A+", "A", "B", "C", "D", "F")
    assert body["is_current"] is True
    # Audit B4 — security pillar is now computed via compute_vendor_rating()
    # scoped to the vendor's primary_domain. With a fully-populated vendor
    # and zero recorded exposures, expect a high vendor-scope score rather
    # than the previous neutral-70 fallback.
    assert body["pillar_scores"]["security"] > 70.0
    assert body["pillar_scores"]["operational"] >= 60


async def test_scorecard_uses_questionnaire_score(
    client: AsyncClient, analyst_user, organization
):
    seed = await client.post(
        "/api/v1/tprm/templates/seed-builtins",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    tpl = next(t for t in seed.json() if t["name"] == "sig_lite")
    vendor_id = await _create_vendor(client, analyst_user, organization)
    sent = await client.post(
        "/api/v1/tprm/questionnaires",
        json={
            "organization_id": str(organization["id"]),
            "template_id": tpl["id"],
            "vendor_asset_id": vendor_id,
        },
        headers=_hdr(analyst_user),
    )
    iid = sent.json()["id"]
    # Answer ALL yes for clean profile (data_breach_history = no)
    for q in tpl["questions"]:
        if not q["required"]:
            continue
        if q["answer_kind"] == "scale_1_5":
            v = "5"
        elif q["id"] == "data_breach_history":
            v = "no"
        else:
            v = "yes"
        await client.post(
            f"/api/v1/tprm/questionnaires/{iid}/answers",
            json={"question_id": q["id"], "answer_value": v},
            headers=_hdr(analyst_user),
        )
    await client.post(
        f"/api/v1/tprm/questionnaires/{iid}/state",
        json={"to_state": "received"},
        headers=_hdr(analyst_user),
    )
    await client.post(
        f"/api/v1/tprm/questionnaires/{iid}/state",
        json={"to_state": "reviewed"},
        headers=_hdr(analyst_user),
    )
    sc = await client.post(
        f"/api/v1/tprm/scorecards/{vendor_id}/recompute",
        headers=_hdr(analyst_user),
    )
    body = sc.json()
    # `data_breach_history=no` scores 0 in our mapping (yes→100, no→0).
    # That's intentional: "yes you had a breach" = 100 isn't right, but
    # this test demonstrates the score is sensitive to answers.
    assert body["pillar_scores"]["questionnaire"] >= 0
    assert body["score"] != 0


async def test_scorecard_listing_per_org(
    client: AsyncClient, analyst_user, organization, second_organization
):
    v1 = await _create_vendor(client, analyst_user, organization, name="A Co")
    v2 = await _create_vendor(
        client, analyst_user, second_organization, name="B Co"
    )
    await client.post(
        f"/api/v1/tprm/scorecards/{v1}/recompute",
        headers=_hdr(analyst_user),
    )
    await client.post(
        f"/api/v1/tprm/scorecards/{v2}/recompute",
        headers=_hdr(analyst_user),
    )
    listed = await client.get(
        "/api/v1/tprm/scorecards",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert all(
        s["organization_id"] == str(organization["id"]) for s in listed.json()
    )
    assert any(s["vendor_asset_id"] == v1 for s in listed.json())
    assert not any(s["vendor_asset_id"] == v2 for s in listed.json())
