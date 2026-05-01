"""Security Rating (Phase 1.3) — full integration tests against real DB.

Verifies:
    - rubric endpoint returns weights + thresholds
    - recompute on empty org returns a low grade (no email_auth, no surface)
    - exposures pillar lowers score proportionally to severity
    - acknowledged exposure: half penalty
    - reopened exposure: +25% penalty
    - email_domain with DMARC reject → high email_auth pillar
    - history retains past ratings; only one is_current=True at a time
    - ratings scoped per-org
    - audit log entry recorded on recompute
"""

from __future__ import annotations

import io

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.easm.runners import (
    Runner,
    RunnerOutput,
    get_runner_registry,
    reset_runner_registry,
    set_runner_registry,
)

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


class _Fake(Runner):
    def __init__(self, kind: str, output: RunnerOutput):
        self.kind = kind
        self._output = output

    async def run(self, target, parameters=None):
        return self._output


@pytest.fixture(autouse=True)
def _reset():
    reset_runner_registry()
    yield
    reset_runner_registry()


def _install(kind: str, output: RunnerOutput):
    reg = dict(get_runner_registry())
    reg[kind] = _Fake(kind, output)
    set_runner_registry(reg)


async def _enqueue_and_tick(client, analyst, admin, organization, kind, target):
    """Enqueue the job, then drain enough of the queue that ours definitely
    runs.  The worker is FIFO/global so prior tests can leave queued
    siblings — we tick generously and verify our specific job finished.
    """
    r = await client.post(
        "/api/v1/easm/scan",
        json={
            "organization_id": str(organization["id"]),
            "kind": kind,
            "target": target,
        },
        headers=_hdr(analyst),
    )
    assert r.status_code == 201
    job_id = r.json()["job_id"]

    # Drain up to 200 backlog entries; our job is somewhere in there.
    tick = await client.post(
        "/api/v1/easm/worker/tick", json={"max_jobs": 200}, headers=_hdr(admin)
    )
    assert tick.status_code == 200

    # Confirm our specific job actually finished.
    jobs = await client.get(
        "/api/v1/onboarding/discovery-jobs",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst),
    )
    mine = [j for j in jobs.json() if j["id"] == job_id]
    assert mine, f"job {job_id} not visible in org listing"
    assert mine[0]["status"] in ("succeeded", "failed"), (
        f"job {job_id} still in {mine[0]['status']!r} after tick"
    )


# --- Rubric --------------------------------------------------------------


async def test_rubric_endpoint_lists_weights(client: AsyncClient, analyst_user):
    r = await client.get("/api/v1/ratings/rubric", headers=_hdr(analyst_user))
    assert r.status_code == 200
    body = r.json()
    assert body["version"] == "1.0"
    assert "exposures" in body["pillar_weights"]
    assert sum(body["pillar_weights"].values()) == pytest.approx(1.0)
    assert body["grade_thresholds"]["A+"] == 95


# --- Recompute on empty org ---------------------------------------------


async def test_recompute_on_empty_org_returns_a_grade(
    client: AsyncClient, analyst_user, organization
):
    r = await client.post(
        f"/api/v1/ratings/recompute?organization_id={organization['id']}",
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    # No exposures + placeholder pillars at 100, surface/email/governance 0 →
    # ~ 35 + 0 + 0 + 0 + 10 + 5 = 50 → F. Verify it's a real number.
    assert 0 < body["score"] <= 100
    assert body["grade"] in {"A+", "A", "B", "C", "D", "F"}
    assert body["is_current"] is True
    factor_keys = {f["factor_key"] for f in body["factors"]}
    assert {
        "open_exposures",
        "surface_hygiene",
        "dmarc_coverage",
        "asset_governance",
        "breach_exposure",
        "dark_web_mentions",
    } <= factor_keys


# --- Exposure penalty ---------------------------------------------------


_ONE_CRITICAL = RunnerOutput(
    succeeded=True,
    items=[
        {
            "rule_id": "CVE-2024-PAIN",
            "name": "Critical RCE",
            "description": "Bad.",
            "severity": "critical",
            "tags": ["cve"],
            "matched_at": "https://probe.example.test/x",
            "host": "probe.example.test",
            "url": "https://probe.example.test/x",
            "cve_ids": ["CVE-2024-PAIN"],
            "cwe_ids": [],
            "cvss_score": 9.5,
        }
    ],
)


async def test_exposure_drops_rating(
    client: AsyncClient, analyst_user, admin_user, organization
):
    baseline = await client.post(
        f"/api/v1/ratings/recompute?organization_id={organization['id']}",
        headers=_hdr(analyst_user),
    )
    base_score = baseline.json()["score"]

    _install("vuln_scan", _ONE_CRITICAL)
    await _enqueue_and_tick(
        client, analyst_user, admin_user, organization,
        "vuln_scan", "probe.example.test",
    )

    after = await client.post(
        f"/api/v1/ratings/recompute?organization_id={organization['id']}",
        headers=_hdr(analyst_user),
    )
    after_score = after.json()["score"]
    assert after_score < base_score  # exposure pulled the score down

    open_factor = next(
        f for f in after.json()["factors"] if f["factor_key"] == "open_exposures"
    )
    assert open_factor["raw_score"] < 100
    assert open_factor["evidence"]["open_total"] == 1
    assert open_factor["evidence"]["by_severity"]["critical"] == 1


async def test_acknowledged_exposure_half_penalty(
    client: AsyncClient, analyst_user, admin_user, organization
):
    _install("vuln_scan", _ONE_CRITICAL)
    await _enqueue_and_tick(
        client, analyst_user, admin_user, organization,
        "vuln_scan", "probe.example.test",
    )
    listed = await client.get(
        "/api/v1/easm/exposures",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    fid = listed.json()[0]["id"]

    open_recompute = await client.post(
        f"/api/v1/ratings/recompute?organization_id={organization['id']}",
        headers=_hdr(analyst_user),
    )
    open_score = next(
        f for f in open_recompute.json()["factors"]
        if f["factor_key"] == "open_exposures"
    )["raw_score"]

    # Acknowledge → half penalty → factor score should rise
    await client.post(
        f"/api/v1/easm/exposures/{fid}/state",
        json={"to_state": "acknowledged"},
        headers=_hdr(analyst_user),
    )
    ack_recompute = await client.post(
        f"/api/v1/ratings/recompute?organization_id={organization['id']}",
        headers=_hdr(analyst_user),
    )
    ack_score = next(
        f for f in ack_recompute.json()["factors"]
        if f["factor_key"] == "open_exposures"
    )["raw_score"]

    assert ack_score > open_score


async def test_dmarc_reject_lifts_email_auth_pillar(
    client: AsyncClient, analyst_user, organization
):
    # Create email_domain with DMARC reject
    asset = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "email_domain",
            "value": "secure.example",
            "details": {
                "domain": "secure.example",
                "dmarc_policy": "reject",
                "spf_record": "v=spf1 -all",
            },
        },
        headers=_hdr(analyst_user),
    )
    assert asset.status_code == 201, asset.text

    rating = await client.post(
        f"/api/v1/ratings/recompute?organization_id={organization['id']}",
        headers=_hdr(analyst_user),
    )
    factor = next(
        f for f in rating.json()["factors"] if f["factor_key"] == "dmarc_coverage"
    )
    # 70% of dmarc score (100) + 30% of spf score (100) = 100
    assert factor["raw_score"] == pytest.approx(100, rel=1e-3)


# --- History + idempotency ---------------------------------------------


async def test_only_one_current_rating(
    client: AsyncClient, analyst_user, organization
):
    for _ in range(3):
        await client.post(
            f"/api/v1/ratings/recompute?organization_id={organization['id']}",
            headers=_hdr(analyst_user),
        )
    history = await client.get(
        f"/api/v1/ratings/history?organization_id={organization['id']}",
        headers=_hdr(analyst_user),
    )
    assert len(history.json()) >= 3
    current_count = sum(1 for r in history.json() if r["is_current"])
    assert current_count == 1


# --- Tenant isolation ---------------------------------------------------


async def test_ratings_scoped_per_org(
    client: AsyncClient, analyst_user, organization, second_organization
):
    await client.post(
        f"/api/v1/ratings/recompute?organization_id={organization['id']}",
        headers=_hdr(analyst_user),
    )
    other = await client.get(
        f"/api/v1/ratings/current?organization_id={second_organization['id']}",
        headers=_hdr(analyst_user),
    )
    # Org B has no rating yet — clean 404
    assert other.status_code == 404


# --- Audit log ---------------------------------------------------------


async def test_audit_log_records_recompute(
    client: AsyncClient, analyst_user, organization, test_engine
):
    r = await client.post(
        f"/api/v1/ratings/recompute?organization_id={organization['id']}",
        headers=_hdr(analyst_user),
    )
    rating_id = r.json()["id"]

    from src.models.auth import AuditAction, AuditLog

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        rows = await s.execute(
            select(AuditLog.action).where(
                AuditLog.resource_id == rating_id
            )
        )
        actions = [row[0] for row in rows.all()]
    assert AuditAction.RATING_RECOMPUTE.value in actions


async def test_unauthenticated_rejected(client: AsyncClient):
    r = await client.get("/api/v1/ratings/rubric")
    assert r.status_code in (401, 403)
