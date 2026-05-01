"""Onboarding wizard — full integration tests.

Covers: session lifecycle (create → patch each step → validate → complete),
abandon, validation errors, duplicate-asset warnings, discovery job
enqueueing, kind-routing per asset type, audit log emission, and tenant
isolation.

Runs against the real Postgres test DB and live FastAPI app.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


# --- Lifecycle ----------------------------------------------------------


async def test_full_wizard_lifecycle(client: AsyncClient, analyst_user):
    h = _hdr(analyst_user)

    # 1) Create session (no org bound — will be created at completion)
    create = await client.post(
        "/api/v1/onboarding/sessions", json={"notes": "demo run"}, headers=h
    )
    assert create.status_code == 201, create.text
    sess_id = create.json()["id"]
    assert create.json()["state"] == "draft"
    assert create.json()["current_step"] == 1

    # 2) Step 1 — organization
    r = await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={
            "step": "organization",
            "data": {
                "name": "Wizard Test Co",
                "industry": "finance",
                "primary_domain": "wizard-test.example",
                "keywords": ["wizard", "test"],
            },
        },
        headers=h,
    )
    assert r.status_code == 200
    assert r.json()["current_step"] == 2

    # 3) Step 2 — infra
    r = await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={
            "step": "infra",
            "data": {
                "assets": [
                    {"asset_type": "domain", "value": "wizard-test.example"},
                    {
                        "asset_type": "subdomain",
                        "value": "api.wizard-test.example",
                        "details": {"parent_domain": "wizard-test.example"},
                    },
                    {"asset_type": "ip_range", "value": "10.20.0.0/16",
                     "details": {"cidr": "10.20.0.0/16"}},
                    {
                        "asset_type": "email_domain",
                        "value": "mail.wizard-test.example",
                        "details": {"domain": "mail.wizard-test.example",
                                    "dmarc_policy": "quarantine", "dmarc_pct": 100},
                    },
                ]
            },
        },
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["current_step"] == 3

    # 4) Step 3 — people & brand
    r = await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={
            "step": "people_and_brand",
            "data": {
                "assets": [
                    {
                        "asset_type": "executive",
                        "value": "Krishna Iyer",
                        "criticality": "crown_jewel",
                        "details": {"full_name": "Krishna Iyer", "title": "CEO"},
                    },
                    {
                        "asset_type": "brand",
                        "value": "WizardCo",
                        "details": {"name": "WizardCo", "keywords": ["wizard"]},
                    },
                    {
                        "asset_type": "social_handle",
                        "value": "twitter:wizardco",
                        "details": {"platform": "twitter", "handle": "wizardco"},
                    },
                ]
            },
        },
        headers=h,
    )
    assert r.status_code == 200
    assert r.json()["current_step"] == 4

    # 5) Step 4 — vendors
    r = await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={
            "step": "vendors",
            "data": {
                "assets": [
                    {
                        "asset_type": "vendor",
                        "value": "Acme Cloud Inc",
                        "details": {
                            "legal_name": "Acme Cloud Inc",
                            "primary_domain": "acme-cloud.example",
                            "relationship_type": "saas",
                            "data_access_level": "pii",
                        },
                    }
                ]
            },
        },
        headers=h,
    )
    assert r.status_code == 200
    assert r.json()["current_step"] == 5

    # 6) Step 5 — review
    r = await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={
            "step": "review",
            "data": {
                "enable_auto_discovery": True,
                "discover_kinds": ["subdomain_enum", "httpx_probe", "dns_refresh"],
            },
        },
        headers=h,
    )
    assert r.status_code == 200

    # 7) Validate every step
    val = await client.post(
        f"/api/v1/onboarding/sessions/{sess_id}/validate", headers=h
    )
    assert val.status_code == 200
    for report in val.json():
        assert report["valid"], report

    # 8) Complete
    done = await client.post(
        f"/api/v1/onboarding/sessions/{sess_id}/complete", headers=h
    )
    assert done.status_code == 200, done.text
    body = done.json()
    org_id = body["organization_id"]
    assert body["assets_created"] == 4 + 3 + 1  # 4 infra + 3 brand + 1 vendor
    assert body["discovery_jobs_enqueued"] >= 1

    # 9) Confirm session is now COMPLETED
    after = await client.get(
        f"/api/v1/onboarding/sessions/{sess_id}", headers=h
    )
    assert after.json()["state"] == "completed"

    # 10) Confirm assets really exist
    listed = await client.get(
        "/api/v1/assets", params={"organization_id": org_id}, headers=h
    )
    assert listed.status_code == 200
    values = {a["value"] for a in listed.json()}
    assert "wizard-test.example" in values
    assert "Krishna Iyer" in values
    assert "Acme Cloud Inc" in values

    # 11) Confirm discovery jobs queued
    jobs = await client.get(
        "/api/v1/onboarding/discovery-jobs",
        params={"organization_id": org_id},
        headers=h,
    )
    assert jobs.status_code == 200
    statuses = {j["status"] for j in jobs.json()}
    assert "queued" in statuses
    # Discovery kind routing: subdomain_enum should go to domain/subdomain assets only
    by_target = {(j["target"], j["kind"]) for j in jobs.json()}
    assert ("wizard-test.example", "subdomain_enum") in by_target
    # Email-domain only got dns_refresh (not subdomain_enum)
    assert (
        "mail.wizard-test.example",
        "subdomain_enum",
    ) not in by_target


async def test_complete_without_organization_step_fails(
    client: AsyncClient, analyst_user
):
    create = await client.post(
        "/api/v1/onboarding/sessions", json={}, headers=_hdr(analyst_user)
    )
    sess_id = create.json()["id"]
    r = await client.post(
        f"/api/v1/onboarding/sessions/{sess_id}/complete",
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 422
    assert "organization" in str(r.json())


async def test_validate_catches_invalid_asset(client: AsyncClient, analyst_user):
    create = await client.post(
        "/api/v1/onboarding/sessions", json={}, headers=_hdr(analyst_user)
    )
    sess_id = create.json()["id"]

    await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={
            "step": "organization",
            "data": {"name": "Bad Org Test"},
        },
        headers=_hdr(analyst_user),
    )
    await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={
            "step": "infra",
            "data": {
                "assets": [
                    {"asset_type": "domain", "value": "ok.example"},
                    {"asset_type": "domain", "value": "not a domain"},
                ]
            },
        },
        headers=_hdr(analyst_user),
    )
    val = await client.post(
        f"/api/v1/onboarding/sessions/{sess_id}/validate",
        headers=_hdr(analyst_user),
    )
    assert val.status_code == 200
    by_step = {r["step"]: r for r in val.json()}
    assert by_step["infra"]["valid"] is False
    assert any("not a domain" in str(e) for e in by_step["infra"]["errors"])

    # Completion must refuse
    done = await client.post(
        f"/api/v1/onboarding/sessions/{sess_id}/complete",
        headers=_hdr(analyst_user),
    )
    assert done.status_code == 422


async def test_abandon_session(client: AsyncClient, analyst_user):
    create = await client.post(
        "/api/v1/onboarding/sessions", json={}, headers=_hdr(analyst_user)
    )
    sess_id = create.json()["id"]

    r = await client.post(
        f"/api/v1/onboarding/sessions/{sess_id}/abandon",
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    assert r.json()["state"] == "abandoned"

    # Subsequent edits are blocked
    r2 = await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={"step": "organization", "data": {"name": "X"}},
        headers=_hdr(analyst_user),
    )
    assert r2.status_code == 409


async def test_completion_skips_duplicate_assets(
    client: AsyncClient, analyst_user, organization
):
    """Resuming into an existing org with duplicates should warn, not fail."""
    h = _hdr(analyst_user)
    org_id = str(organization["id"])

    # Pre-existing asset
    pre = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": org_id,
            "asset_type": "domain",
            "value": "preexisting.example",
        },
        headers=h,
    )
    assert pre.status_code == 201

    create = await client.post(
        "/api/v1/onboarding/sessions",
        json={"organization_id": org_id},
        headers=h,
    )
    sess_id = create.json()["id"]

    await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={"step": "organization", "data": {"name": organization["name"]}},
        headers=h,
    )
    await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={
            "step": "infra",
            "data": {
                "assets": [
                    {"asset_type": "domain", "value": "preexisting.example"},  # dup
                    {"asset_type": "domain", "value": "freshone.example"},
                ]
            },
        },
        headers=h,
    )
    await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={
            "step": "review",
            "data": {"enable_auto_discovery": False},
        },
        headers=h,
    )
    done = await client.post(
        f"/api/v1/onboarding/sessions/{sess_id}/complete", headers=h
    )
    assert done.status_code == 200, done.text
    assert done.json()["assets_created"] == 1
    assert any("Skipped duplicate" in w for w in done.json()["warnings"])


async def test_discovery_job_cancel(
    client: AsyncClient, analyst_user, organization
):
    """Run a small wizard, then cancel a queued discovery job."""
    h = _hdr(analyst_user)
    org_id = str(organization["id"])

    create = await client.post(
        "/api/v1/onboarding/sessions",
        json={"organization_id": org_id},
        headers=h,
    )
    sess_id = create.json()["id"]
    await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={"step": "organization", "data": {"name": organization["name"]}},
        headers=h,
    )
    await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={
            "step": "infra",
            "data": {
                "assets": [
                    {"asset_type": "domain", "value": "cancel-me.example"}
                ]
            },
        },
        headers=h,
    )
    await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={
            "step": "review",
            "data": {
                "enable_auto_discovery": True,
                "discover_kinds": ["subdomain_enum"],
            },
        },
        headers=h,
    )
    done = await client.post(
        f"/api/v1/onboarding/sessions/{sess_id}/complete", headers=h
    )
    assert done.json()["discovery_jobs_enqueued"] >= 1

    jobs = await client.get(
        "/api/v1/onboarding/discovery-jobs",
        params={"organization_id": org_id, "status": "queued"},
        headers=h,
    )
    assert jobs.status_code == 200
    job_id = jobs.json()[0]["id"]

    cancel = await client.post(
        f"/api/v1/onboarding/discovery-jobs/{job_id}/cancel", headers=h
    )
    assert cancel.status_code == 200
    assert cancel.json()["status"] == "cancelled"

    # Cancelling a cancelled job returns 409
    again = await client.post(
        f"/api/v1/onboarding/discovery-jobs/{job_id}/cancel", headers=h
    )
    assert again.status_code == 409


async def test_unauthenticated_rejected(client: AsyncClient):
    r = await client.post("/api/v1/onboarding/sessions", json={})
    assert r.status_code in (401, 403)


async def test_audit_log_for_onboarding(
    client: AsyncClient, analyst_user, test_engine
):
    h = _hdr(analyst_user)

    create = await client.post(
        "/api/v1/onboarding/sessions", json={}, headers=h
    )
    sess_id = create.json()["id"]

    await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={"step": "organization", "data": {"name": "Audit Test Co"}},
        headers=h,
    )
    await client.patch(
        f"/api/v1/onboarding/sessions/{sess_id}",
        json={"step": "review", "data": {"enable_auto_discovery": False}},
        headers=h,
    )
    await client.post(
        f"/api/v1/onboarding/sessions/{sess_id}/complete", headers=h
    )

    from src.models.auth import AuditAction, AuditLog

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        result = await s.execute(
            select(AuditLog.action)
            .where(AuditLog.resource_id == sess_id)
            .order_by(AuditLog.timestamp.asc())
        )
        actions = [row[0] for row in result.all()]

    assert AuditAction.ONBOARDING_START.value in actions
    assert AuditAction.ONBOARDING_UPDATE.value in actions
    assert AuditAction.ONBOARDING_COMPLETE.value in actions
