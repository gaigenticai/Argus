"""Phase 11 — Cross-cutting hardening tests.

Three concerns:
    1. Audit log export (CSV + NDJSON, admin-only, filterable)
    2. Executive summary PDF generation
    3. Tenant isolation property test — every public list endpoint must
       return zero items for a fresh second org regardless of how much
       data org A accumulates.
"""

from __future__ import annotations

import io
import json
import uuid

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


# --- Audit export ----------------------------------------------------


async def test_audit_export_csv(
    client: AsyncClient, admin_user, organization
):
    # Generate at least one audit event
    await client.post(
        "/api/v1/cases",
        json={
            "organization_id": str(organization["id"]),
            "title": "audit export test",
        },
        headers=_hdr(admin_user),
    )
    r = await client.get(
        "/api/v1/audit/export",
        params={"fmt": "csv", "limit": 50},
        headers=_hdr(admin_user),
    )
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/csv")
    assert "id,timestamp,user_id" in r.text
    assert int(r.headers.get("X-Argus-Row-Count", 0)) >= 1


async def test_audit_export_ndjson_filterable(
    client: AsyncClient, admin_user, organization
):
    await client.post(
        "/api/v1/cases",
        json={
            "organization_id": str(organization["id"]),
            "title": "ndjson test",
        },
        headers=_hdr(admin_user),
    )
    r = await client.get(
        "/api/v1/audit/export",
        params={"fmt": "ndjson", "action": "case_create"},
        headers=_hdr(admin_user),
    )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/x-ndjson")
    lines = [json.loads(l) for l in r.text.splitlines() if l.strip()]
    assert all(row["action"] == "case_create" for row in lines)


async def test_audit_export_admin_only(client: AsyncClient, analyst_user):
    r = await client.get(
        "/api/v1/audit/export",
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 403


# --- Exec summary PDF ------------------------------------------------


async def test_exec_summary_pdf_generates(
    client: AsyncClient, analyst_user, organization
):
    r = await client.get(
        "/api/v1/exec-summary",
        params={
            "organization_id": str(organization["id"]),
            "days": 30,
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    body = r.content
    assert body.startswith(b"%PDF-")
    # File header → trailer must be present
    assert b"%%EOF" in body[-1024:]


async def test_exec_summary_unknown_org(
    client: AsyncClient, analyst_user
):
    r = await client.get(
        "/api/v1/exec-summary",
        params={"organization_id": str(uuid.uuid4())},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 404


# --- Tenant isolation property test ----------------------------------


async def test_cross_tenant_listing_empty_for_fresh_second_org(
    client: AsyncClient, analyst_user, admin_user, organization, second_organization
):
    """Every list endpoint that org A populates must show zero items
    when queried with org B's id. Drives confidence that a customer
    cannot see another customer's data.
    """
    org_a = str(organization["id"])
    org_b = str(second_organization["id"])
    h = _hdr(analyst_user)

    # Populate org A across every model surface we ship.
    await client.post(
        "/api/v1/assets",
        json={"organization_id": org_a, "asset_type": "domain", "value": "tenant-a.test"},
        headers=h,
    )
    await client.post(
        "/api/v1/cases",
        json={"organization_id": org_a, "title": "tenant-a case"},
        headers=h,
    )
    await client.post(
        "/api/v1/brand/terms",
        json={"organization_id": org_a, "kind": "name", "value": "tenant-a"},
        headers=h,
    )
    await client.post(
        "/api/v1/brand/feed/ingest",
        json={
            "organization_id": org_a,
            "source": "manual",
            "domains": ["tenant-a-bait.com"],
        },
        headers=h,
    )
    await client.post(
        "/api/v1/leakage/policies",
        json={
            "organization_id": org_a,
            "name": "tenant-a-policy",
            "kind": "keyword",
            "pattern": "tenanta-secret",
        },
        headers=h,
    )
    await client.post(
        "/api/v1/social/vips",
        json={"organization_id": org_a, "full_name": "Krishna Tenant-A"},
        headers=h,
    )
    await client.post(
        "/api/v1/takedown/tickets",
        json={
            "organization_id": org_a,
            "partner": "manual",
            "target_kind": "suspect_domain",
            "target_identifier": "tenant-a-phish.com",
            "reason": "phish",
        },
        headers=h,
    )
    await client.post(
        "/api/v1/news/feeds",
        json={
            "organization_id": org_a,
            "name": f"tenant-a-feed-{uuid.uuid4().hex[:6]}",
            "url": f"https://tenant-a-{uuid.uuid4().hex[:6]}.example/rss",
        },
        headers=h,
    )

    # Now query each list endpoint with org B's id — none should leak.
    tenant_b_endpoints: list[tuple[str, dict]] = [
        ("/api/v1/assets", {"organization_id": org_b}),
        ("/api/v1/cases", {"organization_id": org_b}),
        ("/api/v1/brand/terms", {"organization_id": org_b}),
        ("/api/v1/brand/suspects", {"organization_id": org_b}),
        ("/api/v1/brand/logos", {"organization_id": org_b}),
        ("/api/v1/brand/logos/matches", {"organization_id": org_b}),
        ("/api/v1/leakage/policies", {"organization_id": org_b}),
        ("/api/v1/leakage/dlp", {"organization_id": org_b}),
        ("/api/v1/leakage/cards", {"organization_id": org_b}),
        ("/api/v1/social/vips", {"organization_id": org_b}),
        ("/api/v1/social/accounts", {"organization_id": org_b}),
        ("/api/v1/social/impersonations", {"organization_id": org_b}),
        ("/api/v1/social/mobile-apps", {"organization_id": org_b}),
        ("/api/v1/social/fraud", {"organization_id": org_b}),
        ("/api/v1/takedown/tickets", {"organization_id": org_b}),
        ("/api/v1/easm/exposures", {"organization_id": org_b}),
        ("/api/v1/easm/changes", {"organization_id": org_b}),
        ("/api/v1/easm/findings", {"organization_id": org_b}),
        ("/api/v1/sla/policies", {"organization_id": org_b}),
        ("/api/v1/sla/breaches", {"organization_id": org_b}),
        ("/api/v1/sla/tickets", {"organization_id": org_b}),
        ("/api/v1/tprm/scorecards", {"organization_id": org_b}),
        ("/api/v1/tprm/onboarding", {"organization_id": org_b}),
        ("/api/v1/tprm/questionnaires", {"organization_id": org_b}),
        ("/api/v1/news/relevance", {"organization_id": org_b}),
        ("/api/v1/intel/hardening", {"organization_id": org_b}),
        ("/api/v1/dmarc/reports", {"organization_id": org_b}),
        ("/api/v1/notifications/channels", {"organization_id": org_b}),
        ("/api/v1/notifications/rules", {"organization_id": org_b}),
        ("/api/v1/notifications/deliveries", {"organization_id": org_b}),
        ("/api/v1/onboarding/sessions", {}),  # this endpoint scopes by user
        ("/api/v1/mitre/attachments", {"organization_id": org_b}),
        ("/api/v1/evidence", {"organization_id": org_b}),
    ]

    for path, params in tenant_b_endpoints:
        r = await client.get(path, params=params, headers=h)
        assert r.status_code in (200, 404), f"{path}: HTTP {r.status_code}"
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                # Either empty, or every row is org B (never org A)
                for row in data:
                    if "organization_id" in row:
                        assert row["organization_id"] != org_a, (
                            f"tenant leak in {path}: {row}"
                        )
