"""Asset Registry — full integration tests.

Covers: type-specific validation, canonicalization, CRUD lifecycle,
filtering, count aggregation, bulk JSON + CSV import, duplicate
handling, tenant isolation, audit log emission, and asset_type schema
introspection.

Every test runs against the real Postgres test DB and the live FastAPI
app via httpx — no mocks, no in-memory shortcuts.
"""

from __future__ import annotations

import io
import json
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession


pytestmark = pytest.mark.asyncio


# --- Type-specific validation -------------------------------------------


async def test_create_domain_canonicalizes_and_validates(
    client: AsyncClient, analyst_user, organization
):
    body = {
        "organization_id": str(organization["id"]),
        "asset_type": "domain",
        "value": " Example.COM. ",
        "details": {"registrar": "GoDaddy", "is_root": True},
        "criticality": "crown_jewel",
        "tags": ["primary", "public"],
    }
    r = await client.post("/api/v1/assets", json=body, headers=analyst_user["headers"])
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["value"] == "example.com"
    assert data["asset_type"] == "domain"
    assert data["criticality"] == "crown_jewel"
    assert sorted(data["tags"]) == ["primary", "public"]
    assert data["monitoring_enabled"] is True
    assert data["details"]["registrar"] == "GoDaddy"
    assert data["details"]["is_root"] is True


async def test_create_invalid_domain_rejected(
    client: AsyncClient, analyst_user, organization
):
    r = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "domain",
            "value": "not a domain",
        },
        headers=analyst_user["headers"],
    )
    assert r.status_code == 422


async def test_ip_address_canonicalized(
    client: AsyncClient, analyst_user, organization
):
    # IPv6 case-fold + zero-compression canonicalization
    r = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "ip_address",
            "value": "2001:DB8:0000::0001",
        },
        headers=analyst_user["headers"],
    )
    assert r.status_code == 201, r.text
    assert r.json()["value"] == "2001:db8::1"

    # Standard IPv4 round-trips unchanged
    r2 = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "ip_address",
            "value": "203.0.113.42",
        },
        headers=analyst_user["headers"],
    )
    assert r2.status_code == 201
    assert r2.json()["value"] == "203.0.113.42"

    # Leading-zero IPv4 octets are rejected (RFC compliance)
    bad = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "ip_address",
            "value": "001.002.003.004",
        },
        headers=analyst_user["headers"],
    )
    assert bad.status_code == 422


async def test_ip_range_validated(client: AsyncClient, analyst_user, organization):
    ok = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "ip_range",
            "value": "10.0.0.0/24",
            "details": {"cidr": "10.0.0.0/24", "asn": 12345},
        },
        headers=analyst_user["headers"],
    )
    assert ok.status_code == 201, ok.text

    bad = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "ip_range",
            "value": "300.0.0.0/24",
        },
        headers=analyst_user["headers"],
    )
    assert bad.status_code == 422


async def test_service_value_format(client: AsyncClient, analyst_user, organization):
    r = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "service",
            "value": "Example.COM:443",
            "details": {"host": "example.com", "port": 443, "service_name": "https"},
        },
        headers=analyst_user["headers"],
    )
    assert r.status_code == 201
    assert r.json()["value"] == "example.com:443"

    bad = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "service",
            "value": "example.com:99999",
        },
        headers=analyst_user["headers"],
    )
    assert bad.status_code == 422


async def test_executive_with_full_details(
    client: AsyncClient, analyst_user, organization
):
    r = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "executive",
            "value": "  Krishna  Iyer  ",
            "details": {
                "full_name": "Krishna Iyer",
                "title": "CEO",
                "emails": ["krishna@example.com"],
                "social_profiles": {"linkedin": "kiyer"},
            },
            "criticality": "crown_jewel",
        },
        headers=analyst_user["headers"],
    )
    assert r.status_code == 201, r.text
    assert r.json()["value"] == "Krishna Iyer"


async def test_social_handle_canonicalization(
    client: AsyncClient, analyst_user, organization
):
    r = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "social_handle",
            "value": "TWITTER:@argus_official",
            "details": {"platform": "twitter", "handle": "argus_official"},
        },
        headers=analyst_user["headers"],
    )
    assert r.status_code == 201
    assert r.json()["value"] == "twitter:argus_official"


async def test_email_domain_dmarc_validation(
    client: AsyncClient, analyst_user, organization
):
    r = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "email_domain",
            "value": "Mail.Example.com",
            "details": {
                "domain": "mail.example.com",
                "dmarc_policy": "quarantine",
                "dmarc_pct": 50,
                "dmarc_rua": ["mailto:dmarc@example.com"],
            },
        },
        headers=analyst_user["headers"],
    )
    assert r.status_code == 201

    # invalid dmarc_pct
    bad = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "email_domain",
            "value": "other.example.com",
            "details": {
                "domain": "other.example.com",
                "dmarc_policy": "quarantine",
                "dmarc_pct": 250,
            },
        },
        headers=analyst_user["headers"],
    )
    assert bad.status_code == 422


# --- CRUD lifecycle ------------------------------------------------------


async def test_full_crud_lifecycle(
    client: AsyncClient, analyst_user, organization
):
    org_id = str(organization["id"])

    # Create
    create = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": org_id,
            "asset_type": "domain",
            "value": "lifecycle.test",
            "criticality": "high",
            "tags": ["alpha"],
        },
        headers=analyst_user["headers"],
    )
    assert create.status_code == 201
    asset_id = create.json()["id"]

    # Get
    got = await client.get(f"/api/v1/assets/{asset_id}", headers=analyst_user["headers"])
    assert got.status_code == 200
    assert got.json()["value"] == "lifecycle.test"

    # Patch
    patched = await client.patch(
        f"/api/v1/assets/{asset_id}",
        json={
            "criticality": "crown_jewel",
            "tags": ["alpha", "promoted"],
            "monitoring_enabled": False,
        },
        headers=analyst_user["headers"],
    )
    assert patched.status_code == 200
    assert patched.json()["criticality"] == "crown_jewel"
    assert patched.json()["monitoring_enabled"] is False
    assert patched.json()["last_change_at"] is not None

    # Delete
    deleted = await client.delete(
        f"/api/v1/assets/{asset_id}", headers=analyst_user["headers"]
    )
    assert deleted.status_code == 204

    # Confirm 404
    gone = await client.get(f"/api/v1/assets/{asset_id}", headers=analyst_user["headers"])
    assert gone.status_code == 404


async def test_duplicate_creation_returns_409(
    client: AsyncClient, analyst_user, organization
):
    body = {
        "organization_id": str(organization["id"]),
        "asset_type": "domain",
        "value": "duplicate.test",
    }
    first = await client.post("/api/v1/assets", json=body, headers=analyst_user["headers"])
    assert first.status_code == 201

    dup = await client.post("/api/v1/assets", json=body, headers=analyst_user["headers"])
    assert dup.status_code == 409


# --- Filters + count ----------------------------------------------------


async def test_list_includes_total_count_header(
    client: AsyncClient, analyst_user, organization
):
    """Audit B6 — list endpoints expose X-Total-Count for pagination."""
    h = analyst_user["headers"]
    org_id = str(organization["id"])
    for i in range(3):
        await client.post(
            "/api/v1/assets",
            json={
                "organization_id": org_id,
                "asset_type": "domain",
                "value": f"paging-{i}.example",
            },
            headers=h,
        )
    r = await client.get(
        "/api/v1/assets",
        params={"organization_id": org_id, "limit": 2, "offset": 0},
        headers=h,
    )
    assert r.status_code == 200
    assert "X-Total-Count" in r.headers
    assert int(r.headers["X-Total-Count"]) >= 3
    assert len(r.json()) == 2  # paged, but total reflects unpaged count


async def test_list_with_filters_and_count(
    client: AsyncClient, analyst_user, organization
):
    org_id = str(organization["id"])
    seed = [
        ("domain", "filt-a.test", "high", ["public"]),
        ("domain", "filt-b.test", "low", ["internal"]),
        ("ip_address", "10.10.10.10", "crown_jewel", ["public"]),
    ]
    for atype, value, crit, tags in seed:
        r = await client.post(
            "/api/v1/assets",
            json={
                "organization_id": org_id,
                "asset_type": atype,
                "value": value,
                "criticality": crit,
                "tags": tags,
            },
            headers=analyst_user["headers"],
        )
        assert r.status_code == 201

    # Filter by type
    only_domains = await client.get(
        "/api/v1/assets",
        params={"organization_id": org_id, "asset_type": "domain"},
        headers=analyst_user["headers"],
    )
    assert only_domains.status_code == 200
    values = {a["value"] for a in only_domains.json()}
    assert "filt-a.test" in values and "filt-b.test" in values
    assert "10.10.10.10" not in values

    # Filter by criticality
    only_crown = await client.get(
        "/api/v1/assets",
        params={"organization_id": org_id, "criticality": "crown_jewel"},
        headers=analyst_user["headers"],
    )
    assert {a["value"] for a in only_crown.json()} == {"10.10.10.10"}

    # Filter by tag
    public_tagged = await client.get(
        "/api/v1/assets",
        params={"organization_id": org_id, "tag": "public"},
        headers=analyst_user["headers"],
    )
    pub_values = {a["value"] for a in public_tagged.json()}
    assert "filt-a.test" in pub_values and "10.10.10.10" in pub_values
    assert "filt-b.test" not in pub_values

    # Search by substring
    search = await client.get(
        "/api/v1/assets",
        params={"organization_id": org_id, "q": "filt-a"},
        headers=analyst_user["headers"],
    )
    assert {a["value"] for a in search.json()} == {"filt-a.test"}

    # Count aggregation
    counts = await client.get(
        "/api/v1/assets/count",
        params={"organization_id": org_id},
        headers=analyst_user["headers"],
    )
    assert counts.status_code == 200
    body = counts.json()
    assert body["total"] >= 3
    assert body["by_type"]["domain"] >= 2
    assert body["by_criticality"]["crown_jewel"] >= 1


# --- Bulk JSON + CSV import ---------------------------------------------


async def test_bulk_json_import(client: AsyncClient, analyst_user, organization):
    org_id = str(organization["id"])
    payload = {
        "organization_id": org_id,
        "rows": [
            {"asset_type": "domain", "value": "bulk-1.test"},
            {"asset_type": "domain", "value": "bulk-2.test", "criticality": "high"},
            {"asset_type": "domain", "value": "bulk-1.test"},  # dup
            {"asset_type": "domain", "value": "not a domain"},  # invalid
        ],
    }
    r = await client.post(
        "/api/v1/assets/bulk", json=payload, headers=analyst_user["headers"]
    )
    assert r.status_code == 200
    body = r.json()
    assert body["inserted"] == 2
    assert body["skipped_duplicates"] == 1
    assert len(body["errors"]) == 1
    assert "not a domain" in body["errors"][0]["value"]


async def test_bulk_csv_import(client: AsyncClient, analyst_user, organization):
    import csv as _csv

    org_id = str(organization["id"])
    buf = io.StringIO()
    writer = _csv.writer(buf, quoting=_csv.QUOTE_MINIMAL)
    writer.writerow(["asset_type", "value", "criticality", "tags", "details_json"])
    writer.writerow(["domain", "csv-a.test", "high", "public;external", ""])
    writer.writerow(["domain", "csv-b.test", "medium", "", ""])
    writer.writerow(
        [
            "executive",
            "Jane Doe",
            "crown_jewel",
            "",
            json.dumps({"full_name": "Jane Doe", "title": "CFO"}),
        ]
    )
    writer.writerow(["domain", "not a domain", "medium", "", ""])
    csv_data = buf.getvalue()

    r = await client.post(
        "/api/v1/assets/bulk/csv",
        params={"organization_id": org_id},
        files={"file": ("seed.csv", io.BytesIO(csv_data.encode()), "text/csv")},
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["inserted"] == 3
    assert any("not a domain" in (e.get("value") or "") for e in body["errors"])


# --- Tenant isolation ---------------------------------------------------


async def test_cross_org_listing_isolated(
    client: AsyncClient, analyst_user, organization, second_organization
):
    org_a = str(organization["id"])
    org_b = str(second_organization["id"])

    a = await client.post(
        "/api/v1/assets",
        json={"organization_id": org_a, "asset_type": "domain", "value": "iso-a.test"},
        headers=analyst_user["headers"],
    )
    b = await client.post(
        "/api/v1/assets",
        json={"organization_id": org_b, "asset_type": "domain", "value": "iso-b.test"},
        headers=analyst_user["headers"],
    )
    assert a.status_code == 201 and b.status_code == 201

    list_a = await client.get(
        "/api/v1/assets",
        params={"organization_id": org_a},
        headers=analyst_user["headers"],
    )
    values_a = {x["value"] for x in list_a.json()}
    assert "iso-a.test" in values_a
    assert "iso-b.test" not in values_a


async def test_parent_asset_must_match_org(
    client: AsyncClient, analyst_user, organization, second_organization
):
    parent = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "domain",
            "value": "parent.test",
        },
        headers=analyst_user["headers"],
    )
    parent_id = parent.json()["id"]

    bad = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(second_organization["id"]),
            "asset_type": "subdomain",
            "value": "sub.parent.test",
            "details": {"parent_domain": "parent.test"},
            "parent_asset_id": parent_id,
        },
        headers=analyst_user["headers"],
    )
    assert bad.status_code == 422


# --- Auth & schema introspection ---------------------------------------


async def test_unauthenticated_rejected(client: AsyncClient, organization):
    r = await client.get(
        "/api/v1/assets", params={"organization_id": str(organization["id"])}
    )
    assert r.status_code in (401, 403)


async def test_asset_type_schemas_returned(client: AsyncClient, analyst_user):
    r = await client.get("/api/v1/assets/types/schema", headers=analyst_user["headers"])
    assert r.status_code == 200
    schemas = r.json()
    for required in (
        "domain",
        "subdomain",
        "ip_address",
        "ip_range",
        "service",
        "email_domain",
        "executive",
        "brand",
        "mobile_app",
        "social_handle",
        "vendor",
        "code_repository",
        "cloud_account",
    ):
        assert required in schemas
        assert "properties" in schemas[required]


# --- Audit log emission --------------------------------------------------


async def test_audit_log_recorded_on_lifecycle(
    client: AsyncClient, analyst_user, organization, test_engine
):
    org_id = str(organization["id"])
    create = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": org_id,
            "asset_type": "domain",
            "value": "audit.test",
        },
        headers=analyst_user["headers"],
    )
    assert create.status_code == 201
    asset_id = create.json()["id"]

    await client.patch(
        f"/api/v1/assets/{asset_id}",
        json={"criticality": "high"},
        headers=analyst_user["headers"],
    )
    await client.delete(
        f"/api/v1/assets/{asset_id}", headers=analyst_user["headers"]
    )

    from src.models.auth import AuditAction, AuditLog

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        result = await s.execute(
            select(AuditLog.action)
            .where(AuditLog.resource_id == asset_id)
            .order_by(AuditLog.timestamp.asc())
        )
        actions = [row[0] for row in result.all()]

    assert AuditAction.ASSET_CREATE.value in actions
    assert AuditAction.ASSET_UPDATE.value in actions
    assert AuditAction.ASSET_DELETE.value in actions
