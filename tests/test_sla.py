"""Phase 9 — SLA + Ticketing integration tests."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.models.cases import Case

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


# --- Policy CRUD ------------------------------------------------------


async def test_upsert_policy_creates_then_updates(
    client: AsyncClient, analyst_user, organization
):
    org_id = str(organization["id"])
    a = await client.post(
        "/api/v1/sla/policies",
        json={
            "organization_id": org_id,
            "severity": "high",
            "first_response_minutes": 60,
            "remediation_minutes": 480,
        },
        headers=_hdr(analyst_user),
    )
    assert a.status_code == 201
    a_id = a.json()["id"]
    b = await client.post(
        "/api/v1/sla/policies",
        json={
            "organization_id": org_id,
            "severity": "high",
            "first_response_minutes": 30,
            "remediation_minutes": 240,
            "description": "tightened",
        },
        headers=_hdr(analyst_user),
    )
    assert b.status_code == 201
    assert b.json()["id"] == a_id
    assert b.json()["first_response_minutes"] == 30
    assert b.json()["description"] == "tightened"


async def test_policy_invalid_ordering_rejected(
    client: AsyncClient, analyst_user, organization
):
    r = await client.post(
        "/api/v1/sla/policies",
        json={
            "organization_id": str(organization["id"]),
            "severity": "high",
            "first_response_minutes": 240,
            "remediation_minutes": 60,  # < first_response — invalid
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 422


# --- Evaluation -------------------------------------------------------


async def _create_case(client, analyst, organization, severity="critical"):
    r = await client.post(
        "/api/v1/cases",
        json={
            "organization_id": str(organization["id"]),
            "title": f"sla-test-{uuid.uuid4().hex[:6]}",
            "severity": severity,
        },
        headers=_hdr(analyst),
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _backdate_case(test_engine, case_id: str, hours_ago: float):
    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        new_ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        await s.execute(
            update(Case)
            .where(Case.id == uuid.UUID(case_id))
            .values(created_at=new_ts)
        )
        await s.commit()


async def test_evaluate_records_first_response_breach(
    client: AsyncClient, analyst_user, organization, test_engine
):
    org_id = str(organization["id"])
    await client.post(
        "/api/v1/sla/policies",
        json={
            "organization_id": org_id,
            "severity": "critical",
            "first_response_minutes": 30,
            "remediation_minutes": 240,
        },
        headers=_hdr(analyst_user),
    )
    case_id = await _create_case(client, analyst_user, organization)
    # Backdate the case beyond 30 min but within 240
    await _backdate_case(test_engine, case_id, hours_ago=1.0)

    r = await client.post(
        f"/api/v1/sla/evaluate?organization_id={org_id}",
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["new_breaches"] == 1
    breaches = await client.get(
        f"/api/v1/sla/breaches?organization_id={org_id}",
        headers=_hdr(analyst_user),
    )
    kinds = {b["kind"] for b in breaches.json()}
    assert "first_response" in kinds


async def test_evaluate_records_remediation_breach(
    client: AsyncClient, analyst_user, organization, test_engine
):
    org_id = str(organization["id"])
    await client.post(
        "/api/v1/sla/policies",
        json={
            "organization_id": org_id,
            "severity": "high",
            "first_response_minutes": 30,
            "remediation_minutes": 60,
        },
        headers=_hdr(analyst_user),
    )
    case_id = await _create_case(
        client, analyst_user, organization, severity="high"
    )
    await _backdate_case(test_engine, case_id, hours_ago=2.0)

    r = await client.post(
        f"/api/v1/sla/evaluate?organization_id={org_id}",
        headers=_hdr(analyst_user),
    )
    breaches = await client.get(
        "/api/v1/sla/breaches",
        params={"organization_id": org_id, "case_id": case_id},
        headers=_hdr(analyst_user),
    )
    assert breaches.status_code == 200, breaches.text
    kinds = {b["kind"] for b in breaches.json()}
    assert {"first_response", "remediation"} <= kinds


async def test_evaluate_idempotent_per_kind(
    client: AsyncClient, analyst_user, organization, test_engine
):
    org_id = str(organization["id"])
    await client.post(
        "/api/v1/sla/policies",
        json={
            "organization_id": org_id,
            "severity": "critical",
            "first_response_minutes": 30,
            "remediation_minutes": 240,
        },
        headers=_hdr(analyst_user),
    )
    case_id = await _create_case(client, analyst_user, organization)
    await _backdate_case(test_engine, case_id, hours_ago=1.0)

    a = await client.post(
        f"/api/v1/sla/evaluate?organization_id={org_id}",
        headers=_hdr(analyst_user),
    )
    b = await client.post(
        f"/api/v1/sla/evaluate?organization_id={org_id}",
        headers=_hdr(analyst_user),
    )
    assert a.json()["new_breaches"] == 1
    assert b.json()["new_breaches"] == 0


async def test_no_breach_when_first_response_recorded(
    client: AsyncClient, analyst_user, organization, test_engine
):
    org_id = str(organization["id"])
    await client.post(
        "/api/v1/sla/policies",
        json={
            "organization_id": org_id,
            "severity": "critical",
            "first_response_minutes": 30,
            "remediation_minutes": 240,
        },
        headers=_hdr(analyst_user),
    )
    case_id = await _create_case(client, analyst_user, organization)
    # Move to triaged so first_response_at is set, then backdate created_at.
    await client.post(
        f"/api/v1/cases/{case_id}/transitions",
        json={"to_state": "triaged"},
        headers=_hdr(analyst_user),
    )
    await _backdate_case(test_engine, case_id, hours_ago=1.0)
    r = await client.post(
        f"/api/v1/sla/evaluate?organization_id={org_id}",
        headers=_hdr(analyst_user),
    )
    body = r.json()
    # remediation breach can still happen — but first_response should NOT.
    case_rows = [row for row in body["rows"] if row["case_id"] == case_id]
    assert case_rows
    assert case_rows[0]["first_response_breached"] is False


# --- Ticket bindings -------------------------------------------------


async def test_ticket_binding_full_lifecycle(
    client: AsyncClient, analyst_user, organization
):
    case_id = await _create_case(client, analyst_user, organization)
    create = await client.post(
        "/api/v1/sla/tickets",
        json={
            "organization_id": str(organization["id"]),
            "case_id": case_id,
            "system": "jira",
            "external_id": "PROJ-1234",
            "external_url": "https://argus.atlassian.net/browse/PROJ-1234",
            "project_key": "PROJ",
        },
        headers=_hdr(analyst_user),
    )
    assert create.status_code == 201
    bid = create.json()["id"]

    dup = await client.post(
        "/api/v1/sla/tickets",
        json={
            "organization_id": str(organization["id"]),
            "case_id": case_id,
            "system": "jira",
            "external_id": "PROJ-1234",
        },
        headers=_hdr(analyst_user),
    )
    assert dup.status_code == 409

    sync = await client.patch(
        f"/api/v1/sla/tickets/{bid}",
        json={
            "status": "In Progress",
            "last_sync_status": "ok",
        },
        headers=_hdr(analyst_user),
    )
    assert sync.status_code == 200
    assert sync.json()["status"] == "In Progress"
    assert sync.json()["last_synced_at"] is not None

    delete = await client.delete(
        f"/api/v1/sla/tickets/{bid}",
        headers=_hdr(analyst_user),
    )
    assert delete.status_code == 204
