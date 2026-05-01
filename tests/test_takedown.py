"""Phase 10 — Takedown integration tests."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient

from src.takedown.adapters import (
    StatusResult,
    SubmitPayload,
    SubmitResult,
    TakedownAdapter,
    register_adapter,
    reset_registry,
)

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


@pytest.fixture(autouse=True)
def _reset_registry():
    reset_registry()
    yield
    reset_registry()


# --- Manual adapter (default) ----------------------------------------


async def test_manual_adapter_submits_locally(
    client: AsyncClient, analyst_user, organization
):
    r = await client.post(
        "/api/v1/takedown/tickets",
        json={
            "organization_id": str(organization["id"]),
            "partner": "manual",
            "target_kind": "suspect_domain",
            "target_identifier": "phishy-argus.com",
            "reason": "Brand impersonation phishing kit captured.",
            "evidence_urls": ["https://argus.test/evidence/abcd"],
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["state"] == "submitted"
    assert body["partner"] == "manual"
    assert body["partner_reference"]


async def test_partners_endpoint(client: AsyncClient, analyst_user):
    r = await client.get("/api/v1/takedown/partners", headers=_hdr(analyst_user))
    assert r.status_code == 200
    assert "manual" in r.json()["partners"]
    assert "netcraft" in r.json()["partners"]


# --- Custom adapter via test injection -------------------------------


class _FakePartnerAdapter(TakedownAdapter):
    name = "manual"  # override the default to force-success without going net

    def __init__(self, *, succeed_on_submit=True, status="acknowledged"):
        self.succeed_on_submit = succeed_on_submit
        self.status = status
        self.submitted: list[SubmitPayload] = []

    async def submit(self, payload):
        self.submitted.append(payload)
        if self.succeed_on_submit:
            return SubmitResult(
                success=True,
                partner_reference="FAKE-1234",
                partner_url="https://fakepartner.example/tk/FAKE-1234",
            )
        return SubmitResult(success=False, error_message="fake failure")

    async def fetch_status(self, ref):
        return StatusResult(success=True, partner_state=self.status)


async def test_failed_submit_records_failed_state(
    client: AsyncClient, analyst_user, organization
):
    register_adapter(_FakePartnerAdapter(succeed_on_submit=False))
    r = await client.post(
        "/api/v1/takedown/tickets",
        json={
            "organization_id": str(organization["id"]),
            "partner": "manual",
            "target_kind": "impersonation",
            "target_identifier": "twitter:fake_argus",
            "reason": "exec impersonation",
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 201
    assert r.json()["state"] == "failed"
    assert r.json()["failed_at"] is not None


async def test_duplicate_target_partner_409(
    client: AsyncClient, analyst_user, organization
):
    payload = {
        "organization_id": str(organization["id"]),
        "partner": "manual",
        "target_kind": "suspect_domain",
        "target_identifier": "dupe-argus.com",
        "reason": "phish",
    }
    a = await client.post(
        "/api/v1/takedown/tickets", json=payload, headers=_hdr(analyst_user)
    )
    b = await client.post(
        "/api/v1/takedown/tickets", json=payload, headers=_hdr(analyst_user)
    )
    assert a.status_code == 201
    assert b.status_code == 409


async def test_state_machine_progresses_to_succeeded(
    client: AsyncClient, analyst_user, organization
):
    create = await client.post(
        "/api/v1/takedown/tickets",
        json={
            "organization_id": str(organization["id"]),
            "partner": "manual",
            "target_kind": "mobile_app",
            "target_identifier": "com.scammer.argus",
            "reason": "rogue app on Google Play",
        },
        headers=_hdr(analyst_user),
    )
    tid = create.json()["id"]

    ack = await client.post(
        f"/api/v1/takedown/tickets/{tid}/state",
        json={"to_state": "acknowledged"},
        headers=_hdr(analyst_user),
    )
    assert ack.status_code == 200
    assert ack.json()["acknowledged_at"] is not None

    in_prog = await client.post(
        f"/api/v1/takedown/tickets/{tid}/state",
        json={"to_state": "in_progress"},
        headers=_hdr(analyst_user),
    )
    assert in_prog.status_code == 200

    done = await client.post(
        f"/api/v1/takedown/tickets/{tid}/state",
        json={
            "to_state": "succeeded",
            "proof_evidence_sha256": "a" * 64,
        },
        headers=_hdr(analyst_user),
    )
    assert done.status_code == 200
    assert done.json()["succeeded_at"] is not None
    assert done.json()["proof_evidence_sha256"] == "a" * 64

    # Succeeded is terminal — re-transition forbidden
    bad = await client.post(
        f"/api/v1/takedown/tickets/{tid}/state",
        json={"to_state": "in_progress"},
        headers=_hdr(analyst_user),
    )
    assert bad.status_code == 422


async def test_state_machine_reason_required_on_rejection(
    client: AsyncClient, analyst_user, organization
):
    create = await client.post(
        "/api/v1/takedown/tickets",
        json={
            "organization_id": str(organization["id"]),
            "partner": "manual",
            "target_kind": "fraud",
            "target_identifier": "https://scam.example",
            "reason": "fraud channel",
        },
        headers=_hdr(analyst_user),
    )
    tid = create.json()["id"]
    no_reason = await client.post(
        f"/api/v1/takedown/tickets/{tid}/state",
        json={"to_state": "rejected"},
        headers=_hdr(analyst_user),
    )
    assert no_reason.status_code == 422
    ok = await client.post(
        f"/api/v1/takedown/tickets/{tid}/state",
        json={
            "to_state": "rejected",
            "reason": "host registrar rejected on insufficient evidence",
        },
        headers=_hdr(analyst_user),
    )
    assert ok.status_code == 200
    assert ok.json()["state"] == "rejected"


async def test_sync_pulls_partner_state(
    client: AsyncClient, analyst_user, organization
):
    register_adapter(_FakePartnerAdapter(status="succeeded"))
    create = await client.post(
        "/api/v1/takedown/tickets",
        json={
            "organization_id": str(organization["id"]),
            "partner": "manual",
            "target_kind": "suspect_domain",
            "target_identifier": "sync-test-argus.com",
            "reason": "phish",
        },
        headers=_hdr(analyst_user),
    )
    tid = create.json()["id"]
    sync = await client.post(
        f"/api/v1/takedown/tickets/{tid}/sync",
        headers=_hdr(analyst_user),
    )
    assert sync.status_code == 200
    assert sync.json()["state"] == "succeeded"
    assert sync.json()["succeeded_at"] is not None


async def test_listing_filters_by_state_and_partner(
    client: AsyncClient, analyst_user, organization
):
    for kind in ("suspect_domain", "impersonation", "mobile_app"):
        await client.post(
            "/api/v1/takedown/tickets",
            json={
                "organization_id": str(organization["id"]),
                "partner": "manual",
                "target_kind": kind,
                "target_identifier": f"x-{kind}.example",
                "reason": "test",
            },
            headers=_hdr(analyst_user),
        )
    listed = await client.get(
        "/api/v1/takedown/tickets",
        params={
            "organization_id": str(organization["id"]),
            "target_kind": "impersonation",
        },
        headers=_hdr(analyst_user),
    )
    assert all(t["target_kind"] == "impersonation" for t in listed.json())
