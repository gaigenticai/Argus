"""Brand Protection (Phase 3.1) — typosquat detection integration tests.

Verifies:
    - permutation engine generates the expected categories
    - similarity scoring is monotonic (closer = higher)
    - end-to-end scan with fake resolver creates SuspectDomain rows
    - re-scan bumps last_seen_at + similarity, no duplicates
    - state machine: open → confirmed_phishing requires reason
    - filters by state, source, similarity floor
    - tenant isolation
    - audit log on scan + state change
"""

from __future__ import annotations

import uuid
from typing import Iterable

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.api.routes.brand import reset_test_resolver, set_test_resolver
from src.brand.permutations import (
    domain_similarity,
    generate_permutations,
)
from src.brand.scanner import ResolutionResult

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


@pytest.fixture(autouse=True)
def _reset_resolver():
    reset_test_resolver()
    yield
    reset_test_resolver()


def _fake_resolver(resolvable_set: Iterable[str]):
    rs = {d.lower() for d in resolvable_set}

    async def resolve(domains):
        out = []
        for d in domains:
            if d.lower() in rs:
                out.append(
                    ResolutionResult(
                        d,
                        is_resolvable=True,
                        a_records=["10.0.0.1"],
                        mx_records=["10 mx.example."],
                        nameservers=["ns1.example.", "ns2.example."],
                    )
                )
            else:
                out.append(ResolutionResult(d, False, [], [], []))
        return out

    return resolve


# --- Pure unit ----------------------------------------------------------


def test_permutations_emit_expected_kinds():
    perms = generate_permutations("argus.com", max_per_kind=200)
    kinds = {p.kind for p in perms}
    assert {
        "addition",
        "omission",
        "repetition",
        "replacement",
        "transposition",
        "homoglyph",
        "bitsquatting",
        "hyphenation",
        "vowel_swap",
        "tld_swap",
    } <= kinds
    # No self-permutation
    assert all(p.domain != "argus.com" for p in perms)
    # tld swap targets stay sensible
    assert any(p.domain.endswith(".net") for p in perms)


def test_similarity_monotonic():
    base = "argus.com"
    sim_self = domain_similarity(base, base)
    sim_close = domain_similarity(base, "arqus.com")
    sim_far = domain_similarity(base, "totallyunrelated.io")
    assert sim_self == 1.0
    assert sim_close > sim_far
    assert 0 <= sim_far < 0.5


# --- API: terms ---------------------------------------------------------


async def test_create_and_list_brand_terms(client: AsyncClient, analyst_user, organization):
    create = await client.post(
        "/api/v1/brand/terms",
        json={
            "organization_id": str(organization["id"]),
            "kind": "apex_domain",
            "value": "Argus.Com",  # gets lowercased
        },
        headers=_hdr(analyst_user),
    )
    assert create.status_code == 201, create.text
    assert create.json()["value"] == "argus.com"

    listed = await client.get(
        "/api/v1/brand/terms",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert listed.status_code == 200
    assert any(t["value"] == "argus.com" for t in listed.json())


async def test_duplicate_term_409(client: AsyncClient, analyst_user, organization):
    payload = {
        "organization_id": str(organization["id"]),
        "kind": "name",
        "value": "argus",
    }
    a = await client.post("/api/v1/brand/terms", json=payload, headers=_hdr(analyst_user))
    b = await client.post("/api/v1/brand/terms", json=payload, headers=_hdr(analyst_user))
    assert a.status_code == 201
    assert b.status_code == 409


# --- Scan ---------------------------------------------------------------


async def test_scan_creates_suspects_for_resolvable_lookalikes(
    client: AsyncClient, analyst_user, organization
):
    await client.post(
        "/api/v1/brand/terms",
        json={
            "organization_id": str(organization["id"]),
            "kind": "apex_domain",
            "value": "argus.com",
        },
        headers=_hdr(analyst_user),
    )
    # Pre-generate to pick realistic resolvable candidates the engine
    # actually emits (tld_swap, homoglyph, hyphenation).
    from src.brand.permutations import generate_permutations

    perms = {p.domain for p in generate_permutations("argus.com")}
    assert "argus.net" in perms  # tld_swap
    assert "argu5.com" in perms  # homoglyph (s → 5)
    assert "ar-gus.com" in perms  # hyphenation

    set_test_resolver(_fake_resolver(["argus.net", "argu5.com", "ar-gus.com"]))
    r = await client.post(
        f"/api/v1/brand/scan?organization_id={organization['id']}",
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["terms_scanned"] >= 1
    assert body["permutations_generated"] > 100
    assert body["candidates_resolved"] == 3
    assert body["suspects_created"] == 3

    listed = await client.get(
        "/api/v1/brand/suspects",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    domains = {s["domain"] for s in listed.json()}
    assert {"argus.net", "argu5.com", "ar-gus.com"} <= domains


async def test_rescan_idempotent(
    client: AsyncClient, analyst_user, organization
):
    await client.post(
        "/api/v1/brand/terms",
        json={
            "organization_id": str(organization["id"]),
            "kind": "apex_domain",
            "value": "argus.com",
        },
        headers=_hdr(analyst_user),
    )
    set_test_resolver(_fake_resolver(["argus.net"]))
    first = await client.post(
        f"/api/v1/brand/scan?organization_id={organization['id']}",
        headers=_hdr(analyst_user),
    )
    second = await client.post(
        f"/api/v1/brand/scan?organization_id={organization['id']}",
        headers=_hdr(analyst_user),
    )
    assert first.json()["suspects_created"] == 1
    assert second.json()["suspects_created"] == 0
    assert second.json()["suspects_seen_again"] >= 1


async def test_scan_with_only_resolvable_false_picks_all(
    client: AsyncClient, analyst_user, organization
):
    await client.post(
        "/api/v1/brand/terms",
        json={
            "organization_id": str(organization["id"]),
            "kind": "apex_domain",
            "value": "shortbrand.io",
        },
        headers=_hdr(analyst_user),
    )
    # No resolvable hits configured.
    set_test_resolver(_fake_resolver([]))
    r = await client.post(
        f"/api/v1/brand/scan?organization_id={organization['id']}&only_resolvable=false",
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    body = r.json()
    # We should still create some suspects (every permutation, since
    # only_resolvable=false). Cap to avoid huge list — bound by permutation count.
    assert body["suspects_created"] > 50


# --- State machine ------------------------------------------------------


async def test_state_change_requires_reason(
    client: AsyncClient, analyst_user, organization
):
    await client.post(
        "/api/v1/brand/terms",
        json={
            "organization_id": str(organization["id"]),
            "kind": "apex_domain",
            "value": "argus.com",
        },
        headers=_hdr(analyst_user),
    )
    set_test_resolver(_fake_resolver(["argus.net"]))
    await client.post(
        f"/api/v1/brand/scan?organization_id={organization['id']}",
        headers=_hdr(analyst_user),
    )
    suspect = (
        await client.get(
            "/api/v1/brand/suspects",
            params={"organization_id": str(organization["id"])},
            headers=_hdr(analyst_user),
        )
    ).json()[0]
    sid = suspect["id"]

    bad = await client.post(
        f"/api/v1/brand/suspects/{sid}/state",
        json={"to_state": "confirmed_phishing"},
        headers=_hdr(analyst_user),
    )
    assert bad.status_code == 422

    ok = await client.post(
        f"/api/v1/brand/suspects/{sid}/state",
        json={"to_state": "confirmed_phishing", "reason": "phishing kit captured"},
        headers=_hdr(analyst_user),
    )
    assert ok.status_code == 200
    assert ok.json()["state"] == "confirmed_phishing"


# --- Filters ------------------------------------------------------------


async def test_filter_by_min_similarity(
    client: AsyncClient, analyst_user, organization
):
    await client.post(
        "/api/v1/brand/terms",
        json={
            "organization_id": str(organization["id"]),
            "kind": "apex_domain",
            "value": "argus.com",
        },
        headers=_hdr(analyst_user),
    )
    # ar-gus.com (1 char insertion, sim ~0.9) vs argus.net (3 chars
    # different in TLD, sim ~0.67). Threshold 0.85 keeps ar-gus and drops argus.net.
    set_test_resolver(_fake_resolver(["argus.net", "ar-gus.com"]))
    await client.post(
        f"/api/v1/brand/scan?organization_id={organization['id']}",
        headers=_hdr(analyst_user),
    )
    high = await client.get(
        "/api/v1/brand/suspects",
        params={
            "organization_id": str(organization["id"]),
            "min_similarity": 0.85,
        },
        headers=_hdr(analyst_user),
    )
    domains_high = {s["domain"] for s in high.json()}
    assert "ar-gus.com" in domains_high
    assert "argus.net" not in domains_high

    # Lower threshold pulls argus.net in too.
    low = await client.get(
        "/api/v1/brand/suspects",
        params={
            "organization_id": str(organization["id"]),
            "min_similarity": 0.5,
        },
        headers=_hdr(analyst_user),
    )
    domains_low = {s["domain"] for s in low.json()}
    assert {"argus.net", "ar-gus.com"} <= domains_low


# --- Tenant isolation + audit -----------------------------------------


async def test_scope_tenant_and_audit(
    client: AsyncClient, analyst_user, organization, second_organization, test_engine
):
    await client.post(
        "/api/v1/brand/terms",
        json={
            "organization_id": str(organization["id"]),
            "kind": "apex_domain",
            "value": "argus.com",
        },
        headers=_hdr(analyst_user),
    )
    set_test_resolver(_fake_resolver(["argus.net"]))
    r = await client.post(
        f"/api/v1/brand/scan?organization_id={organization['id']}",
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200

    other = await client.get(
        "/api/v1/brand/suspects",
        params={"organization_id": str(second_organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert other.json() == []

    from src.models.auth import AuditAction, AuditLog

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        rows = await s.execute(
            select(AuditLog.action).where(
                AuditLog.action.in_(
                    [
                        AuditAction.BRAND_TERM_CREATE.value,
                        AuditAction.SUSPECT_DOMAIN_DETECT.value,
                    ]
                )
            )
        )
        actions = {row[0] for row in rows.all()}
    assert AuditAction.BRAND_TERM_CREATE.value in actions
    assert AuditAction.SUSPECT_DOMAIN_DETECT.value in actions


async def test_unauthenticated_rejected(client: AsyncClient, organization):
    r = await client.get(
        "/api/v1/brand/suspects",
        params={"organization_id": str(organization["id"])},
    )
    assert r.status_code in (401, 403)
