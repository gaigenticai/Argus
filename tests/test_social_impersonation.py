"""Phase 4 — Social Impersonation + Mobile App findings.

Verifies:
    - VIP CRUD + photo attachment computes pHash and stores evidence
    - Impersonation scoring engine: name + handle + bio + photo signals aggregate correctly
    - check_impersonation persists ImpersonationFinding rows for review/confirmed
    - check_impersonation skips persisting low-score (verdict=ignore)
    - state machine transitions
    - Mobile app finding lifecycle
    - Tenant isolation
"""

from __future__ import annotations

import io
import uuid

import pytest
from httpx import AsyncClient
from PIL import Image
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.brand.logo_match import fingerprint
from src.models.social import VipProfile
from src.social.impersonation import score_candidate

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


def _png(rgb=(20, 70, 200)) -> bytes:
    img = Image.new("RGB", (96, 96), rgb)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# --- Pure scoring engine ----------------------------------------------


def _vip(name="Krishna Iyer", aliases=("K. Iyer", "Krish"), bio_keywords=("CEO", "Argus", "Gaigentic")):
    v = VipProfile(
        organization_id=uuid.uuid4(),
        full_name=name,
        title="CEO",
        aliases=list(aliases),
        bio_keywords=list(bio_keywords),
        photo_evidence_sha256s=[],
        photo_phashes=[],
    )
    return v


def test_score_strong_impersonation():
    s = score_candidate(
        candidate_handle="krishna_iyer_official",
        candidate_display_name="Krishna Iyer (CEO)",
        candidate_bio="CEO at Gaigentic AI, building Argus.",
        candidate_photo_phash=None,
        vip=_vip(),
        official_handles=["krishnaiyer"],
    )
    assert s.verdict in ("confirmed", "review")
    assert s.aggregate_score >= 0.6
    assert "name_match_strong" in s.signals or "name_match_partial" in s.signals


def test_score_weak_random_user_ignored():
    s = score_candidate(
        candidate_handle="techguy42",
        candidate_display_name="Random Tech Guy",
        candidate_bio="I love computers.",
        candidate_photo_phash=None,
        vip=_vip(),
        official_handles=["krishnaiyer"],
    )
    assert s.verdict == "ignore"
    assert s.aggregate_score < 0.6


def test_score_photo_match_lifts_aggregate():
    fp = fingerprint(_png((100, 200, 50)))
    vip = _vip()
    vip.photo_phashes = [fp.phash_hex]

    no_photo = score_candidate(
        candidate_handle="random",
        candidate_display_name="Krishna Iyer",
        candidate_bio="",
        candidate_photo_phash=None,
        vip=vip,
        official_handles=["krishnaiyer"],
    )
    with_photo = score_candidate(
        candidate_handle="random",
        candidate_display_name="Krishna Iyer",
        candidate_bio="",
        candidate_photo_phash=fp.phash_hex,
        vip=vip,
        official_handles=["krishnaiyer"],
    )
    assert with_photo.photo_similarity == 1.0
    assert "photo_match_strong" in with_photo.signals
    assert with_photo.aggregate_score >= no_photo.aggregate_score


# --- API: VIP + photo --------------------------------------------------


async def _create_vip(client, analyst, organization, name="Krishna Iyer"):
    r = await client.post(
        "/api/v1/social/vips",
        json={
            "organization_id": str(organization["id"]),
            "full_name": name,
            "title": "CEO",
            "aliases": ["K. Iyer"],
            "bio_keywords": ["ceo", "argus", "gaigentic"],
        },
        headers=_hdr(analyst),
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def test_vip_register_and_attach_photo(
    client: AsyncClient, analyst_user, organization
):
    vid = await _create_vip(client, analyst_user, organization)
    blob = _png((50, 200, 100))
    r = await client.post(
        f"/api/v1/social/vips/{vid}/photos",
        files={"file": ("p.png", io.BytesIO(blob), "image/png")},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["photo_phashes"]) == 1
    assert len(body["photo_evidence_sha256s"]) == 1


# --- API: social account + impersonation flow -------------------------


async def test_impersonation_check_creates_finding(
    client: AsyncClient, analyst_user, organization
):
    vid = await _create_vip(client, analyst_user, organization)
    await client.post(
        "/api/v1/social/accounts",
        json={
            "organization_id": str(organization["id"]),
            "vip_profile_id": vid,
            "platform": "twitter",
            "handle": "krishnaiyer",
            "is_official": True,
        },
        headers=_hdr(analyst_user),
    )
    r = await client.post(
        "/api/v1/social/impersonations/check",
        json={
            "organization_id": str(organization["id"]),
            "vip_profile_id": vid,
            "platform": "twitter",
            "candidate_handle": "krishna_iyer_official",
            "candidate_display_name": "Krishna Iyer (CEO)",
            "candidate_bio": "CEO at Gaigentic AI, building Argus.",
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body is not None
    assert body["aggregate_score"] >= 0.6
    assert body["state"] in ("open", "confirmed")


async def test_impersonation_check_low_score_returns_null(
    client: AsyncClient, analyst_user, organization
):
    vid = await _create_vip(client, analyst_user, organization)
    r = await client.post(
        "/api/v1/social/impersonations/check",
        json={
            "organization_id": str(organization["id"]),
            "vip_profile_id": vid,
            "platform": "twitter",
            "candidate_handle": "techguy42",
            "candidate_display_name": "Random Tech Guy",
            "candidate_bio": "Love computers",
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    assert r.json() is None


async def test_impersonation_state_transition(
    client: AsyncClient, analyst_user, organization
):
    vid = await _create_vip(client, analyst_user, organization)
    r = await client.post(
        "/api/v1/social/impersonations/check",
        json={
            "organization_id": str(organization["id"]),
            "vip_profile_id": vid,
            "platform": "x",
            "candidate_handle": "krishna_official_iyer",
            "candidate_display_name": "Krishna Iyer",
            "candidate_bio": "CEO Argus",
        },
        headers=_hdr(analyst_user),
    )
    fid = r.json()["id"]
    no_reason = await client.post(
        f"/api/v1/social/impersonations/{fid}/state",
        json={"to_state": "takedown_requested"},
        headers=_hdr(analyst_user),
    )
    assert no_reason.status_code == 422
    ok = await client.post(
        f"/api/v1/social/impersonations/{fid}/state",
        json={"to_state": "takedown_requested", "reason": "submitted to X"},
        headers=_hdr(analyst_user),
    )
    assert ok.status_code == 200
    assert ok.json()["state"] == "takedown_requested"


# --- Mobile app findings ---------------------------------------------


async def test_mobile_app_finding_lifecycle(
    client: AsyncClient, analyst_user, organization
):
    create = await client.post(
        "/api/v1/social/mobile-apps/check",
        json={
            "organization_id": str(organization["id"]),
            "store": "google_play",
            "app_id": "com.scammer.argusbank",
            "title": "Argus Banking",
            "publisher": "Scammer Inc.",
            "matched_term": "argus",
            "matched_term_kind": "name",
        },
        headers=_hdr(analyst_user),
    )
    assert create.status_code == 201, create.text
    fid = create.json()["id"]

    listed = await client.get(
        "/api/v1/social/mobile-apps",
        params={"organization_id": str(organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert any(a["id"] == fid for a in listed.json())

    transition = await client.post(
        f"/api/v1/social/mobile-apps/{fid}/state",
        json={"to_state": "takedown_requested", "reason": "DMCA filed"},
        headers=_hdr(analyst_user),
    )
    assert transition.status_code == 200
    assert transition.json()["state"] == "takedown_requested"


async def test_tenant_isolation(
    client: AsyncClient, analyst_user, organization, second_organization
):
    vid = await _create_vip(client, analyst_user, organization)
    await client.post(
        "/api/v1/social/impersonations/check",
        json={
            "organization_id": str(organization["id"]),
            "vip_profile_id": vid,
            "platform": "twitter",
            "candidate_handle": "krishna_official_iyer",
            "candidate_display_name": "Krishna Iyer",
            "candidate_bio": "CEO Argus",
        },
        headers=_hdr(analyst_user),
    )
    other = await client.get(
        "/api/v1/social/impersonations",
        params={"organization_id": str(second_organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert other.json() == []
