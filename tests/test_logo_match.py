"""Logo abuse — perceptual-hash matcher integration tests (Phase 3.4).

Verifies:
    - fingerprint() produces stable pHash/dHash/aHash + color histogram
    - compare() distinguishes identical / near-identical / different images
    - register-logo endpoint persists hashes + evidence blob
    - match endpoint creates LogoMatch rows for likely / possible abuse
    - completely unrelated image → no_match
    - tenant isolation on logos and matches
    - audit log emitted
"""

from __future__ import annotations

import io
import uuid

import pytest
from httpx import AsyncClient
from PIL import Image, ImageDraw, ImageFilter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.brand.logo_match import compare, fingerprint

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


# --- Image helpers -----------------------------------------------------


def _png_with_text(text: str, *, size=(256, 96), bg=(255, 255, 255), fg=(0, 100, 200), seed: int = 0) -> bytes:
    """Synthetic logo: solid bg + colored bar + text. Deterministic for tests."""
    img = Image.new("RGB", size, bg)
    draw = ImageDraw.Draw(img)
    draw.rectangle((0, 0, size[0], 16), fill=fg)
    draw.rectangle((seed, 30, seed + 200, 70), fill=fg)
    draw.text((10, 30), text, fill=fg)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _png_unrelated() -> bytes:
    img = Image.new("RGB", (256, 96), (10, 10, 10))
    draw = ImageDraw.Draw(img)
    for x in range(0, 256, 8):
        draw.rectangle((x, 0, x + 4, 96), fill=(200, 50, 50))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _png_jpeg_recompress(blob: bytes) -> bytes:
    img = Image.open(io.BytesIO(blob))
    out = io.BytesIO()
    img.convert("RGB").save(out, format="JPEG", quality=70)
    return out.getvalue()


def _png_blurred(blob: bytes) -> bytes:
    img = Image.open(io.BytesIO(blob)).filter(ImageFilter.GaussianBlur(radius=1))
    out = io.BytesIO()
    img.convert("RGB").save(out, format="PNG")
    return out.getvalue()


# --- Pure function tests ----------------------------------------------


def test_fingerprint_is_stable():
    blob = _png_with_text("ARGUS")
    a = fingerprint(blob)
    b = fingerprint(blob)
    assert a == b
    assert len(a.phash_hex) > 0
    assert len(a.color_histogram) == 48


def test_compare_identical_is_likely_abuse():
    blob = _png_with_text("ARGUS")
    fp = fingerprint(blob)
    result = compare(fp, fp.phash_hex, fp.dhash_hex, fp.ahash_hex, fp.color_histogram)
    assert result.verdict == "likely_abuse"
    assert result.similarity > 0.95
    assert result.phash_distance == 0


def test_compare_jpeg_recompress_still_likely():
    original = _png_with_text("ARGUS")
    recompressed = _png_jpeg_recompress(original)
    fp_a = fingerprint(original)
    fp_b = fingerprint(recompressed)
    result = compare(fp_b, fp_a.phash_hex, fp_a.dhash_hex, fp_a.ahash_hex, fp_a.color_histogram)
    assert result.verdict in ("likely_abuse", "possible_abuse")
    assert result.similarity >= 0.7


def test_compare_unrelated_is_no_match():
    a = fingerprint(_png_with_text("ARGUS"))
    b = fingerprint(_png_unrelated())
    result = compare(b, a.phash_hex, a.dhash_hex, a.ahash_hex, a.color_histogram)
    assert result.verdict == "no_match"


def test_fingerprint_rejects_empty():
    with pytest.raises(ValueError):
        fingerprint(b"")


# --- API: register + match -------------------------------------------


async def test_register_logo_persists_hashes_and_evidence(
    client: AsyncClient, analyst_user, organization
):
    blob = _png_with_text("ARGUS")
    r = await client.post(
        "/api/v1/brand/logos",
        data={
            "organization_id": str(organization["id"]),
            "label": "Argus primary mark",
        },
        files={"file": ("argus.png", io.BytesIO(blob), "image/png")},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["label"] == "Argus primary mark"
    assert body["phash_hex"] and body["dhash_hex"] and body["ahash_hex"]
    assert body["image_evidence_sha256"]


async def test_register_duplicate_logo_409(
    client: AsyncClient, analyst_user, organization
):
    blob = _png_with_text("ARGUS")
    r1 = await client.post(
        "/api/v1/brand/logos",
        data={"organization_id": str(organization["id"]), "label": "first"},
        files={"file": ("a.png", io.BytesIO(blob), "image/png")},
        headers=_hdr(analyst_user),
    )
    assert r1.status_code == 201
    r2 = await client.post(
        "/api/v1/brand/logos",
        data={"organization_id": str(organization["id"]), "label": "dup"},
        files={"file": ("a.png", io.BytesIO(blob), "image/png")},
        headers=_hdr(analyst_user),
    )
    assert r2.status_code == 409


async def test_match_creates_likely_abuse_row(
    client: AsyncClient, analyst_user, organization
):
    base = _png_with_text("ARGUS")
    await client.post(
        "/api/v1/brand/logos",
        data={"organization_id": str(organization["id"]), "label": "argus"},
        files={"file": ("argus.png", io.BytesIO(base), "image/png")},
        headers=_hdr(analyst_user),
    )
    # Slightly modified copy — JPEG re-encode
    candidate = _png_jpeg_recompress(base)
    r = await client.post(
        "/api/v1/brand/logos/match",
        data={"organization_id": str(organization["id"])},
        files={"file": ("phish.jpg", io.BytesIO(candidate), "image/jpeg")},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200, r.text
    matches = r.json()
    assert len(matches) >= 1
    assert matches[0]["verdict"] in ("likely_abuse", "possible_abuse")
    assert matches[0]["similarity"] > 0.5


async def test_match_unrelated_returns_empty(
    client: AsyncClient, analyst_user, organization
):
    await client.post(
        "/api/v1/brand/logos",
        data={"organization_id": str(organization["id"]), "label": "argus"},
        files={"file": ("a.png", io.BytesIO(_png_with_text("ARGUS")), "image/png")},
        headers=_hdr(analyst_user),
    )
    r = await client.post(
        "/api/v1/brand/logos/match",
        data={"organization_id": str(organization["id"])},
        files={"file": ("u.png", io.BytesIO(_png_unrelated()), "image/png")},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    assert r.json() == []


async def test_logo_match_listing_filters_by_verdict(
    client: AsyncClient, analyst_user, organization
):
    base = _png_with_text("ARGUS")
    await client.post(
        "/api/v1/brand/logos",
        data={"organization_id": str(organization["id"]), "label": "argus"},
        files={"file": ("argus.png", io.BytesIO(base), "image/png")},
        headers=_hdr(analyst_user),
    )
    # match against a re-encoded copy
    cand = _png_jpeg_recompress(base)
    await client.post(
        "/api/v1/brand/logos/match",
        data={"organization_id": str(organization["id"])},
        files={"file": ("c.jpg", io.BytesIO(cand), "image/jpeg")},
        headers=_hdr(analyst_user),
    )
    listed = await client.get(
        "/api/v1/brand/logos/matches",
        params={
            "organization_id": str(organization["id"]),
            "verdict": "likely_abuse",
        },
        headers=_hdr(analyst_user),
    )
    assert listed.status_code == 200
    assert all(m["verdict"] == "likely_abuse" for m in listed.json())


async def test_logos_tenant_scoped(
    client: AsyncClient, analyst_user, organization, second_organization
):
    blob = _png_with_text("ORG-A")
    await client.post(
        "/api/v1/brand/logos",
        data={"organization_id": str(organization["id"]), "label": "a"},
        files={"file": ("a.png", io.BytesIO(blob), "image/png")},
        headers=_hdr(analyst_user),
    )
    other = await client.get(
        "/api/v1/brand/logos",
        params={"organization_id": str(second_organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert other.status_code == 200
    assert other.json() == []


async def test_logo_register_audit_log(
    client: AsyncClient, analyst_user, organization, test_engine
):
    blob = _png_with_text("AUDIT")
    r = await client.post(
        "/api/v1/brand/logos",
        data={"organization_id": str(organization["id"]), "label": "audit"},
        files={"file": ("a.png", io.BytesIO(blob), "image/png")},
        headers=_hdr(analyst_user),
    )
    logo_id = r.json()["id"]

    from src.models.auth import AuditAction, AuditLog

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        rows = await s.execute(
            select(AuditLog.action).where(AuditLog.resource_id == logo_id)
        )
        actions = {row[0] for row in rows.all()}
    assert AuditAction.BRAND_LOGO_REGISTER.value in actions
