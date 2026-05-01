"""Phase 4.3 — Online Anti-Fraud — integration tests."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from src.social.fraud import score_text

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


# --- Pure scoring -----------------------------------------------------


def test_investment_scam_keywords_score_high():
    r = score_text(
        "Invest with us! Guaranteed returns, 100% safe, "
        "double your money in 7 days! Limited slots — act now.",
        brand_terms=[],
    )
    assert r.kind == "investment_scam"
    assert r.score >= 0.5
    assert "guaranteed returns" in r.matched_keywords
    assert "double your money" in r.matched_keywords


def test_crypto_giveaway_with_wallet_score_high():
    r = score_text(
        "Send 0.5 BTC to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq "
        "and we'll double your BTC in our official giveaway",
        brand_terms=[],
    )
    assert r.kind == "crypto_giveaway"
    assert r.score >= 0.5
    assert r.extra["has_crypto_address"] is True


def test_brand_mention_lifts_score():
    no_brand = score_text(
        "Guaranteed returns daily!", brand_terms=[]
    )
    with_brand = score_text(
        "Guaranteed returns daily — invest with Argus VIP fund!",
        brand_terms=["argus"],
    )
    assert with_brand.score > no_brand.score
    assert "argus" in with_brand.matched_brand_terms


def test_benign_text_low_score():
    r = score_text(
        "Hello, this is just a normal blog post about some technical topic.",
        brand_terms=["argus"],
    )
    assert r.score < 0.4


# --- API --------------------------------------------------------------


async def test_fraud_check_persists_when_above_threshold(
    client: AsyncClient, analyst_user, organization
):
    # Seed a brand term so brand mention can lift scores
    await client.post(
        "/api/v1/brand/terms",
        json={
            "organization_id": str(organization["id"]),
            "kind": "name",
            "value": "argus",
        },
        headers=_hdr(analyst_user),
    )
    r = await client.post(
        "/api/v1/social/fraud/check",
        json={
            "organization_id": str(organization["id"]),
            "channel": "telegram",
            "target_identifier": "@argus_official_vip",
            "title": "Argus VIP signals",
            "text": (
                "Welcome to Argus VIP signals! Guaranteed returns of 10x — "
                "send 0.5 BTC to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq "
                "and double your money instantly. Limited slots — act now."
            ),
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body is not None
    assert body["score"] >= 0.5
    assert body["kind"] in ("investment_scam", "crypto_giveaway")
    assert "argus" in body["matched_brand_terms"]


async def test_fraud_check_below_threshold_returns_null(
    client: AsyncClient, analyst_user, organization
):
    r = await client.post(
        "/api/v1/social/fraud/check",
        json={
            "organization_id": str(organization["id"]),
            "channel": "website",
            "target_identifier": "https://example.com/blog",
            "text": "A normal blog post about cybersecurity industry trends.",
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 200
    assert r.json() is None


async def test_fraud_state_machine(
    client: AsyncClient, analyst_user, organization
):
    create = await client.post(
        "/api/v1/social/fraud/check",
        json={
            "organization_id": str(organization["id"]),
            "channel": "telegram",
            "target_identifier": "@scam_channel_argus",
            "text": "Guaranteed returns! 100% safe. Daily profit. ROI guaranteed.",
        },
        headers=_hdr(analyst_user),
    )
    assert create.status_code == 200
    fid = create.json()["id"]

    no_reason = await client.post(
        f"/api/v1/social/fraud/{fid}/state",
        json={"to_state": "reported_to_regulator"},
        headers=_hdr(analyst_user),
    )
    assert no_reason.status_code == 422

    with_reason = await client.post(
        f"/api/v1/social/fraud/{fid}/state",
        json={
            "to_state": "reported_to_regulator",
            "reason": "Filed FCA scam-warning notice 2026-04-28",
        },
        headers=_hdr(analyst_user),
    )
    assert with_reason.status_code == 200
    assert with_reason.json()["state"] == "reported_to_regulator"


async def test_fraud_listing_filters(
    client: AsyncClient, analyst_user, organization
):
    payloads = [
        (
            "telegram",
            "@scam_a",
            "Guaranteed returns daily, 100% safe, double your money, "
            "limited slots! Earn daily — withdraw anytime, no risk.",
        ),
        (
            "website",
            "https://scam.example",
            "Send 0.5 BTC to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq, "
            "double your BTC in our official giveaway. Limited time!",
        ),
    ]
    for channel, target, text in payloads:
        await client.post(
            "/api/v1/social/fraud/check",
            json={
                "organization_id": str(organization["id"]),
                "channel": channel,
                "target_identifier": target,
                "text": text,
            },
            headers=_hdr(analyst_user),
        )

    only_tg = await client.get(
        "/api/v1/social/fraud",
        params={
            "organization_id": str(organization["id"]),
            "channel": "telegram",
        },
        headers=_hdr(analyst_user),
    )
    assert all(f["channel"] == "telegram" for f in only_tg.json())
    assert any("@scam_a" in f["target_identifier"] for f in only_tg.json())
