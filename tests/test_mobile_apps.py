"""Audit B3 — mobile-app scanner smoke test.

Injects fake Google-Play and iTunes search functions so we don't
hammer the real stores during CI. The rest of the pipeline (scoring,
official-publisher matching, persistence, idempotency) runs for real
against the test Postgres.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from src.models.brand import BrandTerm, BrandTermKind
from src.models.social import (
    MobileAppFinding,
    MobileAppStore,
)
from src.social.mobile_apps import (
    AppCandidate,
    scan_organization,
)

pytestmark = pytest.mark.asyncio


def _gp_cand(app_id: str, title: str, publisher: str | None) -> AppCandidate:
    return AppCandidate(
        store=MobileAppStore.GOOGLE_PLAY,
        app_id=app_id,
        title=title,
        publisher=publisher,
        description=None,
        url=f"https://play.google.com/store/apps/details?id={app_id}",
        rating=4.0,
        install_estimate="100,000+",
        raw={"appId": app_id, "title": title, "developer": publisher},
    )


def _ios_cand(app_id: str, title: str, publisher: str | None) -> AppCandidate:
    return AppCandidate(
        store=MobileAppStore.APPLE,
        app_id=app_id,
        title=title,
        publisher=publisher,
        description=None,
        url=f"https://apps.apple.com/app/id{app_id}",
        rating=4.5,
        install_estimate=None,
        raw={"trackId": app_id, "trackName": title, "sellerName": publisher},
    )


async def _seed_brand_term(test_engine, organization_id, kind, value: str):
    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        s.add(
            BrandTerm(
                organization_id=organization_id,
                kind=kind.value,
                value=value.lower(),
                keywords=[],
                is_active=True,
            )
        )
        await s.commit()


async def test_mobile_apps_scan_creates_findings(test_engine, organization):
    """Two rogue apps + one official-publisher app should land 3
    findings total — but only the rogues are eligible for auto-case
    promotion (verified via the ``is_official_publisher`` flag)."""
    org_id = organization["id"]
    await _seed_brand_term(
        test_engine, org_id, BrandTermKind.NAME, "argus"
    )

    fake_gp = [
        # rogue app — random publisher pretending to be the brand
        _gp_cand(
            "com.scammer.argus_pay",
            "Argus Pay - Banking",
            "ScamCorp Ltd",
        ),
        # noise — unrelated app, low fuzz score
        _gp_cand(
            "com.cooking.recipes",
            "1000 Cooking Recipes",
            "Foodies Inc",
        ),
    ]
    fake_ios = [
        # official app — publisher matches the org's known list
        _ios_cand("123456", "Argus Mobile", "Argus Banking Corp"),
        # rogue — close title but not the official publisher
        _ios_cand("999888", "argus secure login", "Random Person"),
    ]

    def fake_gp_search(query: str, limit: int):
        if query.lower() == "argus":
            return fake_gp
        return []

    async def fake_itunes_search(http, query, *, country="us", limit=50):
        if query.lower() == "argus":
            return fake_ios
        return []

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        report = await scan_organization(
            s,
            org_id,
            official_publishers=["Argus Banking Corp"],
            google_play_search=fake_gp_search,
            itunes_search=fake_itunes_search,
        )
        await s.commit()

    assert report.terms_scanned == 1
    assert report.suspects_created >= 2  # at least both rogues
    # The cooking app is below the similarity threshold, so it should
    # not have been persisted as a finding.
    async with factory() as s:
        rows = (
            await s.execute(
                select(MobileAppFinding).where(
                    MobileAppFinding.organization_id == org_id
                )
            )
        ).scalars().all()

    titles = {r.title for r in rows}
    assert "Argus Pay - Banking" in titles
    assert "argus secure login" in titles
    assert "1000 Cooking Recipes" not in titles

    official = next((r for r in rows if r.title == "Argus Mobile"), None)
    assert official is not None, "official app should still be recorded for audit"
    assert official.is_official_publisher is True
    rogue = next((r for r in rows if r.title == "Argus Pay - Banking"), None)
    assert rogue is not None and rogue.is_official_publisher is False


async def test_mobile_apps_scan_idempotent(test_engine, organization):
    """Running the scan twice should not duplicate findings — the
    ``(org, store, app_id)`` unique constraint means re-runs touch
    rather than insert."""
    org_id = organization["id"]
    await _seed_brand_term(
        test_engine, org_id, BrandTermKind.NAME, "argus"
    )

    fake_gp = [_gp_cand("com.x.argus_y", "Argus Y", "XCorp")]

    def fake_gp_search(query: str, limit: int):
        return fake_gp

    async def fake_itunes_search(http, query, **kwargs):
        return []

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )

    async with factory() as s:
        first = await scan_organization(
            s,
            org_id,
            google_play_search=fake_gp_search,
            itunes_search=fake_itunes_search,
        )
        await s.commit()

    async with factory() as s:
        second = await scan_organization(
            s,
            org_id,
            google_play_search=fake_gp_search,
            itunes_search=fake_itunes_search,
        )
        await s.commit()

    assert first.suspects_created == 1
    assert second.suspects_created == 0
    assert second.suspects_seen_again >= 1
