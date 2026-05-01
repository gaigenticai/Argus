"""Audit B3 — TikTok monitor smoke tests.

Inject canned snapshot loaders so tests never spawn a browser.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from src.models.brand import BrandTerm, BrandTermKind
from src.models.fraud import FraudFinding
from src.models.social import (
    ImpersonationFinding,
    SocialPlatform,
    VipProfile,
)
from src.models.threat import Organization
from src.social.tiktok_monitor import (
    TikTokProfileSnapshot,
    TikTokVideoSnapshot,
    scan_organization,
)

pytestmark = pytest.mark.asyncio


async def _seed_brand(test_engine, organization_id, value, kind):
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


async def _set_handles(test_engine, organization_id, handles):
    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        org = await s.get(Organization, organization_id)
        org.settings = {"tiktok_monitor_handles": handles}
        await s.commit()


def _snap(handle, *, name=None, bio=None, verified=False, videos=()):
    return TikTokProfileSnapshot(
        handle=handle,
        display_name=name,
        biography=bio,
        is_verified=verified,
        profile_url=f"https://www.tiktok.com/@{handle}",
        videos=list(videos),
        raw={},
    )


async def test_tiktok_scan_creates_findings_per_handle(
    test_engine, organization
):
    org_id = organization["id"]
    await _seed_brand(test_engine, org_id, "argus", BrandTermKind.NAME)
    await _set_handles(
        test_engine, org_id, ["argus_official_xx", "real_argus_tt"]
    )

    profiles = {
        # impersonator: handle matches brand, has scam video, not verified
        "argus_official_xx": _snap(
            "argus_official_xx",
            name="Argus Bank Help",
            bio="Customer support",
            verified=False,
            videos=[
                TikTokVideoSnapshot(
                    video_id="v1",
                    description=(
                        "Argus Bank free 100 BTC giveaway! Send 0.1 BTC to "
                        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq, "
                        "urgent, last chance!"
                    ),
                    url="https://www.tiktok.com/@argus_official_xx/video/v1",
                ),
            ],
        ),
        # verified: should not be flagged for impersonation
        "real_argus_tt": _snap(
            "real_argus_tt",
            name="Argus Banking Corp",
            bio="Official.",
            verified=True,
        ),
    }

    async def fake_loader(handle: str):
        return profiles.get(handle)

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        report = await scan_organization(
            s, org_id, load_profile=fake_loader
        )
        await s.commit()

    assert report.handles_scanned == 2
    assert report.fraud_findings_created == 1, report
    assert report.impersonations_created == 1, report

    async with factory() as s:
        impers = (
            await s.execute(
                select(ImpersonationFinding).where(
                    ImpersonationFinding.organization_id == org_id,
                    ImpersonationFinding.platform == SocialPlatform.TIKTOK.value,
                )
            )
        ).scalars().all()
        frauds = (
            await s.execute(
                select(FraudFinding).where(
                    FraudFinding.organization_id == org_id
                )
            )
        ).scalars().all()

    handles = {i.candidate_handle for i in impers}
    assert "argus_official_xx" in handles
    assert "real_argus_tt" not in handles
    assert any("argus" in (f.matched_brand_terms or []) for f in frauds)
