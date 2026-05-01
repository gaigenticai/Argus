"""Audit B3 — Instagram monitor smoke tests.

Inject canned profile snapshots so tests don't hit the real
Instagram CDN. Exercises fraud + impersonation paths plus the
verified-account suppression rule.
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
from src.social.instagram_monitor import (
    InstagramProfileSnapshot,
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
        org.settings = {"instagram_monitor_handles": handles}
        await s.commit()


def _snap(handle, *, full_name=None, biography=None, is_verified=False):
    return InstagramProfileSnapshot(
        handle=handle,
        full_name=full_name,
        biography=biography,
        is_verified=is_verified,
        is_private=False,
        profile_url=f"https://www.instagram.com/{handle}/",
        raw={},
    )


async def test_instagram_scan_creates_fraud_and_impersonation(
    test_engine, organization
):
    org_id = organization["id"]
    await _seed_brand(test_engine, org_id, "argus", BrandTermKind.NAME)
    await _set_handles(test_engine, org_id, ["argus_official_2", "real_argus"])

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        s.add(
            VipProfile(
                organization_id=org_id,
                full_name="Argus CEO",
                aliases=["argus_ceo"],
            )
        )
        await s.commit()

    profiles = {
        # Fake-looking: handle starts with the brand, not verified, bio
        # is a textbook crypto-giveaway scam → should fire BOTH fraud
        # and impersonation.
        "argus_official_2": _snap(
            "argus_official_2",
            full_name="Argus Bank Support",
            biography=(
                "Argus Bank free 100 BTC giveaway! Send 0.1 BTC to "
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq and we "
                "double it! Urgent, last chance!"
            ),
        ),
        # Real verified account that happens to look like the brand —
        # impersonation suppression must spare this one.
        "real_argus": _snap(
            "real_argus",
            full_name="Argus Banking Corp",
            biography="Official account of Argus Banking Corp.",
            is_verified=True,
        ),
    }

    def fake_loader(handle: str):
        return profiles.get(handle)

    async with factory() as s:
        report = await scan_organization(
            s, org_id, load_profile=fake_loader
        )
        await s.commit()

    assert report.handles_scanned == 2
    assert report.fraud_findings_created == 1
    assert report.impersonations_created == 1, report

    async with factory() as s:
        impers = (
            await s.execute(
                select(ImpersonationFinding).where(
                    ImpersonationFinding.organization_id == org_id,
                    ImpersonationFinding.platform
                    == SocialPlatform.INSTAGRAM.value,
                )
            )
        ).scalars().all()
    handles = {i.candidate_handle for i in impers}
    assert "argus_official_2" in handles
    # Verified account must be suppressed even though the score would
    # have qualified.
    assert "real_argus" not in handles


async def test_instagram_scan_no_op_without_handles(
    test_engine, organization
):
    org_id = organization["id"]
    await _seed_brand(test_engine, org_id, "argus", BrandTermKind.NAME)

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        report = await scan_organization(s, org_id, load_profile=lambda h: None)

    assert report.handles_scanned == 0
    assert report.fraud_findings_created == 0
    assert report.impersonations_created == 0
