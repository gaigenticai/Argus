"""Audit B3 — Twitter/X monitor smoke tests.

Inject async fake loaders so tests never call into Scweet / never
need authenticated X sessions.
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
from src.social.twitter_monitor import (
    TweetSnapshot,
    TwitterProfileSnapshot,
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
        org.settings = {"twitter_monitor_handles": handles}
        await s.commit()


def _snap(handle, *, name=None, bio=None, verified=False, tweets=()):
    return TwitterProfileSnapshot(
        handle=handle,
        display_name=name,
        biography=bio,
        is_verified=verified,
        profile_url=f"https://twitter.com/{handle}",
        tweets=list(tweets),
        raw={},
    )


async def test_twitter_scan_creates_findings(test_engine, organization):
    org_id = organization["id"]
    await _seed_brand(test_engine, org_id, "argus", BrandTermKind.NAME)
    await _set_handles(
        test_engine, org_id, ["argus_official_yy", "real_argus_x"]
    )

    profiles = {
        "argus_official_yy": _snap(
            "argus_official_yy",
            name="Argus Bank Official",
            bio="Customer help",
            verified=False,
            tweets=[
                TweetSnapshot(
                    tweet_id="t1",
                    text=(
                        "Argus Bank free 100 BTC giveaway! Send 0.1 BTC to "
                        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq "
                        "and we double it! Urgent, last chance!"
                    ),
                    url="https://twitter.com/argus_official_yy/status/t1",
                ),
            ],
        ),
        "real_argus_x": _snap(
            "real_argus_x",
            name="Argus Banking Corp",
            bio="Verified.",
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
    assert report.fraud_findings_created >= 1
    assert report.impersonations_created == 1, report

    async with factory() as s:
        impers = (
            await s.execute(
                select(ImpersonationFinding).where(
                    ImpersonationFinding.organization_id == org_id,
                    ImpersonationFinding.platform == SocialPlatform.TWITTER.value,
                )
            )
        ).scalars().all()
    handles = {i.candidate_handle for i in impers}
    assert "argus_official_yy" in handles
    assert "real_argus_x" not in handles


async def test_twitter_scan_no_op_without_session_dir(
    test_engine, organization, monkeypatch
):
    """If the operator hasn't configured Scweet sessions, the default
    loader returns None for every handle and the scan reports zero
    findings (instead of crashing or silently emitting empty data)."""
    org_id = organization["id"]
    await _seed_brand(test_engine, org_id, "argus", BrandTermKind.NAME)
    await _set_handles(test_engine, org_id, ["arguss_x"])
    monkeypatch.delenv("ARGUS_TWITTER_SESSION_DIR", raising=False)

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        # Don't pass load_profile — exercise the production default.
        report = await scan_organization(s, org_id)

    assert report.handles_scanned == 1
    assert report.fraud_findings_created == 0
    assert report.impersonations_created == 0
