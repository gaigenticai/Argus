"""Audit B3 — LinkedIn monitor smoke tests.

Inject a fake company-page loader so tests never spin up Selenium
or hit LinkedIn.
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
)
from src.models.threat import Organization
from src.social.linkedin_monitor import (
    LinkedInCompanySnapshot,
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
        org.settings = {"linkedin_monitor_handles": handles}
        await s.commit()


def _snap(handle, *, name=None, headline=None, about=None, industry=None):
    return LinkedInCompanySnapshot(
        handle=handle,
        display_name=name,
        headline=headline,
        about=about,
        industry=industry,
        profile_url=f"https://www.linkedin.com/company/{handle}/",
        raw={},
    )


async def test_linkedin_scan_creates_findings(test_engine, organization):
    org_id = organization["id"]
    await _seed_brand(test_engine, org_id, "argus", BrandTermKind.NAME)
    await _set_handles(test_engine, org_id, ["argus-secure-co"])

    profiles = {
        "argus-secure-co": _snap(
            "argus-secure-co",
            name="Argus Secure Banking",
            headline="The official Argus banking team",
            about=(
                "Argus Bank free 100 BTC giveaway! Send 0.1 BTC to "
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq, urgent!"
            ),
            industry="Financial Services",
        ),
    }

    async def fake_loader(handle: str):
        return profiles.get(handle)

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        # per_company_delay=0 so the test isn't slow
        report = await scan_organization(
            s, org_id, load_company=fake_loader, per_company_delay=0
        )
        await s.commit()

    assert report.handles_scanned == 1
    assert report.impersonations_created == 1, report
    assert report.fraud_findings_created == 1, report

    async with factory() as s:
        impers = (
            await s.execute(
                select(ImpersonationFinding).where(
                    ImpersonationFinding.organization_id == org_id,
                    ImpersonationFinding.platform == SocialPlatform.LINKEDIN.value,
                )
            )
        ).scalars().all()
    assert any(i.candidate_handle == "argus-secure-co" for i in impers)


async def test_linkedin_scan_fail_closed_after_3_empty_loads(
    test_engine, organization
):
    """If the loader returns None for the first 3 handles in a row,
    the scan must abort early with ``fail_closed=True`` rather than
    burn the per-company delay on a clearly-broken run.
    """
    org_id = organization["id"]
    await _seed_brand(test_engine, org_id, "argus", BrandTermKind.NAME)
    await _set_handles(
        test_engine, org_id, ["a", "b", "c", "d", "e"]
    )

    calls = []

    async def fake_loader(handle: str):
        calls.append(handle)
        return None

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        report = await scan_organization(
            s, org_id, load_company=fake_loader, per_company_delay=0
        )

    # Aborted at idx 2 (3rd None in a row), didn't touch d/e.
    assert report.fail_closed is True
    assert len(calls) == 3
    assert "d" not in calls
