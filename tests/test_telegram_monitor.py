"""Audit B3 — Telegram monitor smoke test.

Injects a fake t.me HTML payload so the test never hits the live web.
The rest of the pipeline (parse → fraud score → impersonation match
→ persist) runs against the real Postgres test stack.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
from sqlalchemy import select

import pytest

from src.models.brand import BrandTerm, BrandTermKind
from src.models.fraud import FraudFinding
from src.models.social import ImpersonationFinding, VipProfile
from src.models.threat import Organization
from src.social.telegram_monitor import scan_organization

pytestmark = pytest.mark.asyncio


_FAKE_HTML = """
<html>
<body>
  <div class="tgme_widget_message_wrap">
    <div class="tgme_widget_message_text">
      Argus is giving away 100 BTC! Send 0.1 BTC to
      bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq and we double it.
      URGENT, last chance, expires today.
    </div>
    <a class="tgme_widget_message_date" href="https://t.me/argus_official_xyz/42"></a>
    <time datetime="2026-04-29T09:00:00+00:00"></time>
  </div>
  <div class="tgme_widget_message_wrap">
    <div class="tgme_widget_message_text">
      Just a normal weather update for Berlin today.
    </div>
    <a class="tgme_widget_message_date" href="https://t.me/argus_official_xyz/43"></a>
    <time datetime="2026-04-29T09:05:00+00:00"></time>
  </div>
</body>
</html>
"""


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


async def _set_org_settings(test_engine, organization_id, settings_dict):
    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        org = await s.get(Organization, organization_id)
        org.settings = settings_dict
        await s.commit()


async def test_telegram_monitor_creates_fraud_and_impersonation(
    test_engine, organization
):
    org_id = organization["id"]
    await _seed_brand_term(test_engine, org_id, BrandTermKind.NAME, "argus")
    await _set_org_settings(
        test_engine,
        org_id,
        {"telegram_monitor_channels": ["argus_official_xyz"]},
    )
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

    async def fake_fetch(http, channel: str):
        assert channel == "argus_official_xyz"
        return _FAKE_HTML

    async with factory() as s:
        report = await scan_organization(
            s, org_id, fetch_html=fake_fetch
        )
        await s.commit()

    assert report.channels_scanned == 1
    assert report.messages_seen == 2
    assert report.fraud_findings_created == 1, report
    assert report.impersonations_created == 1, report

    async with factory() as s:
        frauds = (
            await s.execute(
                select(FraudFinding).where(
                    FraudFinding.organization_id == org_id
                )
            )
        ).scalars().all()
        impers = (
            await s.execute(
                select(ImpersonationFinding).where(
                    ImpersonationFinding.organization_id == org_id
                )
            )
        ).scalars().all()

    assert len(frauds) == 1
    assert frauds[0].matched_brand_terms == ["argus"]
    assert frauds[0].score >= 0.4

    assert len(impers) == 1
    assert impers[0].candidate_handle == "argus_official_xyz"
    assert impers[0].aggregate_score >= 0.75


async def test_telegram_monitor_no_op_without_channels(
    test_engine, organization
):
    """Org with no `telegram_monitor_channels` setting → no-op, no
    findings, no fetch attempts."""
    org_id = organization["id"]
    await _seed_brand_term(test_engine, org_id, BrandTermKind.NAME, "argus")

    fetch_calls = []

    async def fake_fetch(http, channel: str):
        fetch_calls.append(channel)
        return ""

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        report = await scan_organization(
            s, org_id, fetch_html=fake_fetch
        )
        await s.commit()

    assert report.channels_scanned == 0
    assert report.messages_seen == 0
    assert fetch_calls == []
