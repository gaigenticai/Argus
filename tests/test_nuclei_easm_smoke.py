"""Nuclei EASM worker — first-ingest smoke test.

Boots a real test DB, mocks ``NucleiScanner`` to return a fixed
finding, calls ``nuclei_easm.tick_once()`` once, then asserts:

  * a ``feed_health`` row for ``maintenance.nuclei_easm`` was written
    with status='ok' (NOT 'disabled' / 'failure')
  * an ``ExposureFinding`` row landed in the database
  * the org's asset's ``last_scanned_at`` was bumped

This is the kind of trace the audit caught last time when the
adapters were silently orphaned. If this test starts failing in CI,
the worker is no longer wired correctly to the production code path.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlalchemy import select

from src.models.admin import FeedHealth
from src.models.exposures import ExposureFinding, ExposureSource
from src.models.threat import Asset, Organization
from src.workers.maintenance import nuclei_easm
from src.workers.maintenance.nuclei_easm import FEED_NAME

pytestmark = pytest.mark.asyncio


_FAKE_NUCLEI_FINDING = {
    "template_id": "CVE-2021-41773",
    "name": "Apache Path Traversal",
    "severity": "critical",
    "url": "https://target.example.com/cgi-bin/test",
    "matched_at": "https://target.example.com/cgi-bin/test",
    "description": "Apache 2.4.49 path traversal",
    "cve_ids": ["CVE-2021-41773"],
    "remediation": "Upgrade to 2.4.51",
}


class _StubScanner:
    """Returns a fixed finding for every target — proves the worker's
    DB-write path runs end-to-end without needing a real nuclei
    binary in the test environment."""

    async def check_installed(self):
        return True

    async def scan_target(self, target, severity=None, timeout=None):
        return [_FAKE_NUCLEI_FINDING]


@pytest_asyncio.fixture(loop_scope="session")
async def org_with_asset(test_engine):
    """Standalone org + 1 monitored asset. Lifecycle: created here,
    cleaned up explicitly after the test (we can't rely on session
    rollback because ``tick_once`` opens its own session via
    ``async_session_factory``)."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False,
    )
    async with factory() as s:
        org = Organization(
            name=f"NucleiSmoke-{uuid.uuid4().hex[:8]}",
            domains=["nuclei-smoke.example"],
            keywords=["nuclei-smoke"],
            industry="finance",
        )
        s.add(org)
        await s.flush()

        asset = Asset(
            organization_id=org.id,
            asset_type="domain",
            value="nuclei-smoke.example",
            criticality="medium",
            tags=[],
            discovery_method="manual",
            is_active=True,
            monitoring_enabled=True,
        )
        s.add(asset)
        await s.commit()
        await s.refresh(org)
        await s.refresh(asset)

    yield {"org_id": org.id, "asset_id": asset.id}

    # Teardown — wipe the rows tick_once persisted under this org.
    async with factory() as s:
        from sqlalchemy import delete
        await s.execute(delete(ExposureFinding).where(
            ExposureFinding.organization_id == org.id,
        ))
        await s.execute(delete(Asset).where(Asset.organization_id == org.id))
        await s.execute(delete(Organization).where(Organization.id == org.id))
        await s.commit()


async def test_tick_once_persists_finding_and_health(test_engine, org_with_asset):
    """End-to-end: one tick mocks the scanner → ExposureFinding row +
    feed_health row land in the DB."""
    org_id = org_with_asset["org_id"]
    asset_id = org_with_asset["asset_id"]

    # Wire the worker to the test session factory. tick_once() reads
    # ``_db.async_session_factory`` directly — we already set it via
    # the test_engine fixture in conftest.

    with patch.object(nuclei_easm, "NucleiScanner", _StubScanner):
        await nuclei_easm.tick_once()

    # Fresh session to inspect the after-state.
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False,
    )

    async with factory() as s:
        # 1. ExposureFinding row created with the right shape.
        rows = (await s.execute(
            select(ExposureFinding).where(
                ExposureFinding.organization_id == org_id,
            )
        )).scalars().all()
        assert len(rows) == 1, (
            "expected exactly one ExposureFinding; "
            f"got {len(rows)} — tick_once may have skipped persistence"
        )
        finding = rows[0]
        assert finding.source == ExposureSource.NUCLEI.value
        assert finding.rule_id == "CVE-2021-41773"
        assert finding.severity == "critical"
        assert finding.cve_ids == ["CVE-2021-41773"]
        assert finding.asset_id == asset_id

        # 2. Asset.last_scanned_at bumped.
        refreshed_asset = (await s.execute(
            select(Asset).where(Asset.id == asset_id)
        )).scalar_one()
        assert refreshed_asset.last_scanned_at is not None, (
            "tick_once should set last_scanned_at on every visited asset"
        )

        # 3. feed_health row written with status='ok'.
        health = (await s.execute(
            select(FeedHealth)
            .where(FeedHealth.feed_name == FEED_NAME)
            .order_by(FeedHealth.observed_at.desc())
            .limit(1)
        )).scalar_one_or_none()
        assert health is not None, (
            f"no feed_health row for {FEED_NAME!r} after tick_once"
        )
        assert health.status == "ok", (
            f"expected status=ok, got status={health.status!r}; "
            f"detail={health.detail!r}"
        )
        # Detail must reflect what happened (≥1 finding ingested)
        assert "findings=1" in (health.detail or "")


async def test_tick_once_marks_disabled_when_binary_missing(test_engine):
    """If the nuclei binary isn't installed, tick_once must short-
    circuit with a feed_health 'disabled' marker — not crash, not
    silently no-op."""

    class _MissingBinaryScanner:
        async def check_installed(self):
            return False

        async def scan_target(self, *args, **kwargs):
            raise AssertionError("scan_target must NOT be called when binary missing")

    with patch.object(nuclei_easm, "NucleiScanner", _MissingBinaryScanner):
        await nuclei_easm.tick_once()

    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False,
    )
    async with factory() as s:
        health = (await s.execute(
            select(FeedHealth)
            .where(FeedHealth.feed_name == FEED_NAME)
            .order_by(FeedHealth.observed_at.desc())
            .limit(1)
        )).scalar_one_or_none()
        assert health is not None
        assert health.status == "disabled"
        assert "binary not detected" in (health.detail or "").lower()
