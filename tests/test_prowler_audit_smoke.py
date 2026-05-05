"""Prowler audit worker — first-ingest smoke test.

Mocks ProwlerRunner to skip the actual Prowler subprocess, sets
AWS env vars to activate the AWS provider path, calls
``prowler_audit.tick_once()`` once, then asserts:

  * ExposureFinding row(s) for status='fail' findings landed
  * source enum is PROWLER (proves the alembic migration applied)
  * feed_health 'maintenance.prowler_audit' = ok with detail mentioning aws
  * Re-running the same finding bumps occurrence_count, doesn't dup
  * No cloud creds detected → feed_health = unconfigured
  * Prowler binary missing → feed_health = disabled
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from src.models.admin import FeedHealth
from src.models.exposures import ExposureFinding, ExposureSource
from src.workers.maintenance import prowler_audit
from src.workers.maintenance.prowler_audit import FEED_NAME

pytestmark = pytest.mark.asyncio


_FAIL_FINDING = {
    "provider": "aws",
    "service": "s3",
    "severity": "high",
    "finding": "Bucket prod-data is publicly accessible",
    "resource": "arn:aws:s3:::prod-data",
    "remediation": "Enable Block Public Access.",
    "status": "fail",
}


_PASS_FINDING = {
    "provider": "aws",
    "service": "iam",
    "severity": "low",
    "finding": "Root MFA enabled",
    "resource": "AWS::IAM::Account",
    "status": "pass",  # passes are filtered out
}


class _StubRunner:
    """Mock ProwlerRunner that returns one fail + one pass per scan."""

    async def check_installed(self):
        return True

    async def run_scan(self, provider="aws", checks=None, *, timeout=None):
        return [_FAIL_FINDING, _PASS_FINDING]


@pytest_asyncio.fixture(loop_scope="session")
async def system_org_id(test_engine):
    """Resolve (or first-provision) the system org — see comment in
    test_suricata_tail_smoke.py for the SystemOrganizationMissing
    rationale."""
    from src.core.tenant import (
        SystemOrganizationMissing,
        get_system_org_id,
    )
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        try:
            return await get_system_org_id(s)
        except SystemOrganizationMissing:
            from src.models.threat import Organization
            org = Organization(
                name="argus-system",
                domains=["system.argus.local"],
                keywords=["system"],
                industry="security",
            )
            s.add(org)
            await s.commit()
            await s.refresh(org)
            return org.id


@pytest_asyncio.fixture(autouse=True)
def _scrub_cloud_env(monkeypatch):
    """Each test starts with NO cloud env vars set."""
    for k in (
        "AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT",
        "KUBECONFIG",
    ):
        monkeypatch.delenv(k, raising=False)


async def _wipe_prowler_findings(test_engine, org_id):
    """Clean up after each test so subsequent runs don't see leftover
    rows when asserting counts."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        await s.execute(delete(ExposureFinding).where(
            ExposureFinding.organization_id == org_id,
            ExposureFinding.source == ExposureSource.PROWLER.value,
        ))
        await s.commit()


async def test_tick_once_persists_fail_finding(test_engine, system_org_id, monkeypatch):
    """Happy path: AWS creds present + scanner returns 1 fail + 1 pass
    → 1 ExposureFinding row with PROWLER source + feed_health ok."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")

    try:
        with patch.object(prowler_audit, "ProwlerRunner", _StubRunner):
            await prowler_audit.tick_once()

        from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
        factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as s:
            rows = (await s.execute(
                select(ExposureFinding).where(
                    ExposureFinding.organization_id == system_org_id,
                    ExposureFinding.source == ExposureSource.PROWLER.value,
                )
            )).scalars().all()
            assert len(rows) == 1, (
                f"expected 1 fail finding (the pass should be filtered); got {len(rows)}"
            )
            row = rows[0]
            assert row.target == "arn:aws:s3:::prod-data"
            assert row.severity == "high"
            assert row.rule_id.startswith("prowler.aws.")
            assert row.occurrence_count == 1

            health = (await s.execute(
                select(FeedHealth)
                .where(FeedHealth.feed_name == FEED_NAME)
                .order_by(FeedHealth.observed_at.desc())
                .limit(1)
            )).scalar_one_or_none()
            assert health is not None
            assert health.status == "ok"
            assert "providers=aws" in (health.detail or "")
            assert "findings=1" in (health.detail or "")
    finally:
        await _wipe_prowler_findings(test_engine, system_org_id)


async def test_tick_once_idempotent_re_observation(test_engine, system_org_id, monkeypatch):
    """Two ticks of the same finding → 1 row with occurrence_count=2."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")

    try:
        with patch.object(prowler_audit, "ProwlerRunner", _StubRunner):
            await prowler_audit.tick_once()
            await prowler_audit.tick_once()

        from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
        factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as s:
            rows = (await s.execute(
                select(ExposureFinding).where(
                    ExposureFinding.organization_id == system_org_id,
                    ExposureFinding.source == ExposureSource.PROWLER.value,
                )
            )).scalars().all()
            assert len(rows) == 1
            assert rows[0].occurrence_count == 2
    finally:
        await _wipe_prowler_findings(test_engine, system_org_id)


async def test_tick_once_unconfigured_when_no_cloud_creds(test_engine, monkeypatch):
    """No AWS_*, AZURE_*, GCP, or KUBECONFIG → unconfigured + no scan
    attempted (the runner.check_installed is short-circuited too)."""

    class _NeverRuns(_StubRunner):
        async def run_scan(self, *args, **kwargs):
            raise AssertionError("scan must NOT run when no creds detected")

    with patch.object(prowler_audit, "ProwlerRunner", _NeverRuns):
        await prowler_audit.tick_once()

    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        health = (await s.execute(
            select(FeedHealth)
            .where(FeedHealth.feed_name == FEED_NAME)
            .order_by(FeedHealth.observed_at.desc())
            .limit(1)
        )).scalar_one_or_none()
        assert health is not None
        assert health.status == "unconfigured"
        assert "no cloud creds" in (health.detail or "").lower()


async def test_tick_once_disabled_when_binary_missing(test_engine, monkeypatch):
    """Prowler binary not installed → status=disabled, no scan attempt."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "x")  # creds are fine
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "y")

    class _MissingBinary(_StubRunner):
        async def check_installed(self):
            return False

        async def run_scan(self, *args, **kwargs):
            raise AssertionError("scan must NOT run when binary missing")

    with patch.object(prowler_audit, "ProwlerRunner", _MissingBinary):
        await prowler_audit.tick_once()

    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
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
