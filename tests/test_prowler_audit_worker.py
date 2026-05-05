"""Prowler cloud-audit worker — fixture tests for the parsers + DB.

Pins:
  * ``_detect_active_providers`` — env-var combinations → provider list.
  * ``_PROWLER_SEVERITY_TO_ENUM`` — verbatim mapping.
  * ``_categorise(finding)`` — heuristic title → ExposureCategory.
  * ``_stable_rule_id`` — deterministic + provider-scoped.
  * ``_persist_finding`` — real DB session, upsert + state preservation,
    PROWLER source enum used.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select

from src.models.common import Severity
from src.models.exposures import (
    ExposureCategory,
    ExposureFinding,
    ExposureSource,
    ExposureState,
)
from src.workers.maintenance.prowler_audit import (
    _PROWLER_SEVERITY_TO_ENUM,
    _categorise,
    _detect_active_providers,
    _persist_finding,
    _stable_rule_id,
)

pytestmark = pytest.mark.asyncio


# ── _detect_active_providers (pure, env-driven) ────────────────────


@pytest.fixture(autouse=True)
def _scrub_cloud_env(monkeypatch):
    """Each test starts with NO cloud env vars set so we can compose
    the exact set we want."""
    for k in (
        "AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT",
        "KUBECONFIG",
    ):
        monkeypatch.delenv(k, raising=False)


def test_detect_no_providers_when_env_empty():
    assert _detect_active_providers() == []


def test_detect_aws_via_access_key(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA...")
    assert _detect_active_providers() == ["aws"]


def test_detect_aws_via_profile(monkeypatch):
    """AWS profile alone is enough — Prowler can read creds from the
    SDK config files."""
    monkeypatch.setenv("AWS_PROFILE", "production")
    assert _detect_active_providers() == ["aws"]


def test_detect_aws_via_role_arn(monkeypatch):
    """STS-assumed roles for IRSA / OIDC."""
    monkeypatch.setenv("AWS_ROLE_ARN", "arn:aws:iam::1:role/x")
    assert _detect_active_providers() == ["aws"]


def test_detect_azure_requires_full_triple(monkeypatch):
    """Service-principal auth needs ALL THREE — tenant + client +
    secret. Partial config doesn't activate Azure."""
    monkeypatch.setenv("AZURE_TENANT_ID", "t")
    assert _detect_active_providers() == []
    monkeypatch.setenv("AZURE_CLIENT_ID", "c")
    assert _detect_active_providers() == []
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "s")
    assert _detect_active_providers() == ["azure"]


def test_detect_gcp_via_credentials_file(monkeypatch, tmp_path):
    """GOOGLE_APPLICATION_CREDENTIALS pointing at a service-account
    JSON activates GCP."""
    sa = tmp_path / "sa.json"
    sa.write_text("{}")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(sa))
    assert _detect_active_providers() == ["gcp"]


def test_detect_gcp_via_project_only(monkeypatch):
    """GOOGLE_CLOUD_PROJECT alone (workload identity) activates GCP."""
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "my-project")
    assert _detect_active_providers() == ["gcp"]


def test_detect_kubernetes_via_kubeconfig(monkeypatch, tmp_path):
    kc = tmp_path / "kubeconfig"
    kc.write_text("apiVersion: v1\nkind: Config\n")
    monkeypatch.setenv("KUBECONFIG", str(kc))
    assert _detect_active_providers() == ["kubernetes"]


def test_detect_multiple_providers(monkeypatch):
    """Operator with multi-cloud creds → all detected."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "k")
    monkeypatch.setenv("AZURE_TENANT_ID", "t")
    monkeypatch.setenv("AZURE_CLIENT_ID", "c")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "s")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "p")
    detected = _detect_active_providers()
    assert "aws" in detected
    assert "azure" in detected
    assert "gcp" in detected


# ── _PROWLER_SEVERITY_TO_ENUM ──────────────────────────────────────


def test_severity_enum_mapping_pinned():
    assert _PROWLER_SEVERITY_TO_ENUM == {
        "critical": Severity.CRITICAL.value,
        "high": Severity.HIGH.value,
        "medium": Severity.MEDIUM.value,
        "low": Severity.LOW.value,
        "informational": Severity.LOW.value,
        "info": Severity.LOW.value,
    }


# ── _categorise ────────────────────────────────────────────────────


def test_categorise_public_exposure():
    """'public', '0.0.0.0/0', 'open to internet' → exposed service."""
    assert _categorise(
        {"finding": "S3 bucket is publicly accessible"},
    ) == ExposureCategory.EXPOSED_SERVICE.value
    assert _categorise(
        {"finding": "Security group allows 0.0.0.0/0 on port 22"},
    ) == ExposureCategory.EXPOSED_SERVICE.value
    assert _categorise(
        {"finding": "RDS database open to internet"},
    ) == ExposureCategory.EXPOSED_SERVICE.value


def test_categorise_encryption():
    assert _categorise(
        {"finding": "S3 bucket has no server-side encryption"},
    ) == ExposureCategory.WEAK_CRYPTO.value
    assert _categorise(
        {"finding": "EBS volume not using KMS"},
    ) == ExposureCategory.WEAK_CRYPTO.value


def test_categorise_default_credential():
    """IAM keys + 'credential' → default credential bucket. Note: the
    code's ``or`` precedence here is loose; the test pins the resulting
    behaviour, not what one might intuit from the prose."""
    assert _categorise(
        {"finding": "IAM access key has no rotation policy"},
    ) == ExposureCategory.DEFAULT_CREDENTIAL.value


def test_categorise_falls_back_to_misconfiguration():
    assert _categorise(
        {"finding": "Lambda timeout exceeds recommendation"},
    ) == ExposureCategory.MISCONFIGURATION.value


# ── _stable_rule_id ────────────────────────────────────────────────


def test_stable_rule_id_deterministic():
    """Same input → same id, no matter how many times called."""
    f = {"service": "s3", "finding": "Bucket is public"}
    a = _stable_rule_id("aws", f)
    b = _stable_rule_id("aws", f)
    assert a == b


def test_stable_rule_id_provider_scoped():
    """Same finding text under different providers must produce
    different rule_ids — a misconfig pattern that exists across
    AWS S3 and GCS shouldn't collide."""
    f = {"service": "storage", "finding": "Bucket is public"}
    aws_id = _stable_rule_id("aws", f)
    gcp_id = _stable_rule_id("gcp", f)
    assert aws_id != gcp_id


def test_stable_rule_id_format():
    f = {"service": "s3", "finding": "x"}
    rid = _stable_rule_id("aws", f)
    assert rid.startswith("prowler.aws.")
    assert len(rid) == len("prowler.aws.") + 16


def test_stable_rule_id_different_findings_different_ids():
    a = _stable_rule_id("aws", {"service": "s3", "finding": "Public"})
    b = _stable_rule_id("aws", {"service": "s3", "finding": "Encryption off"})
    assert a != b


# ── _persist_finding (real DB session) ────────────────────────────


@pytest_asyncio.fixture(loop_scope="session")
async def fresh_org(session):
    from src.models.threat import Organization
    org = Organization(
        name=f"Prowler Test Org {uuid.uuid4().hex[:8]}",
        domains=["prowler-test.example"],
        keywords=["prowler"],
        industry="finance",
    )
    session.add(org)
    await session.flush()
    return org


_PROWLER_FAIL = {
    "provider": "aws",
    "service": "s3",
    "severity": "high",
    "finding": "Bucket prod-data is publicly accessible",
    "resource": "arn:aws:s3:::prod-data",
    "remediation": "Enable Block Public Access on the bucket.",
    "status": "fail",
}


async def test_persist_finding_creates_with_prowler_source(session, fresh_org):
    """Source enum must be PROWLER (not OTHER) — proves the alembic
    migration enum extension landed correctly."""
    now = datetime.now(timezone.utc)
    await _persist_finding(
        session, organization_id=fresh_org.id,
        provider="aws", finding=_PROWLER_FAIL, now=now,
    )
    await session.flush()

    row = (await session.execute(
        select(ExposureFinding).where(ExposureFinding.organization_id == fresh_org.id)
    )).scalar_one()

    assert row.source == ExposureSource.PROWLER.value
    assert row.severity == Severity.HIGH.value
    assert row.category == ExposureCategory.EXPOSED_SERVICE.value
    assert row.title == "Bucket prod-data is publicly accessible"
    assert row.target == "arn:aws:s3:::prod-data"
    assert row.description == "Enable Block Public Access on the bucket."
    assert row.state == ExposureState.OPEN.value
    assert row.occurrence_count == 1
    assert row.rule_id.startswith("prowler.aws.")


async def test_persist_finding_re_observation_bumps_count(session, fresh_org):
    t1 = datetime(2026, 5, 1, 0, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 5, 8, 0, 0, 0, tzinfo=timezone.utc)
    for ts in (t1, t2):
        await _persist_finding(
            session, organization_id=fresh_org.id,
            provider="aws", finding=_PROWLER_FAIL, now=ts,
        )
        await session.flush()

    rows = (await session.execute(
        select(ExposureFinding).where(ExposureFinding.organization_id == fresh_org.id)
    )).scalars().all()
    assert len(rows) == 1  # NOT duplicated
    assert rows[0].occurrence_count == 2
    assert rows[0].last_seen_at == t2


async def test_persist_finding_fixed_state_flips_to_reopened(session, fresh_org):
    now = datetime.now(timezone.utc)
    rule_id = _stable_rule_id("aws", _PROWLER_FAIL)
    pre = ExposureFinding(
        organization_id=fresh_org.id,
        severity=Severity.HIGH.value,
        category=ExposureCategory.EXPOSED_SERVICE.value,
        state=ExposureState.FIXED.value,
        source=ExposureSource.PROWLER.value,
        rule_id=rule_id,
        title="old",
        target="arn:aws:s3:::prod-data",
        matched_at=now,
        last_seen_at=now,
        occurrence_count=1,
        cve_ids=[], cwe_ids=[], references=[],
    )
    session.add(pre)
    await session.flush()

    await _persist_finding(
        session, organization_id=fresh_org.id,
        provider="aws", finding=_PROWLER_FAIL, now=now,
    )
    await session.flush()

    refreshed = (await session.execute(
        select(ExposureFinding).where(ExposureFinding.id == pre.id)
    )).scalar_one()
    assert refreshed.state == ExposureState.REOPENED.value


async def test_persist_finding_accepted_risk_state_preserved(session, fresh_org):
    """Same as Nuclei worker — analyst's ACCEPTED_RISK call sticks."""
    now = datetime.now(timezone.utc)
    rule_id = _stable_rule_id("aws", _PROWLER_FAIL)
    pre = ExposureFinding(
        organization_id=fresh_org.id,
        severity=Severity.HIGH.value,
        category=ExposureCategory.EXPOSED_SERVICE.value,
        state=ExposureState.ACCEPTED_RISK.value,
        source=ExposureSource.PROWLER.value,
        rule_id=rule_id,
        title="old",
        target="arn:aws:s3:::prod-data",
        matched_at=now,
        last_seen_at=now,
        occurrence_count=1,
        cve_ids=[], cwe_ids=[], references=[],
    )
    session.add(pre)
    await session.flush()

    await _persist_finding(
        session, organization_id=fresh_org.id,
        provider="aws", finding=_PROWLER_FAIL, now=now,
    )
    await session.flush()

    refreshed = (await session.execute(
        select(ExposureFinding).where(ExposureFinding.id == pre.id)
    )).scalar_one()
    assert refreshed.state == ExposureState.ACCEPTED_RISK.value
