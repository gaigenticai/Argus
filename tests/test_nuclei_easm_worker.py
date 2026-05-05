"""Nuclei EASM worker — fixture tests for the parser + DB persister.

End-to-end tick_once orchestration is covered separately as a Phase C
smoke. Here we pin:

  * ``_categorise(template_id, name)`` — heuristic mapping from
    nuclei template names → ExposureCategory enum values.
  * ``_NUCLEI_SEVERITY_TO_ENUM`` — verbatim severity table.
  * ``_persist_finding(...)`` — real DB session, upsert behaviour,
    re-observation bumps occurrence_count, FIXED→REOPENED transition,
    OPEN-state preservation when an analyst already closed the row.

Realistic nuclei finding shapes come straight from
``nuclei -json -severity medium,high,critical`` output.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select

from src.models.exposures import (
    ExposureCategory,
    ExposureFinding,
    ExposureSource,
    ExposureState,
)
from src.models.common import Severity
from src.workers.maintenance.nuclei_easm import (
    _NUCLEI_SEVERITY_TO_ENUM,
    _categorise,
    _persist_finding,
)

pytestmark = pytest.mark.asyncio


# ── Realistic nuclei -json finding shapes ───────────────────────────


_FINDING_CVE = {
    "template_id": "CVE-2021-41773",
    "name": "Apache HTTP Server 2.4.49 Path Traversal",
    "severity": "critical",
    "url": "https://target.example.com/cgi-bin/test",
    "matched_at": "https://target.example.com/cgi-bin/test",
    "description": "Apache 2.4.49 allows path traversal via crafted URL.",
    "cve_ids": ["CVE-2021-41773"],
    "remediation": "Upgrade to Apache 2.4.51",
}


_FINDING_DEFAULT_CRED = {
    "template_id": "default-credentials-tomcat",
    "name": "Tomcat manager default creds (admin:admin)",
    "severity": "high",
    "url": "https://target.example.com/manager/html",
    "matched_at": "https://target.example.com/manager/html",
    "description": "Tomcat manager exposed with default credentials.",
    "cve_ids": [],
    "remediation": "Disable default credentials or restrict access.",
}


_FINDING_EXPOSED_PANEL = {
    "template_id": "exposed-panels-grafana",
    "name": "Grafana panel exposed to internet",
    "severity": "low",
    "url": "https://target.example.com:3000/login",
    "matched_at": "https://target.example.com:3000/login",
    "description": "Grafana login page reachable.",
    "cve_ids": [],
    "remediation": "",
}


# ── Pure mapping pins ───────────────────────────────────────────────


def test_severity_enum_mapping_pinned():
    """Pin the severity table verbatim — silent drift here means
    every nuclei finding gets the wrong severity bucket."""
    assert _NUCLEI_SEVERITY_TO_ENUM == {
        "info": Severity.LOW.value,
        "low": Severity.LOW.value,
        "medium": Severity.MEDIUM.value,
        "high": Severity.HIGH.value,
        "critical": Severity.CRITICAL.value,
        "unknown": Severity.LOW.value,
    }


def test_categorise_cve_template_id():
    """CVE / RCE / SQLi / XSS templates → vulnerability category."""
    assert _categorise("CVE-2021-41773", "Apache RCE") == ExposureCategory.VULNERABILITY.value
    assert _categorise("apache-rce", "RCE") == ExposureCategory.VULNERABILITY.value
    assert _categorise("blind-sqli-detection", "SQLi") == ExposureCategory.VULNERABILITY.value
    assert _categorise("xxe-detect", "XXE") == ExposureCategory.VULNERABILITY.value
    assert _categorise("ssrf-detect", "SSRF") == ExposureCategory.VULNERABILITY.value
    assert _categorise("xss-reflected", "XSS") == ExposureCategory.VULNERABILITY.value


def test_categorise_default_credentials():
    assert _categorise(
        "default-credentials-tomcat", "Tomcat creds",
    ) == ExposureCategory.DEFAULT_CREDENTIAL.value


def test_categorise_misconfiguration():
    assert _categorise(
        "exposed-config-php", "PHP info exposed",
    ) == ExposureCategory.MISCONFIGURATION.value


def test_categorise_weak_crypto():
    assert _categorise(
        "ssl-weak-cipher", "Weak TLS cipher",
    ) == ExposureCategory.WEAK_CRYPTO.value
    assert _categorise(
        "tls-version-1.0", "Old TLS",
    ) == ExposureCategory.WEAK_CRYPTO.value


def test_categorise_expired_cert():
    assert _categorise(
        "expired-cert-detection", "Expired",
    ) == ExposureCategory.EXPIRED_CERT.value
    assert _categorise(
        "self-signed-cert", "Self-signed",
    ) == ExposureCategory.EXPIRED_CERT.value


def test_categorise_version_disclosure():
    assert _categorise(
        "version-detect-nginx", "nginx 1.18",
    ) == ExposureCategory.VERSION_DISCLOSURE.value
    assert _categorise(
        "tech-detect-wordpress", "WordPress",
    ) == ExposureCategory.VERSION_DISCLOSURE.value


def test_categorise_information_disclosure():
    assert _categorise(
        "phpinfo-detect", "phpinfo()",
    ) == ExposureCategory.INFORMATION_DISCLOSURE.value


def test_categorise_exposed_service():
    assert _categorise(
        "exposed-panels-grafana", "Grafana panel",
    ) == ExposureCategory.EXPOSED_SERVICE.value


def test_categorise_unknown_falls_back_to_other():
    assert _categorise(
        "totally-mysterious-template", "Unknown",
    ) == ExposureCategory.OTHER.value


# ── _persist_finding (real DB session) ─────────────────────────────


@pytest_asyncio.fixture(loop_scope="session")
async def fresh_org(session):
    """Insert a fresh Organization for this test; the savepoint
    rollback at session teardown reverts it."""
    from src.models.threat import Organization

    org = Organization(
        name=f"Nuclei Test Org {uuid.uuid4().hex[:8]}",
        domains=["nuclei-test.example"],
        keywords=["nuclei"],
        industry="finance",
    )
    session.add(org)
    await session.flush()
    return org


async def test_persist_finding_creates_new_row(session, fresh_org):
    now = datetime.now(timezone.utc)
    await _persist_finding(
        session,
        organization_id=fresh_org.id,
        asset_id=None,
        finding=_FINDING_CVE,
        now=now,
    )
    await session.flush()

    row = (await session.execute(
        select(ExposureFinding)
        .where(ExposureFinding.organization_id == fresh_org.id)
    )).scalar_one()

    assert row.severity == Severity.CRITICAL.value
    assert row.category == ExposureCategory.VULNERABILITY.value
    assert row.source == ExposureSource.NUCLEI.value
    assert row.state == ExposureState.OPEN.value
    assert row.rule_id == "CVE-2021-41773"
    assert row.title == "Apache HTTP Server 2.4.49 Path Traversal"
    assert row.cve_ids == ["CVE-2021-41773"]
    assert row.occurrence_count == 1
    assert row.matched_at == now
    assert row.last_seen_at == now


async def test_persist_finding_re_observation_bumps_count(session, fresh_org):
    """Same (org, rule_id, target) seen twice — second call must bump
    occurrence_count and update last_seen_at, NOT create a duplicate."""
    t1 = datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 5, 1, 16, 0, 0, tzinfo=timezone.utc)

    await _persist_finding(session, organization_id=fresh_org.id,
                           asset_id=None, finding=_FINDING_CVE, now=t1)
    await session.flush()
    await _persist_finding(session, organization_id=fresh_org.id,
                           asset_id=None, finding=_FINDING_CVE, now=t2)
    await session.flush()

    rows = (await session.execute(
        select(ExposureFinding)
        .where(ExposureFinding.organization_id == fresh_org.id)
    )).scalars().all()

    assert len(rows) == 1  # NOT duplicated
    row = rows[0]
    assert row.occurrence_count == 2
    assert row.last_seen_at == t2
    assert row.matched_at == t1  # original first-seen preserved


async def test_persist_finding_fixed_state_flips_to_reopened(session, fresh_org):
    """If the finding had state=FIXED (analyst closed it) and we see
    the same template+target again, state must flip to REOPENED, not
    silently bump occurrence_count on a closed row."""
    now = datetime.now(timezone.utc)
    # Insert a pre-FIXED finding
    pre = ExposureFinding(
        organization_id=fresh_org.id,
        severity=Severity.HIGH.value,
        category=ExposureCategory.VULNERABILITY.value,
        state=ExposureState.FIXED.value,
        source=ExposureSource.NUCLEI.value,
        rule_id="CVE-2021-41773",
        title="Old finding",
        target="https://target.example.com/cgi-bin/test",
        matched_at=now,
        last_seen_at=now,
        occurrence_count=3,
        cve_ids=[],
        cwe_ids=[],
        references=[],
    )
    session.add(pre)
    await session.flush()

    # Re-observe
    await _persist_finding(session, organization_id=fresh_org.id,
                           asset_id=None, finding=_FINDING_CVE, now=now)
    await session.flush()

    refreshed = (await session.execute(
        select(ExposureFinding).where(ExposureFinding.id == pre.id)
    )).scalar_one()
    assert refreshed.state == ExposureState.REOPENED.value
    assert refreshed.occurrence_count == 4


async def test_persist_finding_accepted_risk_state_preserved(session, fresh_org):
    """If the finding had state=ACCEPTED_RISK (analyst said 'we know'),
    re-observation must NOT reset to OPEN — only FIXED transitions
    to REOPENED. ACCEPTED_RISK / FALSE_POSITIVE stick."""
    now = datetime.now(timezone.utc)
    pre = ExposureFinding(
        organization_id=fresh_org.id,
        severity=Severity.HIGH.value,
        category=ExposureCategory.VULNERABILITY.value,
        state=ExposureState.ACCEPTED_RISK.value,
        source=ExposureSource.NUCLEI.value,
        rule_id="CVE-2021-41773",
        title="Old finding",
        target="https://target.example.com/cgi-bin/test",
        matched_at=now,
        last_seen_at=now,
        occurrence_count=2,
        cve_ids=[],
        cwe_ids=[],
        references=[],
    )
    session.add(pre)
    await session.flush()

    await _persist_finding(session, organization_id=fresh_org.id,
                           asset_id=None, finding=_FINDING_CVE, now=now)
    await session.flush()

    refreshed = (await session.execute(
        select(ExposureFinding).where(ExposureFinding.id == pre.id)
    )).scalar_one()
    # Analyst's call sticks — no FIXED→REOPENED transition triggered.
    assert refreshed.state == ExposureState.ACCEPTED_RISK.value
    assert refreshed.occurrence_count == 3


async def test_persist_finding_skips_finding_with_no_target(session, fresh_org):
    """Defensive — nuclei occasionally emits incomplete rows with no
    URL. Skip silently, don't crash."""
    bad = {**_FINDING_CVE, "url": "", "matched_at": ""}
    await _persist_finding(session, organization_id=fresh_org.id,
                           asset_id=None, finding=bad, now=datetime.now(timezone.utc))
    await session.flush()
    rows = (await session.execute(
        select(ExposureFinding).where(ExposureFinding.organization_id == fresh_org.id)
    )).scalars().all()
    assert rows == []


async def test_persist_finding_default_credential(session, fresh_org):
    await _persist_finding(session, organization_id=fresh_org.id,
                           asset_id=None, finding=_FINDING_DEFAULT_CRED,
                           now=datetime.now(timezone.utc))
    await session.flush()
    row = (await session.execute(
        select(ExposureFinding).where(ExposureFinding.organization_id == fresh_org.id)
    )).scalar_one()
    assert row.category == ExposureCategory.DEFAULT_CREDENTIAL.value
    assert row.severity == Severity.HIGH.value


async def test_persist_finding_exposed_panel(session, fresh_org):
    await _persist_finding(session, organization_id=fresh_org.id,
                           asset_id=None, finding=_FINDING_EXPOSED_PANEL,
                           now=datetime.now(timezone.utc))
    await session.flush()
    row = (await session.execute(
        select(ExposureFinding).where(ExposureFinding.organization_id == fresh_org.id)
    )).scalar_one()
    assert row.category == ExposureCategory.EXPOSED_SERVICE.value
    assert row.severity == Severity.LOW.value
