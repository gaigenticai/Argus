"""Compliance Evidence Pack — integration tests (P1 #1.3).

Hits a real Postgres test database (per-session conftest harness) — no
DB mocks. Each test seeds the catalog, exercises one path, and rolls
back via the savepoint fixture.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.compliance.catalog import (
    CONTROLS,
    FRAMEWORKS,
    MAPPINGS,
    seed_compliance_catalog,
)
from src.compliance.mapper import collect_evidence_for_period
from src.compliance.oscal import build_assessment_results, serialise as serialise_oscal
from src.compliance.pdf_exporter import render_evidence_pack_pdf
from src.models.compliance import (
    ComplianceControl,
    ComplianceControlMapping,
    ComplianceEvidence,
    ComplianceFramework,
)
from src.models.threat import Alert, Organization

pytestmark = pytest.mark.asyncio


# --- Catalog ----------------------------------------------------------


async def test_seed_catalogs_idempotent(session: AsyncSession):
    """Re-running the seeder yields no duplicate rows."""
    counts1 = await seed_compliance_catalog(session)
    await session.commit()

    counts2 = await seed_compliance_catalog(session)
    await session.commit()

    assert counts1["frameworks"] == len(FRAMEWORKS)
    assert counts1["controls"] == len(CONTROLS)
    assert counts2["frameworks"] == 0
    assert counts2["controls"] == 0
    assert counts2["mappings"] == 0

    # Sanity: every framework code is present, no dupes.
    fw_codes = (await session.execute(
        select(ComplianceFramework.code)
    )).scalars().all()
    assert sorted(fw_codes) == sorted({fw["code"] for fw in FRAMEWORKS})

    # Sanity: every mapping references an existing control.
    orphan_mappings = (await session.execute(
        select(func.count(ComplianceControlMapping.id))
        .outerjoin(
            ComplianceControl,
            ComplianceControl.id == ComplianceControlMapping.control_id,
        )
        .where(ComplianceControl.id.is_(None))
    )).scalar_one()
    assert orphan_mappings == 0


# --- Mapper ------------------------------------------------------------


async def test_evidence_collection_tenant_isolation(
    session: AsyncSession, organization, second_organization
):
    """Evidence for org A must not include alerts from org B."""
    await seed_compliance_catalog(session)
    await session.commit()

    org_a = organization["id"]
    org_b = second_organization["id"]
    now = datetime.now(timezone.utc)

    # Insert one phishing alert in each org.
    session.add(Alert(
        organization_id=org_a, category="phishing", severity="high",
        title="A — phishing", summary="org A phishing",
    ))
    session.add(Alert(
        organization_id=org_b, category="phishing", severity="high",
        title="B — phishing", summary="org B phishing",
    ))
    await session.flush()

    counts = await collect_evidence_for_period(
        session,
        organization_id=org_a,
        framework_code="NCA-ECC-V2",
        period_from=now - timedelta(days=1),
        period_to=now + timedelta(hours=1),
    )
    await session.flush()

    assert counts["alerts_seen"] == 1, counts
    # Every evidence row produced for this run targets org_a only.
    rows = (await session.execute(
        select(ComplianceEvidence.organization_id, ComplianceEvidence.source_id)
    )).all()
    org_ids = {r[0] for r in rows}
    assert org_ids == {org_a}, (
        f"tenant isolation breach — found rows for {org_ids - {org_a}}"
    )


async def test_evidence_collection_idempotent(
    session: AsyncSession, organization
):
    """Running collection twice over the same window does not duplicate
    evidence rows."""
    await seed_compliance_catalog(session)
    org_id = organization["id"]
    now = datetime.now(timezone.utc)

    session.add(Alert(
        organization_id=org_id, category="ransomware_victim", severity="critical",
        title="ransomware test", summary="test",
    ))
    await session.flush()

    period_from = now - timedelta(days=1)
    period_to = now + timedelta(hours=1)
    c1 = await collect_evidence_for_period(
        session, organization_id=org_id, framework_code="NCA-ECC-V2",
        period_from=period_from, period_to=period_to,
    )
    c2 = await collect_evidence_for_period(
        session, organization_id=org_id, framework_code="NCA-ECC-V2",
        period_from=period_from, period_to=period_to,
    )
    assert c1["evidence_inserted"] > 0
    assert c2["evidence_inserted"] == 0
    assert c2["evidence_skipped_dupe"] == c1["evidence_inserted"]


# --- OSCAL -------------------------------------------------------------


async def test_oscal_assessment_results_shape(
    session: AsyncSession, organization
):
    """OSCAL document has required top-level structure and stable hash."""
    await seed_compliance_catalog(session)
    org_id = organization["id"]
    now = datetime.now(timezone.utc)

    session.add(Alert(
        organization_id=org_id, category="phishing", severity="high",
        title="oscal test", summary="oscal test",
    ))
    await session.flush()
    await collect_evidence_for_period(
        session, organization_id=org_id, framework_code="ISO-27001-2022",
        period_from=now - timedelta(days=1),
        period_to=now + timedelta(hours=1),
    )
    await session.flush()

    framework = (await session.execute(
        select(ComplianceFramework).where(ComplianceFramework.code == "ISO-27001-2022")
    )).scalar_one()

    fixed_at = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
    doc = await build_assessment_results(
        session,
        organization_id=org_id,
        organization_name=organization["name"],
        framework=framework,
        period_from=now - timedelta(days=1),
        period_to=now + timedelta(hours=1),
        generated_at=fixed_at,
    )

    # Required fields per OSCAL Assessment Results 1.1.2.
    assert "assessment-results" in doc
    ar = doc["assessment-results"]
    assert ar["uuid"]
    assert ar["metadata"]["title"]
    assert ar["metadata"]["oscal-version"] == "1.1.2"
    assert ar["metadata"]["last-modified"]
    assert isinstance(ar["metadata"]["parties"], list)
    assert any(p["type"] == "organization" for p in ar["metadata"]["parties"])
    assert "import-ap" in ar
    assert isinstance(ar["results"], list) and len(ar["results"]) == 1
    res = ar["results"][0]
    assert res["start"] and res["end"]
    assert isinstance(res["observations"], list) and len(res["observations"]) >= 1
    assert isinstance(res["findings"], list)
    for f in res["findings"]:
        assert f["target"]["type"] == "statement-id"
        assert f["target"]["target-id"].startswith("ISO-27001-2022::")
        assert isinstance(f["related-observations"], list)

    # Hash stability — same inputs, same bytes.
    payload1, sha1 = serialise_oscal(doc)
    payload2, sha2 = serialise_oscal(doc)
    assert sha1 == sha2
    assert len(payload1) > 0
    # And the document itself has the same UUID across calls (stable v5).
    doc2 = await build_assessment_results(
        session,
        organization_id=org_id,
        organization_name=organization["name"],
        framework=framework,
        period_from=now - timedelta(days=1),
        period_to=now + timedelta(hours=1),
        generated_at=fixed_at,
    )
    assert doc2["assessment-results"]["uuid"] == ar["uuid"]


# --- PDF ---------------------------------------------------------------


@pytest.mark.parametrize("language_mode", ["en", "ar", "bilingual"])
async def test_pdf_renders_three_modes(
    session: AsyncSession, organization, language_mode
):
    """PDF renders successfully for every supported language mode."""
    await seed_compliance_catalog(session)
    org_id = organization["id"]
    now = datetime.now(timezone.utc)

    session.add(Alert(
        organization_id=org_id, category="phishing", severity="high",
        title="pdf test", summary="pdf test",
    ))
    await session.flush()
    await collect_evidence_for_period(
        session, organization_id=org_id, framework_code="NCA-ECC-V2",
        period_from=now - timedelta(days=1),
        period_to=now + timedelta(hours=1),
    )
    await session.flush()

    framework = (await session.execute(
        select(ComplianceFramework).where(ComplianceFramework.code == "NCA-ECC-V2")
    )).scalar_one()

    pdf_bytes = await render_evidence_pack_pdf(
        session,
        organization_id=org_id,
        organization_name=organization["name"],
        framework=framework,
        period_from=now - timedelta(days=1),
        period_to=now + timedelta(hours=1),
        language_mode=language_mode,
        generated_at=now,
    )
    # Real PDF starts with the %PDF magic.
    assert pdf_bytes.startswith(b"%PDF-"), (
        f"expected PDF magic bytes, got {pdf_bytes[:20]!r}"
    )
    # Non-trivial size — empty placeholder PDFs are <600 bytes.
    assert len(pdf_bytes) > 1500


async def test_pdf_handles_empty_period(
    session: AsyncSession, organization
):
    """Even with zero evidence the PDF renders (cover + 'no evidence' notice)."""
    await seed_compliance_catalog(session)
    org_id = organization["id"]
    now = datetime.now(timezone.utc)

    framework = (await session.execute(
        select(ComplianceFramework).where(ComplianceFramework.code == "NIST-CSF-V2")
    )).scalar_one()

    pdf_bytes = await render_evidence_pack_pdf(
        session,
        organization_id=org_id,
        organization_name=organization["name"],
        framework=framework,
        period_from=now - timedelta(days=1),
        period_to=now + timedelta(hours=1),
        language_mode="en",
        generated_at=now,
    )
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000
