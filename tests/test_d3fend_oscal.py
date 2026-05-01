"""D3FEND + OSCAL catalog ingestion (P2 #2.12) — integration tests.

Real Postgres. Covers the curated seeders (idempotency, D3FEND defenses
matching ATT&CK techniques) and the upstream-refresh path with a mocked
JSON payload.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from src.compliance.oscal_catalog import (
    CURATED_NIST_53_R5,
    lookup as lookup_oscal,
    refresh_from_upstream as refresh_oscal,
    seed_minimal as seed_oscal_minimal,
)
from src.intel.d3fend import (
    CURATED_D3FEND,
    defenses_for_attack,
    lookup as lookup_d3fend,
    refresh_from_upstream as refresh_d3fend,
    seed_d3fend_minimal,
)
from src.models.d3fend_oscal import D3FENDTechnique, OscalCatalogEntry

pytestmark = pytest.mark.asyncio


# ── D3FEND ────────────────────────────────────────────────────────────


async def test_seed_d3fend_minimal_idempotent(session: AsyncSession):
    await session.execute(text("TRUNCATE d3fend_techniques"))
    await session.flush()

    counts1 = await seed_d3fend_minimal(session)
    counts2 = await seed_d3fend_minimal(session)
    assert counts1["created"] == len(CURATED_D3FEND)
    assert counts2["created"] == 0
    # Re-seed leaves rows unchanged.
    assert counts2["unchanged"] == len(CURATED_D3FEND)


async def test_d3fend_lookup(session: AsyncSession):
    await session.execute(text("TRUNCATE d3fend_techniques"))
    await session.flush()
    await seed_d3fend_minimal(session)

    mfa = await lookup_d3fend(session, "D3-MFA")
    assert mfa is not None
    assert mfa.label == "Multi-factor Authentication"
    assert mfa.tactic == "harden"


async def test_defenses_for_attack_matches_base_and_subtechnique(
    session: AsyncSession,
):
    await session.execute(text("TRUNCATE d3fend_techniques"))
    await session.flush()
    await seed_d3fend_minimal(session)

    # MFA counters T1078 (Valid Accounts) — exact match.
    by_exact = await defenses_for_attack(session, ["T1078"])
    assert any(d.d3fend_id == "D3-MFA" for d in by_exact)

    # T1078.004 (Cloud Accounts) is in MFA's counters list directly.
    by_sub = await defenses_for_attack(session, ["T1078.004"])
    assert any(d.d3fend_id == "D3-MFA" for d in by_sub)

    # T1110.003 (Password Spraying) — match via base T1110.
    by_base_match = await defenses_for_attack(session, ["T1110.003"])
    assert any(d.d3fend_id == "D3-MFA" for d in by_base_match)


async def test_refresh_d3fend_with_mocked_payload(session: AsyncSession):
    await session.execute(text("TRUNCATE d3fend_techniques"))
    await session.flush()
    payload = {
        "@graph": [
            {"@id": "d3f:D3-XYZ", "rdfs:label": "Mock Defense",
             "rdfs:comment": "Fake D3FEND technique for the test."},
            {"@id": "d3f:NotADefense", "rdfs:label": "ignored"},
            {"@id": "d3f:D3-MFA", "rdfs:label": "Multi-factor Authentication"},
        ],
    }
    counts = await refresh_d3fend(session, json_payload=payload)
    assert counts["created"] == 2  # only D3-XYZ + D3-MFA matched
    xyz = await lookup_d3fend(session, "D3-XYZ")
    assert xyz is not None
    assert xyz.label == "Mock Defense"


# ── OSCAL ─────────────────────────────────────────────────────────────


async def test_seed_oscal_minimal_idempotent(session: AsyncSession):
    await session.execute(text(
        "DELETE FROM oscal_catalog_entries WHERE catalog = 'NIST_SP-800-53_rev5'"
    ))
    await session.flush()

    counts1 = await seed_oscal_minimal(session)
    counts2 = await seed_oscal_minimal(session)
    assert counts1["created"] == len(CURATED_NIST_53_R5)
    assert counts2["created"] == 0
    assert counts2["unchanged"] == len(CURATED_NIST_53_R5)


async def test_oscal_lookup_known_control(session: AsyncSession):
    await session.execute(text(
        "DELETE FROM oscal_catalog_entries WHERE catalog = 'NIST_SP-800-53_rev5'"
    ))
    await session.flush()
    await seed_oscal_minimal(session)

    ac2 = await lookup_oscal(session,
                              catalog="NIST_SP-800-53_rev5", control_id="AC-2")
    assert ac2 is not None
    assert "Account Management" in ac2.title
    assert "manages" in (ac2.statement or "").lower()


async def test_oscal_refresh_with_mocked_payload(session: AsyncSession):
    await session.execute(text(
        "DELETE FROM oscal_catalog_entries WHERE catalog = 'TEST_CAT'"
    ))
    await session.flush()
    payload = {
        "catalog": {
            "groups": [{
                "id": "ac",
                "title": "Access Control",
                "controls": [{
                    "id": "ac-99",
                    "title": "Test Control",
                    "parts": [{
                        "name": "statement",
                        "prose": "Lorem ipsum dolor sit amet.",
                        "parts": [
                            {"prose": "Sub-statement A."},
                            {"prose": "Sub-statement B."},
                        ],
                    }],
                    "controls": [{
                        "id": "ac-99.1",
                        "title": "Sub Control",
                        "parts": [{"name": "statement",
                                    "prose": "child prose"}],
                    }],
                }],
            }],
        },
    }
    counts = await refresh_oscal(session, catalog="TEST_CAT",
                                  json_payload=payload)
    assert counts["created"] == 2  # AC-99 + AC-99.1 (id case + .→- collapse)

    ac99 = await lookup_oscal(session, catalog="TEST_CAT", control_id="AC-99")
    assert ac99 is not None
    assert "Sub-statement A" in (ac99.statement or "")
    assert "Sub-statement B" in (ac99.statement or "")
    # Full OSCAL object preserved for round-trip.
    assert ac99.oscal["title"] == "Test Control"

    sub = await lookup_oscal(session, catalog="TEST_CAT", control_id="AC-99-1")
    assert sub is not None
