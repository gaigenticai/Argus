"""Audit D12 + D13 — finding auto-link to Case + notification dispatch."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from src.cases.auto_link import auto_link_finding
from src.models.cases import Case, CaseFinding, CaseState

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


async def test_auto_link_high_creates_case_and_links(
    client: AsyncClient, analyst_user, organization
):
    """A HIGH-severity finding should create a fresh Case and a
    polymorphic CaseFinding row pointing back to it."""
    from src.storage import database as _db

    finding_id = uuid.uuid4()

    async with _db.async_session_factory() as session:
        case = await auto_link_finding(
            session,
            organization_id=organization["id"],
            finding_type="exposure",
            finding_id=finding_id,
            severity="high",
            title="Critical TLS misconfig on api.example.test",
            summary="HSTS missing; TLS 1.0 enabled",
            event_kind="alert",
            dedup_key=f"test:{finding_id}",
            tags=("test",),
        )
        await session.commit()
        assert case is not None

        # Case persisted at the right severity / state.
        row = (await session.execute(select(Case).where(Case.id == case.id))).scalar_one()
        assert row.severity == "high"
        assert row.state == CaseState.OPEN.value
        assert row.organization_id == organization["id"]

        # Polymorphic linkage.
        link = (
            await session.execute(
                select(CaseFinding).where(
                    CaseFinding.finding_type == "exposure",
                    CaseFinding.finding_id == finding_id,
                )
            )
        ).scalar_one()
        assert link.case_id == case.id
        assert link.alert_id is None


async def test_auto_link_low_severity_does_not_open_case(
    client: AsyncClient, analyst_user, organization
):
    """Below-threshold severities are notified but not auto-cased."""
    from src.storage import database as _db

    finding_id = uuid.uuid4()
    async with _db.async_session_factory() as session:
        case = await auto_link_finding(
            session,
            organization_id=organization["id"],
            finding_type="exposure",
            finding_id=finding_id,
            severity="low",
            title="Minor info disclosure",
        )
        await session.commit()
        assert case is None

        rows = (
            await session.execute(
                select(CaseFinding).where(
                    CaseFinding.finding_type == "exposure",
                    CaseFinding.finding_id == finding_id,
                )
            )
        ).scalars().all()
        assert rows == []


async def test_auto_link_aggregates_into_recent_open_case(
    client: AsyncClient, analyst_user, organization
):
    """Two HIGH findings within the 24-hour window land in the same
    Case so on-call doesn't get one ticket per detection."""
    from src.storage import database as _db

    async with _db.async_session_factory() as session:
        a = await auto_link_finding(
            session,
            organization_id=organization["id"],
            finding_type="exposure",
            finding_id=uuid.uuid4(),
            severity="high",
            title="First finding",
        )
        b = await auto_link_finding(
            session,
            organization_id=organization["id"],
            finding_type="exposure",
            finding_id=uuid.uuid4(),
            severity="high",
            title="Second finding (same incident window)",
        )
        await session.commit()
        assert a is not None and b is not None
        assert a.id == b.id, "two HIGH findings within 24h should aggregate"
