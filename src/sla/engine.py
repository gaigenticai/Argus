"""SLA evaluation engine.

For each open case, evaluate against the org's SlaPolicy for that
severity:

    first_response_due  = case.created_at + first_response_minutes
    remediation_due     = case.created_at + remediation_minutes

Breaches are recorded once per (case, kind) — re-evaluating an already
breached case is idempotent.

Resolution:
    First response satisfied when ``case.first_response_at`` is set.
    Remediation satisfied when state is in
    ``{remediated, verified, closed}``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.cases import Case, CaseState
from src.models.sla import SlaBreachEvent, SlaBreachKind, SlaPolicy


@dataclass
class EvaluationResult:
    case_id: uuid.UUID
    severity: str
    first_response_breached: bool
    remediation_breached: bool
    first_response_due_at: datetime | None
    remediation_due_at: datetime | None
    new_breaches: int


def _now() -> datetime:
    return datetime.now(timezone.utc)


_DONE_STATES = {
    CaseState.REMEDIATED.value,
    CaseState.VERIFIED.value,
    CaseState.CLOSED.value,
}


async def evaluate_case(
    db: AsyncSession,
    case: Case,
    policies: dict[str, SlaPolicy] | None = None,
) -> EvaluationResult:
    if policies is None:
        rows = (
            await db.execute(
                select(SlaPolicy).where(
                    SlaPolicy.organization_id == case.organization_id
                )
            )
        ).scalars().all()
        policies = {p.severity: p for p in rows}

    policy = policies.get(case.severity)
    if policy is None:
        return EvaluationResult(
            case_id=case.id,
            severity=case.severity,
            first_response_breached=False,
            remediation_breached=False,
            first_response_due_at=None,
            remediation_due_at=None,
            new_breaches=0,
        )

    fr_due = case.created_at + timedelta(minutes=policy.first_response_minutes)
    rem_due = case.created_at + timedelta(minutes=policy.remediation_minutes)

    now = _now()
    fr_satisfied = case.first_response_at is not None
    rem_satisfied = case.state in _DONE_STATES

    fr_breached = (not fr_satisfied) and now > fr_due
    rem_breached = (not rem_satisfied) and now > rem_due

    new_breaches = 0
    for breached, kind in (
        (fr_breached, SlaBreachKind.FIRST_RESPONSE),
        (rem_breached, SlaBreachKind.REMEDIATION),
    ):
        if not breached:
            continue
        existing = (
            await db.execute(
                select(SlaBreachEvent).where(
                    and_(
                        SlaBreachEvent.case_id == case.id,
                        SlaBreachEvent.kind == kind.value,
                    )
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            continue
        threshold = (
            policy.first_response_minutes
            if kind == SlaBreachKind.FIRST_RESPONSE
            else policy.remediation_minutes
        )
        db.add(
            SlaBreachEvent(
                organization_id=case.organization_id,
                case_id=case.id,
                kind=kind.value,
                severity=case.severity,
                threshold_minutes=threshold,
                detected_at=now,
            )
        )
        new_breaches += 1

    return EvaluationResult(
        case_id=case.id,
        severity=case.severity,
        first_response_breached=fr_breached,
        remediation_breached=rem_breached,
        first_response_due_at=fr_due,
        remediation_due_at=rem_due,
        new_breaches=new_breaches,
    )


async def evaluate_organization(
    db: AsyncSession, organization_id: uuid.UUID
) -> list[EvaluationResult]:
    cases = (
        await db.execute(
            select(Case).where(
                and_(
                    Case.organization_id == organization_id,
                    Case.state != CaseState.CLOSED.value,
                )
            )
        )
    ).scalars().all()
    rows = (
        await db.execute(
            select(SlaPolicy).where(SlaPolicy.organization_id == organization_id)
        )
    ).scalars().all()
    policies = {p.severity: p for p in rows}
    results: list[EvaluationResult] = []
    for c in cases:
        results.append(await evaluate_case(db, c, policies))
    return results


__all__ = ["EvaluationResult", "evaluate_case", "evaluate_organization"]
