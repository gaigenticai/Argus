"""Mapping engine — signals (alerts/cases/MITRE attachments) → controls.

Public entry point: :func:`collect_evidence_for_period`.

Walks the tenant's alerts and cases in the requested period, extracts
the signals they emit (alert.category, case.state, attached MITRE
techniques), and materialises ``ComplianceEvidence`` rows linking each
signal to the matching controls in the requested framework via the
``compliance_control_mappings`` lookup.

Idempotent on (organization_id, framework_id, control_id, source_kind,
source_id) — re-running across overlapping windows yields no duplicate
evidence rows; new evidence found for already-mapped sources is skipped.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.compliance import (
    ComplianceControl,
    ComplianceControlMapping,
    ComplianceEvidence,
    ComplianceFramework,
    EvidenceSourceKind,
    EvidenceStatus,
    SignalKind,
)

logger = logging.getLogger(__name__)


async def _resolve_framework(
    session: AsyncSession, framework_code: str
) -> ComplianceFramework:
    fw = (await session.execute(
        select(ComplianceFramework).where(
            ComplianceFramework.code == framework_code,
            ComplianceFramework.is_active.is_(True),
        )
    )).scalar_one_or_none()
    if fw is None:
        raise ValueError(
            f"compliance framework {framework_code!r} not found or inactive"
        )
    return fw


async def _controls_for_signal(
    session: AsyncSession,
    framework_id: uuid.UUID,
    signal_kind: str,
    signal_value: str,
) -> list[tuple[ComplianceControl, float]]:
    """Return matching controls and their confidence for a single signal."""
    rows = (await session.execute(
        select(ComplianceControl, ComplianceControlMapping.confidence)
        .join(
            ComplianceControlMapping,
            ComplianceControlMapping.control_id == ComplianceControl.id,
        )
        .where(
            ComplianceControl.framework_id == framework_id,
            ComplianceControlMapping.signal_kind == signal_kind,
            ComplianceControlMapping.signal_value == signal_value,
        )
    )).all()
    return [(ctrl, conf) for ctrl, conf in rows]


async def _existing_evidence_keys(
    session: AsyncSession,
    organization_id: uuid.UUID,
    framework_id: uuid.UUID,
) -> set[tuple[uuid.UUID, str, uuid.UUID]]:
    """Return the (control_id, source_kind, source_id) keys that already
    have an evidence row for this org+framework — used for dedup on
    re-runs."""
    rows = (await session.execute(
        select(
            ComplianceEvidence.control_id,
            ComplianceEvidence.source_kind,
            ComplianceEvidence.source_id,
        ).where(
            ComplianceEvidence.organization_id == organization_id,
            ComplianceEvidence.framework_id == framework_id,
        )
    )).all()
    return {(c, k, s) for c, k, s in rows}


async def _alerts_in_period(
    session: AsyncSession,
    organization_id: uuid.UUID,
    period_from: datetime,
    period_to: datetime,
) -> list[Any]:
    from src.models.threat import Alert

    rows = (await session.execute(
        select(Alert).where(
            Alert.organization_id == organization_id,
            Alert.created_at >= period_from,
            Alert.created_at < period_to,
        )
    )).scalars().all()
    return list(rows)


async def _cases_in_period(
    session: AsyncSession,
    organization_id: uuid.UUID,
    period_from: datetime,
    period_to: datetime,
) -> list[Any]:
    from src.models.cases import Case

    rows = (await session.execute(
        select(Case).where(
            Case.organization_id == organization_id,
            Case.created_at >= period_from,
            Case.created_at < period_to,
        )
    )).scalars().all()
    return list(rows)


async def _mitre_attachments_for_entities(
    session: AsyncSession,
    organization_id: uuid.UUID,
    entity_type: str,
    entity_ids: list[uuid.UUID],
) -> dict[uuid.UUID, list[str]]:
    """Return a map of entity_id -> [technique_external_id, ...]."""
    if not entity_ids:
        return {}
    from src.models.mitre import AttackTechniqueAttachment

    rows = (await session.execute(
        select(
            AttackTechniqueAttachment.entity_id,
            AttackTechniqueAttachment.technique_external_id,
        ).where(
            AttackTechniqueAttachment.organization_id == organization_id,
            AttackTechniqueAttachment.entity_type == entity_type,
            AttackTechniqueAttachment.entity_id.in_(entity_ids),
        )
    )).all()
    out: dict[uuid.UUID, list[str]] = {}
    for ent_id, ext_id in rows:
        out.setdefault(ent_id, []).append(ext_id)
    return out


def _alert_summary(alert: Any) -> tuple[str | None, str | None]:
    """Build per-evidence summary lines (English + Arabic).

    Arabic stays None unless the alert itself stored bilingual content —
    we don't translate live; the bilingual PDF path renders English with
    an Arabic exec summary and that's the supported flow.
    """
    en = f"Alert {alert.id}: {alert.title} (severity={alert.severity}, " \
         f"category={alert.category}, status={alert.status})"
    return en, None


def _case_summary(case: Any) -> tuple[str | None, str | None]:
    en = f"Case {case.id}: {case.title} (state={case.state}, " \
         f"severity={case.severity})"
    return en, None


async def collect_evidence_for_period(
    session: AsyncSession,
    organization_id: uuid.UUID,
    framework_code: str,
    period_from: datetime,
    period_to: datetime,
) -> dict[str, int]:
    """Materialise evidence for the period.

    Returns counts: {"alerts_seen", "cases_seen", "evidence_inserted",
    "evidence_skipped_dupe"}.

    Idempotent — running twice over the same window does not insert
    duplicate evidence. Safe to run before each export.
    """
    framework = await _resolve_framework(session, framework_code)

    alerts = await _alerts_in_period(
        session, organization_id, period_from, period_to,
    )
    cases = await _cases_in_period(
        session, organization_id, period_from, period_to,
    )

    alert_ids = [a.id for a in alerts]
    mitre_by_alert = await _mitre_attachments_for_entities(
        session, organization_id, "alert", alert_ids,
    )

    existing = await _existing_evidence_keys(
        session, organization_id, framework.id,
    )

    counts = {
        "alerts_seen": len(alerts),
        "cases_seen": len(cases),
        "evidence_inserted": 0,
        "evidence_skipped_dupe": 0,
    }

    # Per-control control cache so repeated lookups for the same signal
    # don't re-hit the DB.
    signal_cache: dict[
        tuple[str, str], list[tuple[ComplianceControl, float]]
    ] = {}

    async def _resolve(kind: str, value: str) -> list[
        tuple[ComplianceControl, float]
    ]:
        key = (kind, value)
        if key not in signal_cache:
            signal_cache[key] = await _controls_for_signal(
                session, framework.id, kind, value,
            )
        return signal_cache[key]

    # Walk alerts.
    for alert in alerts:
        signals: list[tuple[str, str]] = [
            (SignalKind.ALERT_CATEGORY.value, alert.category),
        ]
        for tech_id in mitre_by_alert.get(alert.id, []):
            base = tech_id.split(".")[0]  # T1566.001 → T1566 base technique
            signals.append((SignalKind.MITRE_TECHNIQUE.value, base))
            if base != tech_id:
                signals.append((SignalKind.MITRE_TECHNIQUE.value, tech_id))

        seen_controls: set[uuid.UUID] = set()
        for kind, value in signals:
            for control, _conf in await _resolve(kind, value):
                if control.id in seen_controls:
                    continue
                seen_controls.add(control.id)
                key = (control.id, EvidenceSourceKind.ALERT.value, alert.id)
                if key in existing:
                    counts["evidence_skipped_dupe"] += 1
                    continue
                summary_en, summary_ar = _alert_summary(alert)
                session.add(ComplianceEvidence(
                    organization_id=organization_id,
                    framework_id=framework.id,
                    control_id=control.id,
                    source_kind=EvidenceSourceKind.ALERT.value,
                    source_id=alert.id,
                    captured_at=alert.created_at,
                    summary_en=summary_en,
                    summary_ar=summary_ar,
                    details={
                        "alert_severity": alert.severity,
                        "alert_status": alert.status,
                        "alert_category": alert.category,
                    },
                    status=EvidenceStatus.ACTIVE.value,
                ))
                existing.add(key)
                counts["evidence_inserted"] += 1

    # Walk cases.
    for case in cases:
        signals = [(SignalKind.CASE_STATE.value, case.state)]
        seen_controls = set()
        for kind, value in signals:
            for control, _conf in await _resolve(kind, value):
                if control.id in seen_controls:
                    continue
                seen_controls.add(control.id)
                key = (control.id, EvidenceSourceKind.CASE.value, case.id)
                if key in existing:
                    counts["evidence_skipped_dupe"] += 1
                    continue
                summary_en, summary_ar = _case_summary(case)
                session.add(ComplianceEvidence(
                    organization_id=organization_id,
                    framework_id=framework.id,
                    control_id=control.id,
                    source_kind=EvidenceSourceKind.CASE.value,
                    source_id=case.id,
                    captured_at=case.created_at,
                    summary_en=summary_en,
                    summary_ar=summary_ar,
                    details={
                        "case_state": case.state,
                        "case_severity": case.severity,
                    },
                    status=EvidenceStatus.ACTIVE.value,
                ))
                existing.add(key)
                counts["evidence_inserted"] += 1

    await session.flush()
    logger.info(
        "compliance evidence collected: org=%s framework=%s counts=%s",
        organization_id, framework_code, counts,
    )
    return counts


async def evidence_for_export(
    session: AsyncSession,
    organization_id: uuid.UUID,
    framework_code: str,
    period_from: datetime,
    period_to: datetime,
) -> dict[uuid.UUID, list[ComplianceEvidence]]:
    """Return active evidence rows grouped by control_id, scoped to the
    period and framework.

    Read-only — does not materialise new evidence. Call
    :func:`collect_evidence_for_period` first if you want fresh evidence.
    """
    framework = await _resolve_framework(session, framework_code)
    rows = (await session.execute(
        select(ComplianceEvidence).where(
            ComplianceEvidence.organization_id == organization_id,
            ComplianceEvidence.framework_id == framework.id,
            ComplianceEvidence.status == EvidenceStatus.ACTIVE.value,
            ComplianceEvidence.captured_at >= period_from,
            ComplianceEvidence.captured_at < period_to,
        ).order_by(ComplianceEvidence.captured_at.desc())
    )).scalars().all()
    grouped: dict[uuid.UUID, list[ComplianceEvidence]] = {}
    for ev in rows:
        grouped.setdefault(ev.control_id, []).append(ev)
    return grouped
