"""Auto-link findings to cases + dispatch notifications (Audit D12, D13).

A single hook detectors call when they create a Phase 1+ finding worth
escalating. The hook does two things in one pass:

1. **Auto-case linkage (D12).**
   - Looks for an open Case for this org with the same severity that
     was opened in the last 24h.
   - If found, links the new finding to it (one Case can aggregate many
     similar findings detected in the same incident window).
   - If not, creates a new Case at the supplied severity, then links.

2. **Notification dispatch (D13).**
   - Builds a `NotificationEvent` and routes it through the existing
     `src/notifications/router.dispatch` so any rule the customer has
     configured (Slack/Teams/PagerDuty/email/SMS) fires.

Threshold:
    By default we only auto-case CRITICAL + HIGH findings. Anything
    lower stays as a finding and shows up in the dashboard, but does
    not page someone. This keeps the on-call signal-to-noise ratio
    sane. Operators can edit the live policy under the
    ``auto_case.severities`` and ``auto_case.aggregation_window_hours``
    keys via ``/api/v1/admin/settings`` (see
    ``src.core.detector_config.load_auto_case_policy``). The
    ``_DEFAULT_AUTO_CASE_SEVERITIES`` constant below is only the seed
    value for first-read auto-creation of those rows.

Idempotency:
    `auto_link_finding` is safe to call multiple times for the same
    `(finding_type, finding_id)` — the polymorphic index keeps duplicate
    case-finding rows out, and the dispatch path is dedup'd by
    `dedup_key` at the notification-rule layer.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterable

from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.cases import Case, CaseFinding, CaseSeverity, CaseState
from src.models.common import Severity
from src.notifications.adapters import NotificationEvent
from src.notifications.router import dispatch as dispatch_notification


_logger = logging.getLogger(__name__)


_DEFAULT_AUTO_CASE_SEVERITIES = frozenset({Severity.CRITICAL.value, Severity.HIGH.value})

# How far back to reuse an existing Case before opening a fresh one.
_CASE_AGGREGATION_WINDOW = timedelta(hours=24)


async def auto_link_finding(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    finding_type: str,
    finding_id: uuid.UUID,
    severity: str,
    title: str,
    summary: str | None = None,
    event_kind: str = "discovery_finding",
    dedup_key: str | None = None,
    tags: Iterable[str] = (),
    auto_case_severities: Iterable[str] | None = None,
) -> Case | None:
    """Auto-link a finding to a Case (creating one if needed) and
    dispatch a notification. Returns the Case the finding was linked
    to, or ``None`` if the severity was below the auto-case threshold
    (notification still fires for those — analysts may still want a
    Slack ping for a MEDIUM exposure, even if no Case is opened).

    The function commits its own writes via ``db.flush`` only — the
    caller's surrounding transaction is responsible for commit, so
    the link is atomic with the finding insert.
    """
    if auto_case_severities is not None:
        severities = frozenset(auto_case_severities)
        aggregation_window = _CASE_AGGREGATION_WINDOW
    else:
        # Live policy from AppSetting. ``load_auto_case_policy`` returns
        # the in-code default and creates the row on first read so the
        # admin dashboard immediately reflects the live values.
        from src.core.detector_config import load_auto_case_policy

        policy = await load_auto_case_policy(db, organization_id)
        severities = frozenset(policy.severities)
        aggregation_window = timedelta(hours=policy.aggregation_window_hours)

    # --- 1. dispatch a notification (always) -------------------------
    try:
        evt = NotificationEvent(
            kind=event_kind,
            severity=severity,
            title=title,
            summary=summary or title,
            organization_id=str(organization_id),
            dedup_key=dedup_key or f"{finding_type}:{finding_id}",
            tags=tuple(tags),
            extra={
                "finding_type": finding_type,
                "finding_id": str(finding_id),
            },
        )
        await dispatch_notification(db, evt)
    except Exception:  # noqa: BLE001 — notification failures must never block linkage
        _logger.exception(
            "auto_link_finding: notification dispatch failed for %s:%s",
            finding_type, finding_id,
        )

    # --- 2. auto-case (only above threshold) ------------------------
    if severity not in severities:
        return None

    cutoff = datetime.now(timezone.utc) - aggregation_window
    existing = (
        await db.execute(
            select(Case)
            .where(
                and_(
                    Case.organization_id == organization_id,
                    Case.state.in_(
                        [CaseState.OPEN.value, CaseState.IN_PROGRESS.value]
                    ),
                    Case.severity == severity,
                    Case.created_at >= cutoff,
                )
            )
            .order_by(Case.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    if existing is None:
        existing = Case(
            organization_id=organization_id,
            title=title[:500],
            summary=summary,
            severity=severity,
            state=CaseState.OPEN.value,
            tags=list(tags),
        )
        db.add(existing)
        await db.flush()

    link = CaseFinding(
        case_id=existing.id,
        alert_id=None,
        finding_type=finding_type,
        finding_id=finding_id,
        is_primary=False,
        link_reason=f"auto-linked from {finding_type} (severity={severity})",
    )
    db.add(link)
    try:
        await db.flush()
    except IntegrityError:
        # Race / re-detection: another transaction linked the same
        # finding first. Roll back just this insert and keep the case.
        await db.rollback()
        return existing

    return existing


__all__ = ["auto_link_finding"]
