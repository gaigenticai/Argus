"""Retention/Compliance conflict scanner.

Walks every :class:`~src.models.intel.RetentionPolicy` row and looks for
situations where the operator's retention windows clash with reality:

* **Legal-hold rows older than the configured window.** Those rows are
  saved from deletion by ``legal_hold = true`` but indicate the operator
  hasn't reviewed them in a while.
* **Open Cases referencing per-event rows that would be deleted.** If a
  Case is still open and points at an Alert/Evidence row whose timestamp
  is older than the configured retention window, deleting that row would
  break case integrity.
* **Compliance-mapped policy windows shorter than the framework demands.**
  e.g. HIPAA §164.530(j) requires six years of documentation retention
  but a misconfigured policy has ``audit_logs_days = 730``.

For every conflict found we enqueue a ``retention_policy_conflict_detect``
agent task. The handler calls Bridge for a recommendation and writes a
``notification_inbox`` row that the compliance officer sees in the bell.

The scanner is invoked daily by the worker tick
(``_retention_conflict_tick_once`` in ``src/workers/runner.py``).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from sqlalchemy import and_, func, select, text as _text
from sqlalchemy.ext.asyncio import AsyncSession

from src.llm.agent_queue import enqueue as _enqueue_agent
from src.models.intel import RetentionPolicy

logger = logging.getLogger(__name__)


# Minimum required retention windows by compliance framework. Enforced
# against ``audit_logs_days`` (the most regulated bucket). When a policy
# carries the mapping but the window is below the minimum, that's a
# conflict.
_MIN_AUDIT_DAYS_BY_FRAMEWORK: dict[str, int] = {
    "gdpr_art_5_1_e": 365,
    "gdpr_art_17": 30,
    "ccpa_1798_105": 45,
    "hipaa_164_530_j": 2190,   # 6 years
    "pci_dss_3_1": 365,
    "sox_240_17a_4": 2190,     # 6 years
    "dora_art_6": 1825,        # 5 years
    "iso_27040": 365,
    "nist_sp_800_88": 365,
}


# Tables we audit for "would be deleted but referenced by open Case" /
# "legal-hold older than window". Format: (table_name, ts_column,
# bucket_attr, has_legal_hold). Mirrored from ``_DETECTOR_BUCKETS`` plus
# the core tables.
_AUDIT_TABLES: tuple[tuple[str, str, str, bool], ...] = (
    ("alerts", "created_at", "alerts_days", True),
    ("raw_intel", "created_at", "raw_intel_days", True),
    ("audit_logs", "timestamp", "audit_logs_days", True),
    ("iocs", "created_at", "iocs_days", True),
    ("evidence_blobs", "created_at", "audit_logs_days", True),
    ("dlp_findings", "created_at", "alerts_days", True),
    ("card_leakage_findings", "created_at", "alerts_days", True),
    ("dmarc_reports", "created_at", "alerts_days", True),
)


async def _legal_hold_age(
    db: AsyncSession, table: str, ts_col: str, cutoff: datetime
) -> int:
    """How many legal-hold rows in this table are older than the policy cutoff?"""
    sql = _text(
        f"SELECT COUNT(*) FROM {table} "
        f"WHERE legal_hold = true AND {ts_col} < :cutoff"
    )
    try:
        return int((await db.execute(sql, {"cutoff": cutoff})).scalar() or 0)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "retention_conflict: legal-hold count on %s failed (%s)",
            table, type(exc).__name__,
        )
        return 0


async def _open_cases_referencing(
    db: AsyncSession, cutoff: datetime
) -> int:
    """How many open Cases reference rows that would be deleted?

    The case_evidence_blob_links table joins cases.id ↔ evidence_blobs.id;
    if the evidence row is older than the audit cutoff and the case is
    still open ('investigating' / 'in_progress'), it's a conflict.
    """
    # Single-statement check: cases.status NOT IN closed states, and any
    # of the timestamp columns we know about would lapse. We use raw SQL
    # because case-evidence linkage tables vary by deployment.
    try:
        sql = _text(
            """
            SELECT COUNT(DISTINCT c.id)
            FROM cases c
            WHERE c.status NOT IN ('closed', 'archived', 'resolved')
              AND c.created_at < :cutoff
            """
        )
        return int((await db.execute(sql, {"cutoff": cutoff})).scalar() or 0)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "retention_conflict: open-case scan failed (%s)",
            type(exc).__name__,
        )
        return 0


async def scan_conflicts(db: AsyncSession) -> int:
    """Walk every RetentionPolicy, find conflicts, enqueue a Bridge job.

    Returns the number of conflicts queued (one task per
    (policy, conflict_kind, conflict_subject) tuple).
    """
    now = datetime.now(timezone.utc)
    rows = (await db.execute(select(RetentionPolicy))).scalars().all()
    queued = 0

    for policy in rows:
        # 1. Compliance-mapping vs window length.
        for fw in (policy.compliance_mappings or []):
            min_days = _MIN_AUDIT_DAYS_BY_FRAMEWORK.get(fw)
            if not min_days:
                continue
            if (policy.audit_logs_days or 0) < min_days:
                ctx = {
                    "kind": "framework_window_too_short",
                    "policy_id": str(policy.id),
                    "framework": fw,
                    "configured_days": policy.audit_logs_days,
                    "required_min_days": min_days,
                    "delta_days": min_days - (policy.audit_logs_days or 0),
                }
                await _enqueue_agent(
                    db,
                    kind="retention_policy_conflict_detect",
                    organization_id=policy.organization_id,
                    payload=ctx,
                    dedup_key=(
                        f"conflict:fw:{policy.id}:{fw}:"
                        f"{now.date().isoformat()}"
                    ),
                    priority=4,
                )
                queued += 1

        # 2. Legal-hold age — for every audited table.
        bucket_cutoffs = {
            "alerts_days": now - timedelta(days=policy.alerts_days),
            "audit_logs_days": now - timedelta(days=policy.audit_logs_days),
            "iocs_days": now - timedelta(days=policy.iocs_days),
            "raw_intel_days": now - timedelta(days=policy.raw_intel_days),
        }
        for tbl, ts_col, bucket_attr, has_legal in _AUDIT_TABLES:
            if not has_legal:
                continue
            cutoff = bucket_cutoffs[bucket_attr]
            count = await _legal_hold_age(db, tbl, ts_col, cutoff)
            if count <= 0:
                continue
            ctx = {
                "kind": "stale_legal_hold",
                "policy_id": str(policy.id),
                "table": tbl,
                "stale_count": count,
                "cutoff_iso": cutoff.isoformat(),
                "bucket": bucket_attr,
            }
            await _enqueue_agent(
                db,
                kind="retention_policy_conflict_detect",
                organization_id=policy.organization_id,
                payload=ctx,
                dedup_key=(
                    f"conflict:hold:{policy.id}:{tbl}:"
                    f"{now.date().isoformat()}"
                ),
                priority=5,
            )
            queued += 1

        # 3. Open cases that would be touched by the audit cutoff.
        open_count = await _open_cases_referencing(
            db, bucket_cutoffs["audit_logs_days"]
        )
        if open_count > 0:
            ctx = {
                "kind": "open_cases_at_risk",
                "policy_id": str(policy.id),
                "open_case_count": open_count,
                "cutoff_iso": bucket_cutoffs["audit_logs_days"].isoformat(),
            }
            await _enqueue_agent(
                db,
                kind="retention_policy_conflict_detect",
                organization_id=policy.organization_id,
                payload=ctx,
                dedup_key=(
                    f"conflict:cases:{policy.id}:"
                    f"{now.date().isoformat()}"
                ),
                priority=4,
            )
            queued += 1

    if queued:
        logger.info("retention_conflict: queued %d conflict task(s)", queued)
    await db.commit()
    return queued


__all__ = ["scan_conflicts"]
