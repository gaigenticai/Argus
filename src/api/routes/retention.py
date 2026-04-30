"""Data retention management endpoints.

The cleanup engine prunes every per-event-growth table and deletes the
MinIO objects backing soft-deleted ``EvidenceBlob`` rows. Every
detector / finding table that grows per-event is covered. Tables
carrying a ``legal_hold`` boolean honour it: a held row is never
pruned, even after its retention window has elapsed.
"""

from __future__ import annotations


import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import and_, select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser, CurrentUser, audit_log
from src.models.auth import AuditAction, AuditLog
from src.models.intel import IOC, RetentionPolicy
from src.models.threat import Alert, RawIntel
from src.storage.database import get_session

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/retention", tags=["Compliance & DLP"])


# --- Schemas ------------------------------------------------------------


class RetentionPolicyCreate(BaseModel):
    organization_id: uuid.UUID | None = None
    raw_intel_days: int = 90
    alerts_days: int = 365
    audit_logs_days: int = 730
    iocs_days: int = 365
    redact_pii: bool = True
    auto_cleanup_enabled: bool = True


class RetentionPolicyUpdate(BaseModel):
    raw_intel_days: int | None = None
    alerts_days: int | None = None
    audit_logs_days: int | None = None
    iocs_days: int | None = None
    redact_pii: bool | None = None
    auto_cleanup_enabled: bool | None = None


class RetentionPolicyResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    raw_intel_days: int
    alerts_days: int
    audit_logs_days: int
    iocs_days: int
    redact_pii: bool
    auto_cleanup_enabled: bool
    last_cleanup_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CleanupResult(BaseModel):
    raw_intel_deleted: int = 0
    alerts_deleted: int = 0
    audit_logs_deleted: int = 0
    iocs_deleted: int = 0
    news_articles_deleted: int = 0
    live_probes_deleted: int = 0
    dlp_findings_deleted: int = 0
    card_leakage_findings_deleted: int = 0
    dmarc_reports_deleted: int = 0
    sla_breach_events_deleted: int = 0
    exposure_findings_deleted: int = 0
    suspect_domains_deleted: int = 0
    discovery_findings_deleted: int = 0
    impersonation_findings_deleted: int = 0
    mobile_app_findings_deleted: int = 0
    fraud_findings_deleted: int = 0
    notification_deliveries_deleted: int = 0
    asset_changes_deleted: int = 0
    triage_runs_deleted: int = 0
    vulnerability_scans_deleted: int = 0
    actor_sightings_deleted: int = 0
    threat_feed_entries_deleted: int = 0
    logo_matches_deleted: int = 0
    onboarding_sessions_deleted: int = 0
    discovery_jobs_deleted: int = 0
    feed_health_deleted: int = 0
    evidence_blobs_purged: int = 0
    minio_objects_purged: int = 0
    minio_object_purge_errors: int = 0
    total_deleted: int = 0
    policy_id: uuid.UUID
    cleanup_at: datetime


class RetentionStats(BaseModel):
    raw_intel_count: int
    raw_intel_oldest: datetime | None
    raw_intel_would_delete: int
    alerts_count: int
    alerts_oldest: datetime | None
    alerts_would_delete: int
    audit_logs_count: int
    audit_logs_oldest: datetime | None
    audit_logs_would_delete: int
    iocs_count: int
    iocs_oldest: datetime | None
    iocs_would_delete: int


# --- Cleanup engine ----------------------------------------------------


@dataclass
class _Bucket:
    """Internal helper. ``column`` is the timestamp column we age on."""

    label: str
    table: str
    timestamp_column: str
    bucket_days_attr: str  # one of policy.alerts_days / audit_logs_days / iocs_days / raw_intel_days
    has_legal_hold: bool = False
    has_organization_id: bool = True


# Tables grouped by retention bucket. Operational / high-volume data
# follows ``alerts_days``; evidentiary follows ``audit_logs_days``.
# Exotic per-event tables that don't carry a created_at column are
# omitted (the worker writes a FeedHealth row when it can't prune).
#
# Tables intentionally excluded from automated retention (no _Bucket entry):
#   cases                   — legal proceedings; retention managed via legal-hold
#                             and case-close workflow, not time-based pruning.
#   reports                 — compliance PDF artifacts; operator-managed lifecycle.
#   advisories              — reference intelligence; semi-permanent, no pruning.
#   vendor_scorecards       — TPRM business records; operator-managed lifecycle.
#   questionnaire_instances — compliance evidence; operator-managed lifecycle.
#   social_accounts         — monitoring configuration (not per-event data).
#   takedown_tickets        — legal/compliance records; must survive case lifecycle.
_DETECTOR_BUCKETS = (
    _Bucket("exposure_findings", "exposure_findings", "matched_at", "alerts_days", has_legal_hold=True),
    _Bucket("suspect_domains", "suspect_domains", "first_seen_at", "alerts_days", has_legal_hold=True),
    _Bucket("discovery_findings", "discovery_findings", "created_at", "alerts_days"),
    _Bucket("impersonation_findings", "impersonation_findings", "created_at", "alerts_days", has_legal_hold=True),
    _Bucket("mobile_app_findings", "mobile_app_findings", "created_at", "alerts_days", has_legal_hold=True),
    _Bucket("fraud_findings", "fraud_findings", "detected_at", "alerts_days", has_legal_hold=True),
    _Bucket("notification_deliveries", "notification_deliveries", "created_at", "alerts_days"),
    _Bucket("asset_changes", "asset_changes", "detected_at", "alerts_days"),
    _Bucket("triage_runs", "triage_runs", "created_at", "alerts_days"),
    _Bucket("vulnerability_scans", "vulnerability_scans", "completed_at", "alerts_days"),
    _Bucket("actor_sightings", "actor_sightings", "observed_at", "alerts_days"),
    _Bucket("threat_feed_entries", "threat_feed_entries", "first_seen_at", "alerts_days"),
    _Bucket("logo_matches", "logo_matches", "matched_at", "alerts_days"),
    _Bucket("onboarding_sessions", "onboarding_sessions", "created_at", "alerts_days"),
    _Bucket("discovery_jobs", "discovery_jobs", "created_at", "alerts_days"),
    _Bucket("feed_health", "feed_health", "observed_at", "alerts_days", has_legal_hold=False),
)


async def _prune_bucket(
    db: AsyncSession, bucket: _Bucket, cutoff: datetime
) -> int:
    """Run ``DELETE FROM <table> WHERE <ts> < :cutoff [AND legal_hold = false]``.

    Returns the number of rows deleted, or 0 if the table doesn't
    exist on this database (silently swallowed because some Phase 1+
    tables are conditionally created depending on which features
    were provisioned in alembic).
    """
    from sqlalchemy import text as _text

    legal_clause = " AND legal_hold = false" if bucket.has_legal_hold else ""
    sql = _text(
        f"DELETE FROM {bucket.table} WHERE {bucket.timestamp_column} < :cutoff{legal_clause}"
    )
    try:
        result = await db.execute(sql, {"cutoff": cutoff})
        return int(result.rowcount or 0)
    except Exception as exc:  # noqa: BLE001
        # The most common cause is "table doesn't exist" on a partial
        # alembic head. Log loudly and continue so one missing table
        # doesn't abort the whole cleanup.
        logger.warning(
            "retention: pruning %s failed (%s); skipping",
            bucket.table, type(exc).__name__,
        )
        return 0


async def _purge_evidence_blobs(
    db: AsyncSession, cutoff: datetime
) -> tuple[int, int, int]:
    """Hard-delete soft-deleted ``EvidenceBlob`` rows older than ``cutoff``.

    For each blob being purged, we also delete the underlying object
    from MinIO. Deletion happens *before* the row is removed so a
    storage failure leaves the row in place (the next cleanup will
    retry); the caller's audit log shows ``minio_object_purge_errors``
    so a chronic problem surfaces.

    Returns ``(rows_purged, objects_purged, errors)``.
    """
    from src.models.evidence import EvidenceBlob
    from src.storage.evidence_store import evidence_store

    rows = (
        await db.execute(
            select(EvidenceBlob).where(
                and_(
                    EvidenceBlob.is_deleted.is_(True),
                    EvidenceBlob.deleted_at.isnot(None),
                    EvidenceBlob.deleted_at < cutoff,
                    EvidenceBlob.legal_hold.is_(False),
                )
            )
        )
    ).scalars().all()

    objects_purged = 0
    errors = 0
    for blob in rows:
        try:
            evidence_store.delete(blob.s3_bucket, blob.s3_key)
            objects_purged += 1
        except Exception as exc:  # noqa: BLE001
            errors += 1
            logger.error(
                "retention: failed to purge MinIO object %s/%s: %s",
                blob.s3_bucket, blob.s3_key, exc,
            )
            # Skip the row delete so the next run retries.
            continue
        await db.delete(blob)

    return len(rows) - errors, objects_purged, errors


async def run_cleanup(db: AsyncSession, policy: RetentionPolicy) -> CleanupResult:
    """Execute data retention cleanup against ``policy``.

    Handles every per-event-growth table. ``legal_hold`` rows are
    never deleted. Soft-deleted ``EvidenceBlob`` rows trigger MinIO
    object deletion before the row is purged.
    """
    now = datetime.now(timezone.utc)
    cutoff_raw = now - timedelta(days=policy.raw_intel_days)
    cutoff_alerts = now - timedelta(days=policy.alerts_days)
    cutoff_audit = now - timedelta(days=policy.audit_logs_days)
    cutoff_iocs = now - timedelta(days=policy.iocs_days)

    # Core tables (handled inline because their model imports are
    # already cheap and we want explicit ORM-level deletes).
    raw_deleted = (
        await db.execute(
            delete(RawIntel).where(
                and_(
                    RawIntel.created_at < cutoff_raw,
                    RawIntel.legal_hold.is_(False),
                )
            )
        )
    ).rowcount
    alerts_deleted = (
        await db.execute(
            delete(Alert).where(
                and_(
                    Alert.created_at < cutoff_alerts,
                    Alert.legal_hold.is_(False),
                )
            )
        )
    ).rowcount
    audit_deleted = (
        await db.execute(
            delete(AuditLog).where(
                and_(
                    AuditLog.timestamp < cutoff_audit,
                    AuditLog.legal_hold.is_(False),
                )
            )
        )
    ).rowcount
    iocs_deleted = (
        await db.execute(
            delete(IOC).where(
                and_(
                    IOC.created_at < cutoff_iocs,
                    IOC.legal_hold.is_(False),
                )
            )
        )
    ).rowcount

    from src.models.news import NewsArticle
    from src.models.live_probe import LiveProbe
    from src.models.leakage import DlpFinding, CardLeakageFinding
    from src.models.dmarc import DmarcReport
    from src.models.sla import SlaBreachEvent

    news_deleted = (
        await db.execute(
            delete(NewsArticle).where(
                and_(
                    NewsArticle.fetched_at < cutoff_alerts,
                    NewsArticle.legal_hold.is_(False),
                )
            )
        )
    ).rowcount
    probes_deleted = (
        await db.execute(
            delete(LiveProbe).where(
                and_(
                    LiveProbe.created_at < cutoff_alerts,
                    LiveProbe.legal_hold.is_(False),
                )
            )
        )
    ).rowcount
    dlp_deleted = (
        await db.execute(
            delete(DlpFinding).where(
                and_(
                    DlpFinding.created_at < cutoff_alerts,
                    DlpFinding.legal_hold.is_(False),
                )
            )
        )
    ).rowcount
    cc_deleted = (
        await db.execute(
            delete(CardLeakageFinding).where(
                and_(
                    CardLeakageFinding.created_at < cutoff_alerts,
                    CardLeakageFinding.legal_hold.is_(False),
                )
            )
        )
    ).rowcount
    dmarc_deleted = (
        await db.execute(
            delete(DmarcReport).where(
                and_(
                    DmarcReport.created_at < cutoff_alerts,
                    DmarcReport.legal_hold.is_(False),
                )
            )
        )
    ).rowcount
    sla_breach_deleted = (
        await db.execute(
            delete(SlaBreachEvent).where(
                and_(
                    SlaBreachEvent.created_at < cutoff_audit,
                    SlaBreachEvent.legal_hold.is_(False),
                )
            )
        )
    ).rowcount

    # Detector / per-event growth tables. Deleted via raw DELETE so we
    # don't have to import every ORM model.
    bucket_results: dict[str, int] = {}
    bucket_cutoffs = {
        "alerts_days": cutoff_alerts,
        "audit_logs_days": cutoff_audit,
        "iocs_days": cutoff_iocs,
        "raw_intel_days": cutoff_raw,
    }
    for bucket in _DETECTOR_BUCKETS:
        cutoff = bucket_cutoffs[bucket.bucket_days_attr]
        bucket_results[bucket.label] = await _prune_bucket(db, bucket, cutoff)

    # MinIO blob purge — only on rows soft-deleted longer than
    # ``audit_logs_days`` ago (gives the analyst a recovery window).
    blob_rows, minio_purged, minio_errors = await _purge_evidence_blobs(
        db, cutoff_audit
    )

    policy.last_cleanup_at = now
    await db.flush()

    total = (
        raw_deleted + alerts_deleted + audit_deleted + iocs_deleted
        + news_deleted + probes_deleted + dlp_deleted + cc_deleted
        + dmarc_deleted + sla_breach_deleted
        + sum(bucket_results.values())
        + blob_rows
    )

    return CleanupResult(
        raw_intel_deleted=raw_deleted,
        alerts_deleted=alerts_deleted,
        audit_logs_deleted=audit_deleted,
        iocs_deleted=iocs_deleted,
        news_articles_deleted=news_deleted,
        live_probes_deleted=probes_deleted,
        dlp_findings_deleted=dlp_deleted,
        card_leakage_findings_deleted=cc_deleted,
        dmarc_reports_deleted=dmarc_deleted,
        sla_breach_events_deleted=sla_breach_deleted,
        exposure_findings_deleted=bucket_results.get("exposure_findings", 0),
        suspect_domains_deleted=bucket_results.get("suspect_domains", 0),
        discovery_findings_deleted=bucket_results.get("discovery_findings", 0),
        impersonation_findings_deleted=bucket_results.get("impersonation_findings", 0),
        mobile_app_findings_deleted=bucket_results.get("mobile_app_findings", 0),
        fraud_findings_deleted=bucket_results.get("fraud_findings", 0),
        notification_deliveries_deleted=bucket_results.get("notification_deliveries", 0),
        asset_changes_deleted=bucket_results.get("asset_changes", 0),
        triage_runs_deleted=bucket_results.get("triage_runs", 0),
        vulnerability_scans_deleted=bucket_results.get("vulnerability_scans", 0),
        actor_sightings_deleted=bucket_results.get("actor_sightings", 0),
        threat_feed_entries_deleted=bucket_results.get("threat_feed_entries", 0),
        logo_matches_deleted=bucket_results.get("logo_matches", 0),
        onboarding_sessions_deleted=bucket_results.get("onboarding_sessions", 0),
        discovery_jobs_deleted=bucket_results.get("discovery_jobs", 0),
        feed_health_deleted=bucket_results.get("feed_health", 0),
        evidence_blobs_purged=blob_rows,
        minio_objects_purged=minio_purged,
        minio_object_purge_errors=minio_errors,
        total_deleted=total,
        policy_id=policy.id,
        cleanup_at=now,
    )


# --- Audit G4 — legal hold ---------------------------------------------


class LegalHoldRequest(BaseModel):
    """Generic legal-hold flip applicable to any of the held tables."""

    resource_type: str
    resource_id: uuid.UUID
    hold: bool
    reason: str = ""


# Every table that carries a ``legal_hold`` boolean column. Adding a
# new table here requires no other code changes — the API endpoint
# below dispatches to whatever the operator names.
_HOLD_TABLES: dict[str, tuple[str, str]] = {
    "evidence_blob": ("evidence_blobs", "id"),
    "case": ("cases", "id"),
    "audit_log": ("audit_logs", "id"),
    "alert": ("alerts", "id"),
    "raw_intel": ("raw_intel", "id"),
    "ioc": ("iocs", "id"),
    "exposure_finding": ("exposure_findings", "id"),
    "suspect_domain": ("suspect_domains", "id"),
    "impersonation_finding": ("impersonation_findings", "id"),
    "mobile_app_finding": ("mobile_app_findings", "id"),
    "fraud_finding": ("fraud_findings", "id"),
    "card_leakage_finding": ("card_leakage_findings", "id"),
    "dlp_finding": ("dlp_findings", "id"),
    "dmarc_report": ("dmarc_reports", "id"),
    "sla_breach_event": ("sla_breach_events", "id"),
    "news_article": ("news_articles", "id"),
    "live_probe": ("live_probes", "id"),
}


@router.post("/legal-hold", status_code=204)
async def set_legal_hold(
    body: LegalHoldRequest,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Flip the ``legal_hold`` boolean on any of the legal-holdable
    tables. While true, retention refuses to delete the row even after
    the configured window has elapsed.

    Admin only — the flip is itself audit-logged with before/after.
    """
    if body.resource_type not in _HOLD_TABLES:
        raise HTTPException(
            400,
            f"resource_type must be one of {sorted(_HOLD_TABLES)}",
        )
    table, pk = _HOLD_TABLES[body.resource_type]
    from sqlalchemy import text as _text

    # First read the current state so we can record before/after.
    pre = await db.execute(
        _text(f"SELECT legal_hold FROM {table} WHERE {pk} = :id"),
        {"id": body.resource_id},
    )
    pre_row = pre.first()
    if pre_row is None:
        raise HTTPException(404, f"{body.resource_type} not found")
    before_value = bool(pre_row[0])

    await db.execute(
        _text(f"UPDATE {table} SET legal_hold = :h WHERE {pk} = :id"),
        {"h": body.hold, "id": body.resource_id},
    )

    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=admin,
        resource_type=body.resource_type,
        resource_id=str(body.resource_id),
        before={"legal_hold": before_value},
        after={"legal_hold": body.hold},
        details={"reason": body.reason or None},
    )
    await db.commit()


# --- Routes ------------------------------------------------------------


@router.get("/", response_model=list[RetentionPolicyResponse])
async def list_retention_policies(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """List all retention policies (global + per-org)."""
    query = select(RetentionPolicy).order_by(
        RetentionPolicy.organization_id.is_(None).desc(),
        RetentionPolicy.created_at,
    )
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/", response_model=RetentionPolicyResponse, status_code=201)
async def create_retention_policy(
    body: RetentionPolicyCreate,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Create the retention policy. Single-tenant: only one row exists
    (organization_id is the system org or NULL for the global default)."""
    from src.core.tenant import get_system_org_id

    sys_org_id = None
    try:
        sys_org_id = await get_system_org_id(db)
    except Exception:
        pass

    target_org = body.organization_id
    if target_org is not None and sys_org_id is not None and target_org != sys_org_id:
        raise HTTPException(
            403,
            "Cannot create retention policy for an organisation other than the system tenant",
        )

    existing = (
        await db.execute(
            select(RetentionPolicy).where(
                RetentionPolicy.organization_id == target_org
            )
        )
    ).scalar_one_or_none()
    if existing:
        scope = (
            f"organization {target_org}" if target_org else "global"
        )
        raise HTTPException(
            409,
            f"Retention policy already exists for {scope}. Use PATCH to update.",
        )

    policy = RetentionPolicy(
        organization_id=target_org,
        raw_intel_days=body.raw_intel_days,
        alerts_days=body.alerts_days,
        audit_logs_days=body.audit_logs_days,
        iocs_days=body.iocs_days,
        redact_pii=body.redact_pii,
        auto_cleanup_enabled=body.auto_cleanup_enabled,
    )
    db.add(policy)
    await db.flush()

    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=user,
        resource_type="retention_policy",
        resource_id=str(policy.id),
        before=None,
        after={
            "raw_intel_days": policy.raw_intel_days,
            "alerts_days": policy.alerts_days,
            "audit_logs_days": policy.audit_logs_days,
            "iocs_days": policy.iocs_days,
            "redact_pii": policy.redact_pii,
            "auto_cleanup_enabled": policy.auto_cleanup_enabled,
            "organization_id": str(target_org) if target_org else None,
        },
    )
    await db.commit()
    await db.refresh(policy)
    return policy


@router.patch("/{policy_id}", response_model=RetentionPolicyResponse)
async def update_retention_policy(
    policy_id: uuid.UUID,
    body: RetentionPolicyUpdate,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Update a retention policy."""
    from src.core.tenant import get_system_org_id

    policy = await db.get(RetentionPolicy, policy_id)
    if not policy:
        raise HTTPException(404, "Retention policy not found")

    if policy.organization_id is not None:
        sys_org_id = None
        try:
            sys_org_id = await get_system_org_id(db)
        except Exception:
            pass
        if sys_org_id is not None and policy.organization_id != sys_org_id:
            raise HTTPException(
                403,
                "Cannot update retention policy of another organisation",
            )

    before_state = {
        "raw_intel_days": policy.raw_intel_days,
        "alerts_days": policy.alerts_days,
        "audit_logs_days": policy.audit_logs_days,
        "iocs_days": policy.iocs_days,
        "redact_pii": policy.redact_pii,
        "auto_cleanup_enabled": policy.auto_cleanup_enabled,
    }
    update_data = body.model_dump(exclude_unset=True)
    after_state: dict = {}
    for field, value in update_data.items():
        if getattr(policy, field) != value:
            setattr(policy, field, value)
            after_state[field] = value

    if after_state:
        await audit_log(
            db,
            AuditAction.SETTINGS_UPDATE,
            user=user,
            resource_type="retention_policy",
            resource_id=str(policy_id),
            before={k: before_state[k] for k in after_state},
            after=after_state,
        )

    await db.commit()
    await db.refresh(policy)
    return policy


@router.delete("/{policy_id}", status_code=204)
async def delete_retention_policy(
    policy_id: uuid.UUID,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Delete a retention policy. Falls back to global default."""
    policy = await db.get(RetentionPolicy, policy_id)
    if not policy:
        raise HTTPException(404, "Retention policy not found")

    if policy.organization_id is None:
        raise HTTPException(
            400, "Cannot delete the global retention policy. Update it instead."
        )

    before_state = {
        "raw_intel_days": policy.raw_intel_days,
        "alerts_days": policy.alerts_days,
        "audit_logs_days": policy.audit_logs_days,
        "iocs_days": policy.iocs_days,
        "redact_pii": policy.redact_pii,
        "auto_cleanup_enabled": policy.auto_cleanup_enabled,
        "organization_id": str(policy.organization_id),
    }
    await db.delete(policy)

    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=user,
        resource_type="retention_policy",
        resource_id=str(policy_id),
        before=before_state,
        after=None,
    )
    await db.commit()


@router.post("/cleanup", response_model=list[CleanupResult])
async def trigger_cleanup(
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Trigger manual data retention cleanup across all active policies."""
    query = select(RetentionPolicy).where(
        RetentionPolicy.auto_cleanup_enabled.is_(True)
    )
    policies = (await db.execute(query)).scalars().all()
    if not policies:
        raise HTTPException(404, "No active retention policies found")

    results = []
    for policy in policies:
        cleanup_result = await run_cleanup(db, policy)
        results.append(cleanup_result)

    await audit_log(
        db,
        AuditAction.RETENTION_CLEANUP,
        user=user,
        resource_type="retention_policy",
        details={
            "policies_processed": len(results),
            "total_deleted": sum(r.total_deleted for r in results),
            "minio_objects_purged": sum(r.minio_objects_purged for r in results),
            "minio_object_purge_errors": sum(r.minio_object_purge_errors for r in results),
        },
    )

    await db.commit()
    return results


@router.get("/stats", response_model=RetentionStats)
async def retention_stats(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Show what would be cleaned up: counts and date ranges by table."""
    policy = (
        await db.execute(
            select(RetentionPolicy)
            .order_by(RetentionPolicy.organization_id.is_(None).asc())
            .limit(1)
        )
    ).scalar_one_or_none()

    raw_days = policy.raw_intel_days if policy else 90
    alerts_days = policy.alerts_days if policy else 365
    audit_days = policy.audit_logs_days if policy else 730
    iocs_days = policy.iocs_days if policy else 365

    now = datetime.now(timezone.utc)

    raw_count = (await db.execute(select(func.count()).select_from(RawIntel))).scalar() or 0
    raw_oldest = (await db.execute(select(func.min(RawIntel.created_at)))).scalar()
    raw_cutoff = now - timedelta(days=raw_days)
    raw_would_delete = (
        await db.execute(
            select(func.count())
            .select_from(RawIntel)
            .where(RawIntel.created_at < raw_cutoff)
        )
    ).scalar() or 0

    alerts_count = (await db.execute(select(func.count()).select_from(Alert))).scalar() or 0
    alerts_oldest = (await db.execute(select(func.min(Alert.created_at)))).scalar()
    alerts_cutoff = now - timedelta(days=alerts_days)
    alerts_would_delete = (
        await db.execute(
            select(func.count())
            .select_from(Alert)
            .where(Alert.created_at < alerts_cutoff)
        )
    ).scalar() or 0

    audit_count = (await db.execute(select(func.count()).select_from(AuditLog))).scalar() or 0
    audit_oldest = (await db.execute(select(func.min(AuditLog.timestamp)))).scalar()
    audit_cutoff = now - timedelta(days=audit_days)
    audit_would_delete = (
        await db.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.timestamp < audit_cutoff)
        )
    ).scalar() or 0

    iocs_count = (await db.execute(select(func.count()).select_from(IOC))).scalar() or 0
    iocs_oldest = (await db.execute(select(func.min(IOC.created_at)))).scalar()
    iocs_cutoff = now - timedelta(days=iocs_days)
    iocs_would_delete = (
        await db.execute(
            select(func.count())
            .select_from(IOC)
            .where(IOC.created_at < iocs_cutoff)
        )
    ).scalar() or 0

    return RetentionStats(
        raw_intel_count=raw_count,
        raw_intel_oldest=raw_oldest,
        raw_intel_would_delete=raw_would_delete,
        alerts_count=alerts_count,
        alerts_oldest=alerts_oldest,
        alerts_would_delete=alerts_would_delete,
        audit_logs_count=audit_count,
        audit_logs_oldest=audit_oldest,
        audit_logs_would_delete=audit_would_delete,
        iocs_count=iocs_count,
        iocs_oldest=iocs_oldest,
        iocs_would_delete=iocs_would_delete,
    )
