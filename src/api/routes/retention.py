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

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser, CurrentUser, audit_log
from src.models.auth import AuditAction, AuditLog
from src.models.dsar import DsarRequest
from src.models.intel import IOC, RetentionPolicy
from src.models.learnings import LearningsLog
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
    deletion_mode: str = "hard_delete"
    compliance_mappings: list[str] = []
    description: str | None = None


class RetentionPolicyUpdate(BaseModel):
    raw_intel_days: int | None = None
    alerts_days: int | None = None
    audit_logs_days: int | None = None
    iocs_days: int | None = None
    redact_pii: bool | None = None
    auto_cleanup_enabled: bool | None = None
    deletion_mode: str | None = None
    compliance_mappings: list[str] | None = None
    description: str | None = None


class RetentionPolicyResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    raw_intel_days: int
    alerts_days: int
    audit_logs_days: int
    iocs_days: int
    redact_pii: bool
    auto_cleanup_enabled: bool
    deletion_mode: str
    compliance_mappings: list[str]
    description: str | None
    last_cleanup_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# --- Compliance frameworks catalog ----------------------------------------
#
# Single source of truth for retention regulatory mappings. Used to validate
# RetentionPolicy.compliance_mappings, drive the dashboard multi-select, and
# fed into Bridge prompts (regulation translator + attestation generator).
DELETION_MODES = ("hard_delete", "soft_delete", "anonymise")

COMPLIANCE_FRAMEWORKS: list[dict] = [
    {
        "id": "gdpr_art_5_1_e",
        "name": "GDPR Art.5(1)(e) — Storage Limitation",
        "full_text": (
            "Personal data shall be kept in a form which permits identification "
            "of data subjects for no longer than is necessary for the purposes "
            "for which the personal data are processed."
        ),
        "default_retention_days": 365,
        "citation_url": "https://gdpr-info.eu/art-5-gdpr/",
    },
    {
        "id": "gdpr_art_17",
        "name": "GDPR Art.17 — Right to Erasure (\"Right to be Forgotten\")",
        "full_text": (
            "The data subject shall have the right to obtain from the controller "
            "the erasure of personal data concerning him or her without undue "
            "delay; the controller shall have the obligation to erase personal "
            "data without undue delay."
        ),
        "default_retention_days": 30,
        "citation_url": "https://gdpr-info.eu/art-17-gdpr/",
    },
    {
        "id": "ccpa_1798_105",
        "name": "CCPA §1798.105 — Right to Delete",
        "full_text": (
            "A consumer shall have the right to request that a business delete "
            "any personal information about the consumer which the business has "
            "collected from the consumer."
        ),
        "default_retention_days": 45,
        "citation_url": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.105",
    },
    {
        "id": "hipaa_164_530_j",
        "name": "HIPAA §164.530(j) — Documentation Retention",
        "full_text": (
            "A covered entity must retain the documentation required by this "
            "section for six years from the date of its creation or the date "
            "when it last was in effect, whichever is later."
        ),
        "default_retention_days": 2190,  # 6 years
        "citation_url": "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.530",
    },
    {
        "id": "pci_dss_3_1",
        "name": "PCI-DSS 3.1 — Data Retention and Disposal",
        "full_text": (
            "Keep cardholder data storage to a minimum by implementing data "
            "retention and disposal policies, procedures and processes that "
            "include coverage for all cardholder data storage."
        ),
        "default_retention_days": 365,
        "citation_url": "https://www.pcisecuritystandards.org/document_library",
    },
    {
        "id": "sox_240_17a_4",
        "name": "SOX 17 CFR §240.17a-4 — Books and Records",
        "full_text": (
            "Every member, broker, and dealer subject to §240.17a-3 shall "
            "preserve for a period of not less than six years, the first two "
            "years in an easily accessible place, all records required to be "
            "made pursuant to §240.17a-3."
        ),
        "default_retention_days": 2190,  # 6 years
        "citation_url": "https://www.ecfr.gov/current/title-17/chapter-II/part-240/subject-group-ECFR4d829fadc465f08/section-240.17a-4",
    },
    {
        "id": "dora_art_6",
        "name": "DORA Art.6 — ICT Risk Management Framework",
        "full_text": (
            "Financial entities shall have a sound, comprehensive and "
            "well-documented ICT risk management framework, including "
            "retention of ICT-related incident records for at least five years."
        ),
        "default_retention_days": 1825,  # 5 years
        "citation_url": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2554",
    },
    {
        "id": "iso_27040",
        "name": "ISO/IEC 27040 — Storage Security",
        "full_text": (
            "Storage media containing sensitive data shall be sanitised in "
            "accordance with documented procedures prior to disposal, reuse, "
            "or release from organisational control."
        ),
        "default_retention_days": 365,
        "citation_url": "https://www.iso.org/standard/44404.html",
    },
    {
        "id": "nist_sp_800_88",
        "name": "NIST SP 800-88 Rev.1 — Media Sanitisation",
        "full_text": (
            "Information disposed of and media sanitised shall be properly "
            "categorised, the appropriate sanitisation method selected, and "
            "verification of sanitisation performed."
        ),
        "default_retention_days": 365,
        "citation_url": "https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final",
    },
]
_FRAMEWORK_IDS = {f["id"] for f in COMPLIANCE_FRAMEWORKS}


def _validate_mappings(mappings: list[str] | None) -> list[str]:
    if not mappings:
        return []
    bad = [m for m in mappings if m not in _FRAMEWORK_IDS]
    if bad:
        raise HTTPException(
            400,
            f"Unknown compliance mappings: {bad}. "
            f"Allowed: {sorted(_FRAMEWORK_IDS)}",
        )
    return list(dict.fromkeys(mappings))


def _validate_deletion_mode(mode: str | None) -> str:
    if mode is None:
        return "hard_delete"
    if mode not in DELETION_MODES:
        raise HTTPException(
            400,
            f"deletion_mode must be one of {DELETION_MODES}",
        )
    return mode


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
    dry_run: bool = False


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
    db: AsyncSession, bucket: _Bucket, cutoff: datetime, dry_run: bool = False
) -> int:
    """Run ``DELETE FROM <table> WHERE <ts> < :cutoff [AND legal_hold = false]``.

    Returns the number of rows deleted (or counted, if dry_run), or 0 if
    the table doesn't exist on this database (silently swallowed because
    some Phase 1+ tables are conditionally created depending on which
    features were provisioned in alembic).
    """
    from sqlalchemy import text as _text

    legal_clause = " AND legal_hold = false" if bucket.has_legal_hold else ""
    if dry_run:
        sql = _text(
            f"SELECT COUNT(*) FROM {bucket.table} "
            f"WHERE {bucket.timestamp_column} < :cutoff{legal_clause}"
        )
        try:
            async with db.begin_nested():
                result = await db.execute(sql, {"cutoff": cutoff})
                return int(result.scalar() or 0)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "retention(dry-run): counting %s failed (%s); skipping",
                bucket.table, type(exc).__name__,
            )
            return 0
    sql = _text(
        f"DELETE FROM {bucket.table} WHERE {bucket.timestamp_column} < :cutoff{legal_clause}"
    )
    try:
        async with db.begin_nested():
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
    from src.storage import evidence_store as _es

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
            _es.delete(blob.s3_bucket, blob.s3_key)
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


async def _count_or_delete_raw(
    db: AsyncSession,
    table: str,
    ts_col: str,
    cutoff: datetime,
    has_legal_hold: bool,
    dry_run: bool,
) -> int:
    """Count or delete rows older than ``cutoff`` from ``table``.

    Uses raw parameterised SQL because some tables carry a
    ``legal_hold`` column at the database level that isn't declared on
    the ORM model (RawIntel, Alert, AuditLog, IOC, NewsArticle,
    LiveProbe, DLP findings, etc — alembic added the column, the model
    file wasn't updated). Going via SQL also keeps the cleanup engine
    indifferent to ORM drift.

    Each call runs inside a SAVEPOINT so that a missing table /
    missing column on a partially-migrated database doesn't poison the
    enclosing cleanup transaction.
    """
    from sqlalchemy import text as _text

    legal_clause = " AND legal_hold = false" if has_legal_hold else ""
    if dry_run:
        sql = _text(
            f"SELECT COUNT(*) FROM {table} "
            f"WHERE {ts_col} < :cutoff{legal_clause}"
        )
        try:
            async with db.begin_nested():
                return int(
                    (await db.execute(sql, {"cutoff": cutoff})).scalar() or 0
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "retention(dry-run): count on %s failed (%s); skipping",
                table, type(exc).__name__,
            )
            return 0
    sql = _text(
        f"DELETE FROM {table} WHERE {ts_col} < :cutoff{legal_clause}"
    )
    try:
        async with db.begin_nested():
            return int(
                (await db.execute(sql, {"cutoff": cutoff})).rowcount or 0
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "retention: delete on %s failed (%s); skipping",
            table, type(exc).__name__,
        )
        return 0


async def run_cleanup(
    db: AsyncSession,
    policy: RetentionPolicy,
    *,
    dry_run: bool = False,
) -> CleanupResult:
    """Execute data retention cleanup against ``policy``.

    Handles every per-event-growth table. ``legal_hold`` rows are
    never deleted. Soft-deleted ``EvidenceBlob`` rows trigger MinIO
    object deletion before the row is purged.

    When ``dry_run`` is True, no rows are deleted — counts are returned
    so the operator can preview the impact before confirming.
    """
    now = datetime.now(timezone.utc)
    cutoff_raw = now - timedelta(days=policy.raw_intel_days)
    cutoff_alerts = now - timedelta(days=policy.alerts_days)
    cutoff_audit = now - timedelta(days=policy.audit_logs_days)
    cutoff_iocs = now - timedelta(days=policy.iocs_days)

    # Pre-purge knowledge preservation. When redact_pii is set, queue a
    # Bridge-LLM agent task to summarise the about-to-be-deleted raw
    # intel + alerts BEFORE the row goes away, so the wisdom (campaigns,
    # actors, techniques) survives the compliance purge as a PII-free
    # ``learnings_log`` entry. The task enqueues idempotently so a
    # repeat run within the same hour is a no-op.
    if policy.redact_pii and not dry_run:
        try:
            from src.llm.agent_queue import enqueue as _enqueue_agent
            await _enqueue_agent(
                db,
                kind="retention_preserve_knowledge",
                organization_id=policy.organization_id,
                payload={
                    "policy_id": str(policy.id),
                    "cutoff_raw_iso": cutoff_raw.isoformat(),
                    "cutoff_alerts_iso": cutoff_alerts.isoformat(),
                    "deletion_mode": getattr(policy, "deletion_mode", "hard_delete"),
                },
                dedup_key=f"preserve:{policy.id}:{now.date().isoformat()}",
                priority=3,
            )
        except Exception:  # noqa: BLE001 — preservation must not block cleanup
            pass

    raw_deleted = await _count_or_delete_raw(
        db, "raw_intel", "created_at", cutoff_raw, True, dry_run
    )
    alerts_deleted = await _count_or_delete_raw(
        db, "alerts", "created_at", cutoff_alerts, True, dry_run
    )
    audit_deleted = await _count_or_delete_raw(
        db, "audit_logs", "timestamp", cutoff_audit, True, dry_run
    )
    iocs_deleted = await _count_or_delete_raw(
        db, "iocs", "created_at", cutoff_iocs, True, dry_run
    )
    news_deleted = await _count_or_delete_raw(
        db, "news_articles", "fetched_at", cutoff_alerts, True, dry_run
    )
    probes_deleted = await _count_or_delete_raw(
        db, "live_probes", "created_at", cutoff_alerts, True, dry_run
    )
    dlp_deleted = await _count_or_delete_raw(
        db, "dlp_findings", "created_at", cutoff_alerts, True, dry_run
    )
    cc_deleted = await _count_or_delete_raw(
        db, "card_leakage_findings", "created_at",
        cutoff_alerts, True, dry_run,
    )
    dmarc_deleted = await _count_or_delete_raw(
        db, "dmarc_reports", "created_at", cutoff_alerts, True, dry_run
    )
    sla_breach_deleted = await _count_or_delete_raw(
        db, "sla_breach_events", "created_at", cutoff_audit, True, dry_run
    )

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
        bucket_results[bucket.label] = await _prune_bucket(
            db, bucket, cutoff, dry_run=dry_run
        )

    # MinIO blob purge — only on rows soft-deleted longer than
    # ``audit_logs_days`` ago (gives the analyst a recovery window).
    if dry_run:
        from src.models.evidence import EvidenceBlob
        blob_rows = (
            await db.execute(
                select(func.count()).select_from(EvidenceBlob).where(
                    and_(
                        EvidenceBlob.is_deleted.is_(True),
                        EvidenceBlob.deleted_at.isnot(None),
                        EvidenceBlob.deleted_at < cutoff_audit,
                        EvidenceBlob.legal_hold.is_(False),
                    )
                )
            )
        ).scalar() or 0
        minio_purged = 0
        minio_errors = 0
    else:
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
        dry_run=dry_run,
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

    mappings = _validate_mappings(body.compliance_mappings)
    deletion_mode = _validate_deletion_mode(body.deletion_mode)
    policy = RetentionPolicy(
        organization_id=target_org,
        raw_intel_days=body.raw_intel_days,
        alerts_days=body.alerts_days,
        audit_logs_days=body.audit_logs_days,
        iocs_days=body.iocs_days,
        redact_pii=body.redact_pii,
        auto_cleanup_enabled=body.auto_cleanup_enabled,
        deletion_mode=deletion_mode,
        compliance_mappings=mappings,
        description=body.description,
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
            "deletion_mode": policy.deletion_mode,
            "compliance_mappings": policy.compliance_mappings,
            "description": policy.description,
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
        "deletion_mode": policy.deletion_mode,
        "compliance_mappings": list(policy.compliance_mappings or []),
        "description": policy.description,
    }
    update_data = body.model_dump(exclude_unset=True)
    if "compliance_mappings" in update_data:
        update_data["compliance_mappings"] = _validate_mappings(
            update_data["compliance_mappings"]
        )
    if "deletion_mode" in update_data and update_data["deletion_mode"] is not None:
        update_data["deletion_mode"] = _validate_deletion_mode(
            update_data["deletion_mode"]
        )
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
    dry_run: bool = Query(
        False,
        description=(
            "When true, no rows are deleted; counts are returned so the "
            "operator can preview impact before confirming."
        ),
    ),
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
        cleanup_result = await run_cleanup(db, policy, dry_run=dry_run)
        results.append(cleanup_result)

    if dry_run:
        # Don't audit-log a dry-run; just rollback any session changes (none
        # should exist; this is paranoia for any future side-effect added in
        # a counter that accidentally writes).
        await db.rollback()
        return results

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


# --- Compliance frameworks catalog ---------------------------------------


class ComplianceFrameworkOut(BaseModel):
    id: str
    name: str
    full_text: str
    default_retention_days: int
    citation_url: str


@router.get(
    "/compliance-frameworks",
    response_model=list[ComplianceFrameworkOut],
)
async def list_compliance_frameworks(user: CurrentUser):
    """Catalog of supported compliance frameworks for retention mapping."""
    return COMPLIANCE_FRAMEWORKS


# --- DSAR workflow --------------------------------------------------------


_DSAR_REQUEST_TYPES = {
    "access", "erasure", "portability", "rectification", "restriction",
}


class DsarCreate(BaseModel):
    organization_id: uuid.UUID
    subject_email: str | None = None
    subject_name: str | None = None
    subject_phone: str | None = None
    subject_id_other: str | None = None
    request_type: str
    regulation: str | None = None
    notes: str | None = None
    deadline_days: int = 30


class DsarOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    requested_by_user_id: uuid.UUID | None
    subject_email: str | None
    subject_name: str | None
    subject_phone: str | None
    subject_id_other: str | None
    request_type: str
    regulation: str | None
    status: str
    deadline_at: datetime | None
    matched_tables: list[str]
    match_summary: dict
    matched_row_count: int
    draft_response: str | None
    final_response: str | None
    notes: str | None
    closed_reason: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DsarClose(BaseModel):
    closed_reason: str
    final_response: str | None = None


class DsarUpdateDraft(BaseModel):
    draft_response: str


@router.post("/dsar", response_model=DsarOut, status_code=201)
async def create_dsar(
    body: DsarCreate,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Open a Data Subject Access Request. Auto-sets a 30-day deadline."""
    if body.request_type not in _DSAR_REQUEST_TYPES:
        raise HTTPException(
            400,
            f"request_type must be one of {sorted(_DSAR_REQUEST_TYPES)}",
        )
    if not any([body.subject_email, body.subject_name, body.subject_phone, body.subject_id_other]):
        raise HTTPException(
            400, "At least one subject identifier is required",
        )
    now = datetime.now(timezone.utc)
    req = DsarRequest(
        organization_id=body.organization_id,
        requested_by_user_id=getattr(user, "id", None),
        subject_email=(body.subject_email or "").strip().lower() or None,
        subject_name=(body.subject_name or "").strip() or None,
        subject_phone=(body.subject_phone or "").strip() or None,
        subject_id_other=(body.subject_id_other or "").strip() or None,
        request_type=body.request_type,
        regulation=body.regulation,
        status="received",
        deadline_at=now + timedelta(days=max(1, body.deadline_days)),
        matched_tables=[],
        match_summary={},
        matched_row_count=0,
        notes=body.notes,
    )
    db.add(req)
    await db.flush()
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=user,
        resource_type="dsar_request",
        resource_id=str(req.id),
        before=None,
        after={
            "request_type": req.request_type,
            "regulation": req.regulation,
            "subject_email": req.subject_email,
        },
    )
    await db.commit()
    await db.refresh(req)
    return req


@router.get("/dsar", response_model=list[DsarOut])
async def list_dsar(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
    organization_id: uuid.UUID | None = None,
    status: str | None = None,
    limit: int = Query(100, ge=1, le=500),
):
    q = select(DsarRequest).order_by(DsarRequest.created_at.desc()).limit(limit)
    if organization_id:
        q = q.where(DsarRequest.organization_id == organization_id)
    if status:
        q = q.where(DsarRequest.status == status)
    return (await db.execute(q)).scalars().all()


@router.get("/dsar/{dsar_id}", response_model=DsarOut)
async def get_dsar(
    dsar_id: uuid.UUID,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    req = await db.get(DsarRequest, dsar_id)
    if not req:
        raise HTTPException(404, "DSAR request not found")
    return req


@router.post("/dsar/{dsar_id}/scan", response_model=DsarOut)
async def scan_dsar(
    dsar_id: uuid.UUID,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Kick off the DSAR Responder scanner agent. Returns the request row."""
    from src.llm.agent_queue import enqueue as _enqueue_agent

    req = await db.get(DsarRequest, dsar_id)
    if not req:
        raise HTTPException(404, "DSAR request not found")
    req.status = "scanning"
    await db.flush()
    await _enqueue_agent(
        db,
        kind="retention_dsar_scan",
        organization_id=req.organization_id,
        payload={"dsar_id": str(req.id)},
        dedup_key=f"dsar_scan:{req.id}",
        priority=2,
    )
    await db.commit()
    await db.refresh(req)
    return req


@router.post("/dsar/{dsar_id}/draft-response", response_model=DsarOut)
async def draft_dsar_response(
    dsar_id: uuid.UUID,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Kick off the DSAR Responder letter-drafting agent."""
    from src.llm.agent_queue import enqueue as _enqueue_agent

    req = await db.get(DsarRequest, dsar_id)
    if not req:
        raise HTTPException(404, "DSAR request not found")
    await _enqueue_agent(
        db,
        kind="retention_dsar_respond",
        organization_id=req.organization_id,
        payload={"dsar_id": str(req.id)},
        dedup_key=f"dsar_respond:{req.id}",
        priority=2,
    )
    await db.commit()
    await db.refresh(req)
    return req


@router.patch("/dsar/{dsar_id}/draft", response_model=DsarOut)
async def update_dsar_draft(
    dsar_id: uuid.UUID,
    body: DsarUpdateDraft,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Human edit of the LLM-drafted letter before close-out."""
    req = await db.get(DsarRequest, dsar_id)
    if not req:
        raise HTTPException(404, "DSAR request not found")
    req.draft_response = body.draft_response
    await db.commit()
    await db.refresh(req)
    return req


@router.post("/dsar/{dsar_id}/close", response_model=DsarOut)
async def close_dsar(
    dsar_id: uuid.UUID,
    body: DsarClose,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    req = await db.get(DsarRequest, dsar_id)
    if not req:
        raise HTTPException(404, "DSAR request not found")
    req.status = "closed"
    req.closed_reason = body.closed_reason[:120]
    if body.final_response:
        req.final_response = body.final_response
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=user,
        resource_type="dsar_request",
        resource_id=str(req.id),
        before={"status": "open"},
        after={"status": "closed", "closed_reason": req.closed_reason},
    )
    await db.commit()
    await db.refresh(req)
    return req


# --- Regulation translator -----------------------------------------------


class RegulationTranslateBody(BaseModel):
    regulation_text: str
    organization_id: uuid.UUID | None = None


@router.post("/translate-regulation")
async def translate_regulation(
    body: RegulationTranslateBody,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Bridge-LLM call: translate regulation text → suggested policy draft.

    Synchronous because the dashboard wants the result inline. Bridge
    typically replies in 5–20 s. We surface the raw draft to the operator
    so they can save it as a new RetentionPolicy.
    """
    from src.llm.agent_queue import call_bridge
    import json as _json

    if not body.regulation_text or len(body.regulation_text.strip()) < 20:
        raise HTTPException(400, "regulation_text is too short")

    sys_prompt = (
        "You are a data retention compliance translator. Read the regulation "
        "text and recommend retention windows for an enterprise threat "
        "intelligence platform. Output STRICT JSON only — no prose, no "
        "fences. Required keys: alerts_days (int), audit_logs_days (int), "
        "raw_intel_days (int), iocs_days (int), deletion_mode (one of: "
        "hard_delete, soft_delete, anonymise), compliance_mappings (array "
        "of strings, allowed values: " + ", ".join(sorted(_FRAMEWORK_IDS)) + "), "
        "rationale_per_class (object: data_class -> short reason)."
    )
    user_prompt = f"Regulation text:\n---\n{body.regulation_text[:8000]}\n---"
    text, model_id = await call_bridge(sys_prompt, user_prompt)

    parsed: dict = {}
    try:
        parsed = _json.loads(text)
    except Exception:  # noqa: BLE001
        # Try fenced extraction.
        import re as _re
        m = _re.search(r"\{.*\}", text, _re.DOTALL)
        if m:
            try:
                parsed = _json.loads(m.group(0))
            except Exception:  # noqa: BLE001
                parsed = {}

    def _int(v, default):
        try:
            return max(0, int(v))
        except Exception:  # noqa: BLE001
            return default

    suggestion = {
        "alerts_days": _int(parsed.get("alerts_days"), 365),
        "audit_logs_days": _int(parsed.get("audit_logs_days"), 730),
        "raw_intel_days": _int(parsed.get("raw_intel_days"), 90),
        "iocs_days": _int(parsed.get("iocs_days"), 365),
        "deletion_mode": (
            parsed.get("deletion_mode")
            if parsed.get("deletion_mode") in DELETION_MODES
            else "hard_delete"
        ),
        "compliance_mappings": [
            m for m in (parsed.get("compliance_mappings") or [])
            if m in _FRAMEWORK_IDS
        ],
        "rationale_per_class": parsed.get("rationale_per_class") or {},
        "model_id": model_id,
        "raw_response": text[:4000],
    }
    return suggestion


# --- Compliance attestation report ---------------------------------------


class AttestationOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    summary_md: str
    rows_summarised: int
    window_start: datetime | None
    window_end: datetime | None
    model_id: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


@router.post("/attestation", status_code=202)
async def generate_attestation(
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
    organization_id: uuid.UUID | None = None,
    period_days: int = Query(90, ge=1, le=3650),
):
    """Enqueue the attestation generator agent. Polls via /attestations."""
    from src.llm.agent_queue import enqueue as _enqueue_agent

    task = await _enqueue_agent(
        db,
        kind="retention_attestation_generate",
        organization_id=organization_id,
        payload={
            "organization_id": str(organization_id) if organization_id else None,
            "period_days": period_days,
        },
        dedup_key=(
            f"attest:{organization_id or 'global'}:"
            f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}"
        ),
        priority=3,
    )
    return {
        "queued": True,
        "task_id": str(task.id),
        "status": task.status,
        "period_days": period_days,
    }


@router.get("/attestations", response_model=list[AttestationOut])
async def list_attestations(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
    organization_id: uuid.UUID | None = None,
    limit: int = Query(50, ge=1, le=500),
):
    """List past attestation reports (most recent first)."""
    q = (
        select(LearningsLog)
        .where(LearningsLog.source_table == "attestation")
        .order_by(LearningsLog.created_at.desc())
        .limit(limit)
    )
    if organization_id:
        q = q.where(LearningsLog.organization_id == organization_id)
    return (await db.execute(q)).scalars().all()
