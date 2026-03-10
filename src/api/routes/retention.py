"""Data retention management endpoints."""

import uuid
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, delete, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser, CurrentUser, audit_log
from src.models.auth import AuditAction, AuditLog
from src.models.intel import IOC, RetentionPolicy
from src.models.threat import Alert, RawIntel
from src.storage.database import get_session

router = APIRouter(prefix="/retention", tags=["retention"])


# --- Schemas ---


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
    raw_intel_deleted: int
    alerts_deleted: int
    audit_logs_deleted: int
    iocs_deleted: int
    total_deleted: int
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


# --- Cleanup Engine ---


async def run_cleanup(db: AsyncSession, policy: RetentionPolicy) -> CleanupResult:
    """Execute data retention cleanup based on the given policy. Deletes old records."""
    now = datetime.now(timezone.utc)

    cutoff_raw = now - timedelta(days=policy.raw_intel_days)
    cutoff_alerts = now - timedelta(days=policy.alerts_days)
    cutoff_audit = now - timedelta(days=policy.audit_logs_days)
    cutoff_iocs = now - timedelta(days=policy.iocs_days)

    # Delete old raw intel
    raw_result = await db.execute(
        delete(RawIntel).where(RawIntel.created_at < cutoff_raw)
    )
    raw_deleted = raw_result.rowcount

    # Delete old alerts
    alerts_result = await db.execute(
        delete(Alert).where(Alert.created_at < cutoff_alerts)
    )
    alerts_deleted = alerts_result.rowcount

    # Delete old audit logs
    audit_result = await db.execute(
        delete(AuditLog).where(AuditLog.timestamp < cutoff_audit)
    )
    audit_deleted = audit_result.rowcount

    # Delete old IOCs
    iocs_result = await db.execute(
        delete(IOC).where(IOC.created_at < cutoff_iocs)
    )
    iocs_deleted = iocs_result.rowcount

    # Update policy last_cleanup_at
    policy.last_cleanup_at = now
    await db.flush()

    return CleanupResult(
        raw_intel_deleted=raw_deleted,
        alerts_deleted=alerts_deleted,
        audit_logs_deleted=audit_deleted,
        iocs_deleted=iocs_deleted,
        total_deleted=raw_deleted + alerts_deleted + audit_deleted + iocs_deleted,
        policy_id=policy.id,
        cleanup_at=now,
    )


# --- Routes ---


@router.get("/", response_model=list[RetentionPolicyResponse])
async def list_retention_policies(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """List all retention policies (global + per-org)."""
    query = select(RetentionPolicy).order_by(RetentionPolicy.organization_id.is_(None).desc(), RetentionPolicy.created_at)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/", response_model=RetentionPolicyResponse, status_code=201)
async def create_retention_policy(
    body: RetentionPolicyCreate,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Create a retention policy for an organization (or global if org_id is null)."""
    # Check for existing policy for the same org
    existing_q = select(RetentionPolicy).where(
        RetentionPolicy.organization_id == body.organization_id
    )
    existing = (await db.execute(existing_q)).scalar_one_or_none()
    if existing:
        scope = f"organization {body.organization_id}" if body.organization_id else "global"
        raise HTTPException(409, f"Retention policy already exists for {scope}. Use PATCH to update.")

    policy = RetentionPolicy(
        organization_id=body.organization_id,
        raw_intel_days=body.raw_intel_days,
        alerts_days=body.alerts_days,
        audit_logs_days=body.audit_logs_days,
        iocs_days=body.iocs_days,
        redact_pii=body.redact_pii,
        auto_cleanup_enabled=body.auto_cleanup_enabled,
    )
    db.add(policy)

    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=user,
        resource_type="retention_policy",
        resource_id=str(policy.id),
        details={
            "action": "create",
            "organization_id": str(body.organization_id) if body.organization_id else "global",
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
    policy = await db.get(RetentionPolicy, policy_id)
    if not policy:
        raise HTTPException(404, "Retention policy not found")

    changes = {}
    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        old_value = getattr(policy, field)
        if old_value != value:
            setattr(policy, field, value)
            changes[field] = {"old": str(old_value), "new": str(value)}

    if changes:
        await audit_log(
            db,
            AuditAction.SETTINGS_UPDATE,
            user=user,
            resource_type="retention_policy",
            resource_id=str(policy_id),
            details=changes,
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
        raise HTTPException(400, "Cannot delete the global retention policy. Update it instead.")

    await db.delete(policy)

    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=user,
        resource_type="retention_policy",
        resource_id=str(policy_id),
        details={"action": "delete", "organization_id": str(policy.organization_id)},
    )

    await db.commit()


@router.post("/cleanup", response_model=list[CleanupResult])
async def trigger_cleanup(
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Trigger manual data retention cleanup across all active policies."""
    query = select(RetentionPolicy).where(RetentionPolicy.auto_cleanup_enabled == True)
    result = await db.execute(query)
    policies = result.scalars().all()

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
    # Get the effective policy (global fallback)
    policy_q = select(RetentionPolicy).order_by(
        RetentionPolicy.organization_id.is_(None).asc()
    ).limit(1)
    policy = (await db.execute(policy_q)).scalar_one_or_none()

    # Use defaults if no policy exists
    raw_days = policy.raw_intel_days if policy else 90
    alerts_days = policy.alerts_days if policy else 365
    audit_days = policy.audit_logs_days if policy else 730
    iocs_days = policy.iocs_days if policy else 365

    now = datetime.now(timezone.utc)

    # Raw Intel stats
    raw_count = (await db.execute(select(func.count()).select_from(RawIntel))).scalar() or 0
    raw_oldest = (await db.execute(select(func.min(RawIntel.created_at)))).scalar()
    raw_cutoff = now - timedelta(days=raw_days)
    raw_would_delete = (await db.execute(
        select(func.count()).select_from(RawIntel).where(RawIntel.created_at < raw_cutoff)
    )).scalar() or 0

    # Alerts stats
    alerts_count = (await db.execute(select(func.count()).select_from(Alert))).scalar() or 0
    alerts_oldest = (await db.execute(select(func.min(Alert.created_at)))).scalar()
    alerts_cutoff = now - timedelta(days=alerts_days)
    alerts_would_delete = (await db.execute(
        select(func.count()).select_from(Alert).where(Alert.created_at < alerts_cutoff)
    )).scalar() or 0

    # Audit logs stats
    audit_count = (await db.execute(select(func.count()).select_from(AuditLog))).scalar() or 0
    audit_oldest = (await db.execute(select(func.min(AuditLog.timestamp)))).scalar()
    audit_cutoff = now - timedelta(days=audit_days)
    audit_would_delete = (await db.execute(
        select(func.count()).select_from(AuditLog).where(AuditLog.timestamp < audit_cutoff)
    )).scalar() or 0

    # IOCs stats
    iocs_count = (await db.execute(select(func.count()).select_from(IOC))).scalar() or 0
    iocs_oldest = (await db.execute(select(func.min(IOC.created_at)))).scalar()
    iocs_cutoff = now - timedelta(days=iocs_days)
    iocs_would_delete = (await db.execute(
        select(func.count()).select_from(IOC).where(IOC.created_at < iocs_cutoff)
    )).scalar() or 0

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
