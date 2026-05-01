"""Phase 11 — SOC2-friendly audit log export.

Streams the audit log as CSV or NDJSON for compliance handoff. Filters:
    since / until / action / resource_type / user_id / organization_resource

Admin-only.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser
from src.models.auth import AuditLog
from src.storage.database import get_session

router = APIRouter(prefix="/audit/export", tags=["Auth & Identity"])


def _stream_csv(rows: list[AuditLog]):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "id",
            "timestamp",
            "user_id",
            "action",
            "resource_type",
            "resource_id",
            "ip_address",
            "user_agent",
            "details",
        ]
    )
    yield buf.getvalue()
    buf.seek(0)
    buf.truncate()
    for r in rows:
        w.writerow(
            [
                str(r.id),
                r.timestamp.isoformat() if r.timestamp else "",
                str(r.user_id) if r.user_id else "",
                r.action,
                r.resource_type or "",
                r.resource_id or "",
                r.ip_address or "",
                (r.user_agent or "")[:500],
                json.dumps(r.details, default=str) if r.details else "",
            ]
        )
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate()


def _stream_ndjson(rows: list[AuditLog]):
    for r in rows:
        yield json.dumps(
            {
                "id": str(r.id),
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "user_id": str(r.user_id) if r.user_id else None,
                "action": r.action,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "ip_address": r.ip_address,
                "user_agent": r.user_agent,
                "details": r.details,
            },
            default=str,
        ) + "\n"


@router.get("")
async def export_audit_log(
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
    fmt: Annotated[str, Query(pattern="^(csv|ndjson)$")] = "csv",
    since: datetime | None = None,
    until: datetime | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    user_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100_000)] = 10_000,
):
    q = select(AuditLog)
    if since is not None:
        q = q.where(AuditLog.timestamp >= since)
    if until is not None:
        q = q.where(AuditLog.timestamp <= until)
    if action is not None:
        q = q.where(AuditLog.action == action)
    if resource_type is not None:
        q = q.where(AuditLog.resource_type == resource_type)
    if user_id is not None:
        q = q.where(AuditLog.user_id == user_id)
    q = q.order_by(AuditLog.timestamp.asc()).limit(limit)
    rows = list((await db.execute(q)).scalars().all())

    if fmt == "ndjson":
        return StreamingResponse(
            _stream_ndjson(rows),
            media_type="application/x-ndjson",
            headers={
                "Content-Disposition": f'attachment; filename="argus-audit-{datetime.now(timezone.utc).strftime("%Y%m%d")}.ndjson"',
                "X-Argus-Row-Count": str(len(rows)),
            },
        )
    return StreamingResponse(
        _stream_csv(rows),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="argus-audit-{datetime.now(timezone.utc).strftime("%Y%m%d")}.csv"',
            "X-Argus-Row-Count": str(len(rows)),
        },
    )


# --- Audit G1 — SOC2 evidence bundle ---------------------------------


@router.get("/soc2-bundle")
async def soc2_bundle(
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
    since: Annotated[datetime | None, Query()] = None,
    until: Annotated[datetime | None, Query()] = None,
):
    """Stream a ZIP archive of SOC2-relevant evidence: audit log,
    current user roster (email-hashed), retention policies,
    notification channel inventory (no secrets), evidence-vault
    counts, and a metadata blob (git sha + version + window).
    Auditors get one download per control review.

    Each member of the bundle is plain JSON / NDJSON so an auditor
    can grep without unpacking custom tooling.
    """
    import hashlib as _hashlib
    import os
    import zipfile

    from sqlalchemy import func as _func

    from src.models.auth import User
    from src.models.evidence import EvidenceBlob
    from src.models.intel import RetentionPolicy
    from src.models.notifications import NotificationChannel

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. Audit log
        q = select(AuditLog)
        if since is not None:
            q = q.where(AuditLog.timestamp >= since)
        if until is not None:
            q = q.where(AuditLog.timestamp <= until)
        q = q.order_by(AuditLog.timestamp.asc())
        audit_rows = list((await db.execute(q)).scalars().all())

        ndjson_buf = io.StringIO()
        for r in audit_rows:
            ndjson_buf.write(
                json.dumps(
                    {
                        "id": str(r.id),
                        "ts": r.timestamp.isoformat(),
                        "user_id": str(r.user_id) if r.user_id else None,
                        "action": r.action,
                        "resource_type": r.resource_type,
                        "resource_id": r.resource_id,
                        "details": r.details,
                        "ip_address": str(r.ip_address) if r.ip_address else None,
                        "user_agent": r.user_agent,
                    }
                )
                + "\n"
            )
        zf.writestr("audit_log.ndjson", ndjson_buf.getvalue())

        # 2. User roster — emails are SHA-256 hashed (we don't put PII
        # in an evidence bundle that may sit on an auditor's laptop).
        users = list((await db.execute(select(User))).scalars().all())
        zf.writestr(
            "users.json",
            json.dumps(
                [
                    {
                        "id": str(u.id),
                        "email_sha256": _hashlib.sha256(
                            u.email.encode("utf-8")
                        ).hexdigest(),
                        "role": u.role,
                        "is_active": u.is_active,
                        "mfa_enrolled_at": (
                            u.mfa_enrolled_at.isoformat() if u.mfa_enrolled_at else None
                        ),
                        "last_login_at": (
                            u.last_login_at.isoformat() if u.last_login_at else None
                        ),
                        "created_at": u.created_at.isoformat(),
                    }
                    for u in users
                ],
                indent=2,
            ),
        )

        # 3. Retention policies
        policies = list(
            (await db.execute(select(RetentionPolicy))).scalars().all()
        )
        zf.writestr(
            "retention_policies.json",
            json.dumps(
                [
                    {
                        "id": str(p.id),
                        "organization_id": (
                            str(p.organization_id) if p.organization_id else None
                        ),
                        "raw_intel_days": p.raw_intel_days,
                        "alerts_days": p.alerts_days,
                        "audit_logs_days": p.audit_logs_days,
                        "iocs_days": p.iocs_days,
                        "auto_cleanup_enabled": p.auto_cleanup_enabled,
                        "last_cleanup_at": (
                            p.last_cleanup_at.isoformat()
                            if p.last_cleanup_at
                            else None
                        ),
                    }
                    for p in policies
                ],
                indent=2,
            ),
        )

        # 4. Notification channel inventory — kind + name + org only,
        # no secrets.
        channels = list(
            (await db.execute(select(NotificationChannel))).scalars().all()
        )
        zf.writestr(
            "notification_channels.json",
            json.dumps(
                [
                    {
                        "id": str(c.id),
                        "organization_id": str(c.organization_id),
                        "name": c.name,
                        "kind": c.kind,
                        "enabled": c.enabled,
                    }
                    for c in channels
                ],
                indent=2,
            ),
        )

        # 5. Evidence-vault inventory
        ev_count = (
            await db.execute(select(_func.count()).select_from(EvidenceBlob))
        ).scalar() or 0
        ev_oldest = (
            await db.execute(select(_func.min(EvidenceBlob.created_at)))
        ).scalar()
        ev_newest = (
            await db.execute(select(_func.max(EvidenceBlob.created_at)))
        ).scalar()
        zf.writestr(
            "evidence_inventory.json",
            json.dumps(
                {
                    "blob_count": int(ev_count),
                    "oldest": ev_oldest.isoformat() if ev_oldest else None,
                    "newest": ev_newest.isoformat() if ev_newest else None,
                },
                indent=2,
            ),
        )

        # 6. Metadata
        zf.writestr(
            "metadata.json",
            json.dumps(
                {
                    "argus_version": "0.1.0",
                    "git_sha": os.environ.get("ARGUS_GIT_SHA") or "unknown",
                    "exported_at": datetime.now(timezone.utc).isoformat(),
                    "exported_by_user_id": str(admin.id),
                    "window_since": since.isoformat() if since else None,
                    "window_until": until.isoformat() if until else None,
                    "audit_row_count": len(audit_rows),
                },
                indent=2,
            ),
        )

    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="application/zip",
        headers={
            "Content-Disposition": (
                f'attachment; filename="argus-soc2-bundle-'
                f'{datetime.now(timezone.utc).strftime("%Y%m%d")}.zip"'
            ),
        },
    )
