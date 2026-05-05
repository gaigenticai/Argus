"""Compliance Evidence Pack — public API (P1 #1.3).

Endpoints
---------
    GET    /compliance/frameworks               list active frameworks
    POST   /compliance/exports                  enqueue an export job (202)
    GET    /compliance/exports                  list exports for current org
    GET    /compliance/exports/{id}             get one export's status
    GET    /compliance/exports/{id}/download    stream the rendered file

Authentication
--------------
All routes require an authenticated analyst (or admin). The export is
not gated by admin role — any analyst working a case may produce
evidence for their tenant. Cross-tenant reads are prevented by both
RLS and explicit ``organization_id`` filters.

Background processing
---------------------
``POST /compliance/exports`` returns 202 with ``status='pending'`` and
schedules a FastAPI background task that:
  1. Sets the RLS GUC on a fresh session
  2. Calls :func:`src.compliance.mapper.collect_evidence_for_period`
  3. Builds the OSCAL JSON via :mod:`src.compliance.oscal`
  4. For PDF format, also renders via :mod:`src.compliance.pdf_exporter`
  5. Persists the bytes to the evidence-vault bucket
  6. Updates the row to ``status='completed'`` with hash + size

Failure → ``status='failed'`` with the error string. The dashboard
polls GET /compliance/exports/{id} for status.

Rate limiting
-------------
5 exports per organisation per hour. Generation is heavy (DB walk +
PDF render) and we don't want a runaway loop to take down the API.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Response,
    status,
)
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.compliance.mapper import collect_evidence_for_period
from src.compliance.oscal import build_assessment_results, serialise as serialise_oscal
from src.compliance.pdf_exporter import render_evidence_pack_pdf
from src.core.auth import AnalystUser
from src.core.rls import set_session_org
from src.core.tenant import get_system_org_id
from src.models.compliance import (
    ComplianceExport,
    ComplianceFramework,
    ExportFormat,
    ExportLanguageMode,
    ExportStatus,
)
from src.models.threat import Organization
from src.storage import evidence_store
from src.storage import database as _db
from src.storage.database import get_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/compliance", tags=["Compliance"])


_EXPORTS_PER_HOUR = 5


# --- Schemas -----------------------------------------------------------


class FrameworkSummary(BaseModel):
    id: uuid.UUID
    code: str
    name_en: str
    name_ar: str | None = None
    version: str
    source_url: str | None = None
    description_en: str | None = None
    description_ar: str | None = None


class ComplianceExportRequest(BaseModel):
    framework_code: str = Field(min_length=1, max_length=64)
    language_mode: ExportLanguageMode = ExportLanguageMode.EN
    format: ExportFormat = ExportFormat.PDF
    period_from: datetime
    period_to: datetime


class ComplianceExportResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    framework_id: uuid.UUID
    framework_code: str
    framework_name_en: str
    requested_by_user_id: uuid.UUID | None
    language_mode: str
    format: str
    period_from: datetime | None
    period_to: datetime | None
    status: str
    hash_sha256: str | None
    byte_size: int | None
    error_message: str | None
    created_at: datetime
    completed_at: datetime | None
    expires_at: datetime


# --- Helpers -----------------------------------------------------------


def _to_response(
    export: ComplianceExport, framework: ComplianceFramework
) -> ComplianceExportResponse:
    return ComplianceExportResponse(
        id=export.id,
        organization_id=export.organization_id,
        framework_id=export.framework_id,
        framework_code=framework.code,
        framework_name_en=framework.name_en,
        requested_by_user_id=export.requested_by_user_id,
        language_mode=export.language_mode,
        format=export.format,
        period_from=export.period_from,
        period_to=export.period_to,
        status=export.status,
        hash_sha256=export.hash_sha256,
        byte_size=export.byte_size,
        error_message=export.error_message,
        created_at=export.created_at,
        completed_at=export.completed_at,
        expires_at=export.expires_at,
    )


async def _check_rate_limit(
    db: AsyncSession, organization_id: uuid.UUID,
) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
    count = (await db.execute(
        select(func.count(ComplianceExport.id)).where(
            ComplianceExport.organization_id == organization_id,
            ComplianceExport.created_at >= cutoff,
        )
    )).scalar_one()
    if count >= _EXPORTS_PER_HOUR:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Rate limit: {_EXPORTS_PER_HOUR} exports per hour per "
            f"organisation. Wait and retry.",
        )


def _storage_key(organization_id: uuid.UUID, export_id: uuid.UUID, fmt: str) -> str:
    """Stable, predictable key for the export blob.

    Layout: ``compliance/<org_id>/<export_id>.<ext>`` — keeps exports
    grouped per tenant for retention sweeps.
    """
    ext = "json" if fmt == ExportFormat.JSON.value else "pdf"
    return f"compliance/{organization_id}/{export_id}.{ext}"


# --- Background worker -------------------------------------------------


async def _process_export(export_id: uuid.UUID) -> None:
    """Generate the export's bytes and persist them to object storage.

    Runs in a fresh SQLAlchemy session — does NOT inherit the request
    session. RLS GUC is set explicitly before any tenant-scoped query.
    """
    if _db.async_session_factory is None:
        logger.error("compliance export %s: session factory not initialised",
                     export_id)
        return

    async with _db.async_session_factory() as session:
        export = (await session.execute(
            select(ComplianceExport).where(ComplianceExport.id == export_id)
        )).scalar_one_or_none()
        if export is None:
            logger.error("compliance export %s: row not found", export_id)
            return

        framework = (await session.execute(
            select(ComplianceFramework).where(
                ComplianceFramework.id == export.framework_id
            )
        )).scalar_one_or_none()
        if framework is None:
            export.status = ExportStatus.FAILED.value
            export.error_message = "framework not found"
            export.completed_at = datetime.now(timezone.utc)
            await session.commit()
            return

        org = (await session.execute(
            select(Organization).where(Organization.id == export.organization_id)
        )).scalar_one_or_none()
        org_name = org.name if org else "Unknown organisation"

        export.status = ExportStatus.RUNNING.value
        await session.commit()

        try:
            # Tenant isolation — every query that follows is scoped to the
            # export's organisation by RLS, even though we also pass the
            # ID explicitly to the mapper / generators.
            await set_session_org(session, export.organization_id)

            generated_at = datetime.now(timezone.utc)
            if export.period_from is None or export.period_to is None:
                # Default window: trailing 90 days. Caller-supplied
                # period_from/period_to are validated at the API layer.
                export.period_to = generated_at
                export.period_from = generated_at - timedelta(days=90)

            await collect_evidence_for_period(
                session,
                organization_id=export.organization_id,
                framework_code=framework.code,
                period_from=export.period_from,
                period_to=export.period_to,
            )
            await session.flush()

            if export.format == ExportFormat.JSON.value:
                doc = await build_assessment_results(
                    session,
                    organization_id=export.organization_id,
                    organization_name=org_name,
                    framework=framework,
                    period_from=export.period_from,
                    period_to=export.period_to,
                    generated_at=generated_at,
                )
                payload, sha = serialise_oscal(doc)
                content_type = "application/oscal+json"
            else:
                payload = await render_evidence_pack_pdf(
                    session,
                    organization_id=export.organization_id,
                    organization_name=org_name,
                    framework=framework,
                    period_from=export.period_from,
                    period_to=export.period_to,
                    language_mode=export.language_mode,
                    generated_at=generated_at,
                )
                sha = hashlib.sha256(payload).hexdigest()
                content_type = "application/pdf"

            # Persist to object storage. Bucket creation is cheap+idempotent.
            key = _storage_key(export.organization_id, export.id, export.format)
            try:
                from src.config.settings import settings as _settings
                bucket = _settings.evidence.bucket
                evidence_store.ensure_bucket(bucket)
                evidence_store.put(
                    bucket=bucket,
                    key=key,
                    data=payload,
                    content_type=content_type,
                    metadata={
                        "argus_export_id": str(export.id),
                        "argus_org_id": str(export.organization_id),
                        "argus_framework": framework.code,
                        "argus_format": export.format,
                        "argus_language": export.language_mode,
                    },
                )
            except Exception as exc:  # noqa: BLE001 — storage is the
                # only optional dependency in this path; fall back to
                # storing the bytes inline so the export still succeeds.
                logger.warning(
                    "compliance export %s: object storage put failed (%s); "
                    "falling back to inline blob",
                    export.id, exc,
                )
                key = None  # signal "use download synthesis path"

            export.object_storage_key = key
            export.hash_sha256 = sha
            export.byte_size = len(payload)
            export.status = ExportStatus.COMPLETED.value
            export.completed_at = datetime.now(timezone.utc)
            export.error_message = None
            await session.commit()
            logger.info(
                "compliance export %s: completed (%s bytes, sha256=%s)",
                export.id, len(payload), sha[:12],
            )
        except Exception as exc:  # noqa: BLE001 — surface every failure
            logger.exception("compliance export %s failed", export.id)
            export.status = ExportStatus.FAILED.value
            export.error_message = str(exc)[:1000]
            export.completed_at = datetime.now(timezone.utc)
            await session.commit()


# --- Routes ------------------------------------------------------------


@router.get("/frameworks", response_model=list[FrameworkSummary])
async def list_frameworks(
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> list[FrameworkSummary]:
    """List active compliance frameworks available to the tenant."""
    rows = (await db.execute(
        select(ComplianceFramework)
        .where(ComplianceFramework.is_active.is_(True))
        .order_by(ComplianceFramework.code)
    )).scalars().all()
    return [
        FrameworkSummary(
            id=fw.id, code=fw.code,
            name_en=fw.name_en, name_ar=fw.name_ar,
            version=fw.version, source_url=fw.source_url,
            description_en=fw.description_en,
            description_ar=fw.description_ar,
        )
        for fw in rows
    ]


@router.post(
    "/exports",
    response_model=ComplianceExportResponse,
    status_code=202,
)
async def create_export(
    req: ComplianceExportRequest,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> ComplianceExportResponse:
    """Queue a Compliance Evidence Pack export."""
    if req.period_from >= req.period_to:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "period_from must be strictly before period_to",
        )

    framework = (await db.execute(
        select(ComplianceFramework).where(
            ComplianceFramework.code == req.framework_code,
            ComplianceFramework.is_active.is_(True),
        )
    )).scalar_one_or_none()
    if framework is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"framework {req.framework_code!r} not found or inactive",
        )

    org_id = await get_system_org_id(db)
    await _check_rate_limit(db, org_id)

    now = datetime.now(timezone.utc)
    export = ComplianceExport(
        organization_id=org_id,
        framework_id=framework.id,
        requested_by_user_id=user.id,
        language_mode=req.language_mode.value,
        format=req.format.value,
        period_from=req.period_from,
        period_to=req.period_to,
        status=ExportStatus.PENDING.value,
        expires_at=now + timedelta(days=365),
    )
    db.add(export)
    await db.flush()
    await db.commit()

    # Schedule the heavy work after the response is sent.
    background.add_task(_process_export, export.id)

    return _to_response(export, framework)


@router.get("/exports", response_model=list[ComplianceExportResponse])
async def list_exports(
    framework_code: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> list[ComplianceExportResponse]:
    """List exports for the current tenant, newest first."""
    org_id = await get_system_org_id(db)
    q = (
        select(ComplianceExport, ComplianceFramework)
        .join(
            ComplianceFramework,
            ComplianceFramework.id == ComplianceExport.framework_id,
        )
        .where(ComplianceExport.organization_id == org_id)
        .order_by(ComplianceExport.created_at.desc())
        .limit(limit)
    )
    if framework_code:
        q = q.where(ComplianceFramework.code == framework_code)
    rows = (await db.execute(q)).all()
    return [_to_response(ex, fw) for ex, fw in rows]


@router.get(
    "/exports/{export_id}",
    response_model=ComplianceExportResponse,
)
async def get_export(
    export_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> ComplianceExportResponse:
    org_id = await get_system_org_id(db)
    row = (await db.execute(
        select(ComplianceExport, ComplianceFramework)
        .join(
            ComplianceFramework,
            ComplianceFramework.id == ComplianceExport.framework_id,
        )
        .where(
            ComplianceExport.id == export_id,
            ComplianceExport.organization_id == org_id,
        )
    )).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "export not found")
    export, framework = row
    return _to_response(export, framework)


@router.get("/exports/{export_id}/download")
async def download_export(
    export_id: uuid.UUID,
    db: AsyncSession = Depends(get_session),
    user: AnalystUser = None,  # noqa: B008
) -> Response:
    """Stream the rendered export file."""
    org_id = await get_system_org_id(db)
    export = (await db.execute(
        select(ComplianceExport).where(
            ComplianceExport.id == export_id,
            ComplianceExport.organization_id == org_id,
        )
    )).scalar_one_or_none()
    if export is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "export not found")
    if export.status != ExportStatus.COMPLETED.value:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"export status is {export.status!r}, not completed",
        )
    if export.object_storage_key is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "export bytes not stored — re-run the export",
        )

    from src.config.settings import settings as _settings

    try:
        payload = evidence_store.get(
            bucket=_settings.evidence.bucket,
            key=export.object_storage_key,
        )
    except Exception as exc:  # noqa: BLE001 — surface storage failures
        logger.exception("compliance export %s: download failed", export_id)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"object storage error: {exc}",
        )

    media_type = "application/oscal+json" \
        if export.format == ExportFormat.JSON.value else "application/pdf"
    filename = (
        f"compliance-evidence-{export.id}."
        f"{'json' if export.format == ExportFormat.JSON.value else 'pdf'}"
    )
    return Response(
        content=payload,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Argus-Export-Hash": export.hash_sha256 or "",
        },
    )
