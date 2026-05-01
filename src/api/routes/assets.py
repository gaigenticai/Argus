"""Asset Registry — unified CRUD + bulk import + filters.

The canonical surface for managing every monitored entity:
domains, IPs, executives, brands, mobile apps, social handles,
vendors, code repos, cloud accounts.

Type-specific validation is handled by :mod:`src.models.asset_schemas`.
Argus is single-tenant on-prem — every row belongs to the one
``Organization`` resolved by :mod:`src.core.tenant`. The
``organization_id`` filter on each query is infrastructure (the schema
foreign-keys it), not a security boundary against another customer.
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    File,
    status,
)
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import and_, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, audit_log
from src.core.pagination import paginated_response, paginated_select, parse_paging
from src.models.asset_schemas import (
    ASSET_DETAIL_SCHEMAS,
    AssetCriticality,
    AssetType,
    DiscoveryMethod,
    canonicalize_asset_value,
    validate_asset_details,
    validate_monitoring_profile,
)
from src.models.auth import AuditAction
from src.models.threat import Asset, Organization
from src.storage.database import get_session

router = APIRouter(prefix="/assets", tags=["External Surface"])


# --- Schemas -------------------------------------------------------------


class AssetCreate(BaseModel):
    organization_id: uuid.UUID
    asset_type: AssetType
    value: str
    details: dict[str, Any] | None = None
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    tags: list[str] = Field(default_factory=list)
    monitoring_profile: dict[str, Any] | None = None
    parent_asset_id: uuid.UUID | None = None
    discovery_method: DiscoveryMethod = DiscoveryMethod.MANUAL


class AssetUpdate(BaseModel):
    """Partial update — every field optional."""

    details: dict[str, Any] | None = None
    criticality: AssetCriticality | None = None
    tags: list[str] | None = None
    monitoring_profile: dict[str, Any] | None = None
    is_active: bool | None = None
    monitoring_enabled: bool | None = None
    verified_at: datetime | None = None
    owner_user_id: uuid.UUID | None = None


class AssetResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_type: str
    value: str
    details: dict | None
    criticality: str
    tags: list[str]
    monitoring_profile: dict | None
    owner_user_id: uuid.UUID | None
    parent_asset_id: uuid.UUID | None
    discovery_method: str
    discovered_at: datetime | None
    verified_at: datetime | None
    last_scanned_at: datetime | None
    last_change_at: datetime | None
    is_active: bool
    monitoring_enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class BulkImportRow(BaseModel):
    """Schema for a single row in bulk JSON import."""

    asset_type: AssetType
    value: str
    details: dict[str, Any] | None = None
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    tags: list[str] = Field(default_factory=list)


class BulkImportRequest(BaseModel):
    organization_id: uuid.UUID
    rows: list[BulkImportRow]


class BulkImportResult(BaseModel):
    inserted: int
    skipped_duplicates: int
    errors: list[dict[str, Any]]


# --- Helpers -------------------------------------------------------------


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    ua = request.headers.get("User-Agent", "unknown")[:500]
    return ip, ua


async def _ensure_org(db: AsyncSession, org_id: uuid.UUID) -> Organization:
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "Organization not found"
        )
    return org


def _validate_payload(
    asset_type: AssetType,
    value: str,
    details: dict | None,
    monitoring_profile: dict | None,
) -> tuple[str, dict, dict]:
    """Canonicalize value + validate details + monitoring_profile.

    Raises HTTPException(422) on validation failure.
    """
    try:
        canonical_value = canonicalize_asset_value(asset_type, value)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"value: {e}")

    try:
        validated_details = validate_asset_details(asset_type, details)
    except ValidationError as e:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            {"field": "details", "errors": e.errors()},
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"details: {e}")

    try:
        validated_profile = validate_monitoring_profile(monitoring_profile)
    except ValidationError as e:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            {"field": "monitoring_profile", "errors": e.errors()},
        )

    return canonical_value, validated_details, validated_profile


# --- Endpoints -----------------------------------------------------------


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    body: AssetCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Create a single asset under an organization."""
    await _ensure_org(db, body.organization_id)

    canonical_value, validated_details, validated_profile = _validate_payload(
        body.asset_type, body.value, body.details, body.monitoring_profile
    )

    if body.parent_asset_id:
        parent = await db.get(Asset, body.parent_asset_id)
        if not parent or parent.organization_id != body.organization_id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "parent_asset_id refers to an asset in a different organization",
            )

    now = datetime.now(timezone.utc)
    asset = Asset(
        organization_id=body.organization_id,
        asset_type=body.asset_type.value,
        value=canonical_value,
        details=validated_details,
        criticality=body.criticality.value,
        tags=body.tags,
        monitoring_profile=validated_profile,
        owner_user_id=analyst.id,
        parent_asset_id=body.parent_asset_id,
        discovery_method=body.discovery_method.value,
        discovered_at=now,
    )
    db.add(asset)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Asset {body.asset_type.value}:{canonical_value} already exists for this organization",
        )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ASSET_CREATE,
        user=analyst,
        resource_type="asset",
        resource_id=str(asset.id),
        details={
            "org_id": str(body.organization_id),
            "asset_type": body.asset_type.value,
            "value": canonical_value,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(asset)
    return asset


@router.get("", response_model=list[AssetResponse])
async def list_assets(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    response: Response,
    db: AsyncSession = Depends(get_session),
    asset_type: AssetType | None = None,
    criticality: AssetCriticality | None = None,
    tag: str | None = None,
    is_active: bool | None = None,
    monitoring_enabled: bool | None = None,
    q: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """List assets for an organization with rich filtering.

    Filters compose with AND semantics. ``q`` is a case-insensitive
    substring match against ``value``. Paginated — see ``X-Total-Count``
    response header (Audit B6).
    """
    await _ensure_org(db, organization_id)

    query = select(Asset).where(Asset.organization_id == organization_id)

    if asset_type is not None:
        query = query.where(Asset.asset_type == asset_type.value)
    if criticality is not None:
        query = query.where(Asset.criticality == criticality.value)
    if tag is not None:
        query = query.where(Asset.tags.any(tag))
    if is_active is not None:
        query = query.where(Asset.is_active == is_active)
    if monitoring_enabled is not None:
        query = query.where(Asset.monitoring_enabled == monitoring_enabled)
    if q:
        query = query.where(Asset.value.ilike(f"%{q}%"))

    paging = parse_paging(limit=limit, offset=offset)
    rows, total = await paginated_select(
        db, query.order_by(Asset.created_at.desc()), paging
    )
    return paginated_response(rows, total, paging, response)


@router.get("/count")
async def count_assets(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Return per-type and per-criticality counts for the org's asset registry."""
    await _ensure_org(db, organization_id)

    q_type = (
        select(Asset.asset_type, func.count())
        .where(Asset.organization_id == organization_id)
        .group_by(Asset.asset_type)
    )
    q_crit = (
        select(Asset.criticality, func.count())
        .where(Asset.organization_id == organization_id)
        .group_by(Asset.criticality)
    )
    by_type = {row[0]: row[1] for row in (await db.execute(q_type)).all()}
    by_crit = {row[0]: row[1] for row in (await db.execute(q_crit)).all()}
    total = sum(by_type.values())
    return {"total": total, "by_type": by_type, "by_criticality": by_crit}


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    return asset


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: uuid.UUID,
    body: AssetUpdate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")

    asset_type = AssetType(asset.asset_type)
    changes: dict[str, Any] = {}

    if body.details is not None:
        try:
            validated = validate_asset_details(asset_type, body.details)
        except ValidationError as e:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                {"field": "details", "errors": e.errors()},
            )
        asset.details = validated
        changes["details"] = True

    if body.criticality is not None:
        asset.criticality = body.criticality.value
        changes["criticality"] = body.criticality.value

    if body.tags is not None:
        asset.tags = body.tags
        changes["tags"] = body.tags

    if body.monitoring_profile is not None:
        try:
            validated_profile = validate_monitoring_profile(body.monitoring_profile)
        except ValidationError as e:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                {"field": "monitoring_profile", "errors": e.errors()},
            )
        asset.monitoring_profile = validated_profile
        changes["monitoring_profile"] = True

    if body.is_active is not None:
        asset.is_active = body.is_active
        changes["is_active"] = body.is_active

    if body.monitoring_enabled is not None:
        asset.monitoring_enabled = body.monitoring_enabled
        changes["monitoring_enabled"] = body.monitoring_enabled

    if body.verified_at is not None:
        asset.verified_at = body.verified_at
        changes["verified_at"] = body.verified_at.isoformat()

    if body.owner_user_id is not None:
        asset.owner_user_id = body.owner_user_id
        changes["owner_user_id"] = str(body.owner_user_id)

    asset.last_change_at = datetime.now(timezone.utc)

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ASSET_UPDATE,
        user=analyst,
        resource_type="asset",
        resource_id=str(asset.id),
        details={"changes": changes},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")

    org_id = asset.organization_id
    asset_type = asset.asset_type
    value = asset.value

    await db.delete(asset)

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ASSET_DELETE,
        user=analyst,
        resource_type="asset",
        resource_id=str(asset_id),
        details={
            "org_id": str(org_id),
            "asset_type": asset_type,
            "value": value,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return None


@router.post("/bulk", response_model=BulkImportResult)
async def bulk_import_json(
    body: BulkImportRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Bulk-create assets from a JSON payload.

    Idempotent on (organization_id, asset_type, value): duplicates are
    counted as ``skipped_duplicates`` rather than failing the batch.
    Per-row validation errors are collected in ``errors``; the rest of
    the batch still commits.
    """
    await _ensure_org(db, body.organization_id)

    inserted = 0
    skipped = 0
    errors: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)

    for idx, row in enumerate(body.rows):
        try:
            canonical_value, validated_details, validated_profile = _validate_payload(
                row.asset_type, row.value, row.details, None
            )
        except HTTPException as exc:
            errors.append({"index": idx, "value": row.value, "error": exc.detail})
            continue

        # Existence check
        existing = await db.execute(
            select(Asset.id).where(
                and_(
                    Asset.organization_id == body.organization_id,
                    Asset.asset_type == row.asset_type.value,
                    Asset.value == canonical_value,
                )
            )
        )
        if existing.scalar_one_or_none():
            skipped += 1
            continue

        asset = Asset(
            organization_id=body.organization_id,
            asset_type=row.asset_type.value,
            value=canonical_value,
            details=validated_details,
            criticality=row.criticality.value,
            tags=row.tags,
            monitoring_profile=validated_profile,
            owner_user_id=analyst.id,
            discovery_method=DiscoveryMethod.BULK_IMPORT.value,
            discovered_at=now,
        )
        db.add(asset)
        inserted += 1

    try:
        await db.flush()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"Bulk insert failed: {e.orig}"
        )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ASSET_BULK_IMPORT,
        user=analyst,
        resource_type="organization",
        resource_id=str(body.organization_id),
        details={"inserted": inserted, "skipped": skipped, "errors": len(errors)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return BulkImportResult(
        inserted=inserted, skipped_duplicates=skipped, errors=errors
    )


@router.post("/bulk/csv", response_model=BulkImportResult)
async def bulk_import_csv(
    request: Request,
    analyst: AnalystUser,
    organization_id: Annotated[uuid.UUID, Query()],
    file: Annotated[UploadFile, File()],
    db: AsyncSession = Depends(get_session),
):
    """Bulk-import assets from a CSV file.

    Required columns: ``asset_type``, ``value``.
    Optional columns: ``criticality``, ``tags`` (semicolon-separated),
    ``details_json`` (JSON-encoded string).
    """
    await _ensure_org(db, organization_id)

    raw = (await file.read()).decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(raw))
    if not reader.fieldnames or "asset_type" not in reader.fieldnames or "value" not in reader.fieldnames:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "CSV must have at least 'asset_type' and 'value' columns",
        )

    import json as _json

    rows: list[BulkImportRow] = []
    parse_errors: list[dict[str, Any]] = []
    for idx, row in enumerate(reader):
        try:
            details = (
                _json.loads(row["details_json"])
                if row.get("details_json")
                else None
            )
        except _json.JSONDecodeError as e:
            parse_errors.append(
                {"index": idx, "value": row.get("value"), "error": f"details_json: {e}"}
            )
            continue

        try:
            rows.append(
                BulkImportRow(
                    asset_type=AssetType(row["asset_type"].strip()),
                    value=row["value"].strip(),
                    details=details,
                    criticality=AssetCriticality(
                        (row.get("criticality") or "medium").strip()
                    ),
                    tags=[t.strip() for t in (row.get("tags") or "").split(";") if t.strip()],
                )
            )
        except (ValueError, ValidationError) as e:
            parse_errors.append(
                {"index": idx, "value": row.get("value"), "error": str(e)}
            )

    # Reuse the JSON bulk path
    result = await bulk_import_json(
        BulkImportRequest(organization_id=organization_id, rows=rows),
        request,
        analyst,
        db,
    )
    result.errors = parse_errors + result.errors
    return result


@router.get("/types/schema")
async def asset_type_schemas(analyst: AnalystUser):
    """Return JSON-schema for the ``details`` field of every asset type.

    Used by the dashboard to render type-aware forms.
    """
    return {
        atype.value: schema.model_json_schema()
        for atype, schema in ASSET_DETAIL_SCHEMAS.items()
    }
