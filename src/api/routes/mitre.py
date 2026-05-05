"""MITRE ATT&CK API.

Endpoints
---------
    POST   /mitre/sync                                     trigger import (admin)
    GET    /mitre/syncs                                    sync history
    GET    /mitre/tactics                                  list (filter by matrix)
    GET    /mitre/techniques                               list with rich filters
    GET    /mitre/techniques/{external_id}                 detail (matrix optional)
    GET    /mitre/mitigations                              list

    POST   /mitre/attachments                              attach technique → entity
    DELETE /mitre/attachments/{id}                         detach
    GET    /mitre/attachments                              list with filters
    GET    /mitre/entities/{type}/{id}/techniques          techniques attached to entity
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser, AnalystUser, audit_log
from src.mitre.sync import DEFAULT_BUNDLE_URLS, sync_matrix, upsert_actors_from_groups
from src.models.auth import AuditAction
from src.models.mitre import (
    ALLOWED_ENTITY_TYPES,
    AttachmentSource,
    AttackTechniqueAttachment,
    MitreCampaign,
    MitreDataSource,
    MitreGroup,
    MitreLayer,
    MitreMatrix,
    MitreMitigation,
    MitreRelationship,
    MitreSoftware,
    MitreSync,
    MitreTactic,
    MitreTechnique,
    MitreTechniqueCoverage,
)
from src.models.threat import Organization
from src.storage.database import get_session


router = APIRouter(prefix="/mitre", tags=["Threat Intelligence"])


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    ua = request.headers.get("User-Agent", "unknown")[:500]
    return ip, ua


# --- Schemas ------------------------------------------------------------


class SyncRequest(BaseModel):
    matrix: MitreMatrix
    source: str | None = None  # URL or local file path; defaults to canonical URL


class SyncReportResponse(BaseModel):
    matrix: str
    source: str
    sync_version: str | None
    tactics: int
    techniques: int
    subtechniques: int
    mitigations: int
    deprecated: int
    succeeded: bool
    error: str | None


class MitreSyncResponse(BaseModel):
    id: uuid.UUID
    matrix: str
    source_url: str | None
    sync_version: str | None
    tactics_count: int
    techniques_count: int
    subtechniques_count: int
    mitigations_count: int
    deprecated_count: int
    succeeded: bool
    error_message: str | None
    triggered_by_user_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TacticResponse(BaseModel):
    id: uuid.UUID
    matrix: str
    external_id: str
    short_name: str
    name: str
    description: str | None
    url: str | None
    sync_version: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TechniqueResponse(BaseModel):
    id: uuid.UUID
    matrix: str
    external_id: str
    parent_external_id: str | None
    is_subtechnique: bool
    name: str
    description: str | None
    tactics: list[str]
    platforms: list[str]
    data_sources: list[str]
    detection: str | None
    deprecated: bool
    revoked: bool
    url: str | None
    sync_version: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class MitigationResponse(BaseModel):
    id: uuid.UUID
    matrix: str
    external_id: str
    name: str
    description: str | None
    url: str | None
    sync_version: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AttachmentCreate(BaseModel):
    organization_id: uuid.UUID
    entity_type: str = Field(min_length=1, max_length=40)
    entity_id: uuid.UUID
    matrix: MitreMatrix
    technique_external_id: str = Field(min_length=2, max_length=20)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source: AttachmentSource = AttachmentSource.MANUAL
    note: str | None = None


class AttachmentResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    entity_type: str
    entity_id: uuid.UUID
    matrix: str
    technique_external_id: str
    confidence: float
    source: str
    note: str | None
    attached_by_user_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# --- Sync ---------------------------------------------------------------


@router.post("/sync", response_model=SyncReportResponse)
async def trigger_sync(
    body: SyncRequest,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    report = await sync_matrix(
        db,
        body.matrix,
        source=body.source,
        triggered_by_user_id=admin.id,
    )
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.MITRE_SYNC,
        user=admin,
        resource_type="mitre_matrix",
        resource_id=body.matrix.value,
        details={
            "succeeded": report.succeeded,
            "techniques": report.techniques,
            "subtechniques": report.subtechniques,
            "tactics": report.tactics,
            "mitigations": report.mitigations,
            "source": report.source,
            "version": report.sync_version,
            "error": report.error,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return SyncReportResponse(**report.__dict__)


@router.get("/syncs", response_model=list[MitreSyncResponse])
async def list_syncs(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    matrix: MitreMatrix | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
):
    q = select(MitreSync)
    if matrix is not None:
        q = q.where(MitreSync.matrix == matrix.value)
    q = q.order_by(MitreSync.created_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


# --- Catalog ------------------------------------------------------------


@router.get("/tactics", response_model=list[TacticResponse])
async def list_tactics(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    matrix: MitreMatrix | None = None,
):
    q = select(MitreTactic)
    if matrix is not None:
        q = q.where(MitreTactic.matrix == matrix.value)
    q = q.order_by(MitreTactic.matrix, MitreTactic.external_id)
    return list((await db.execute(q)).scalars().all())


@router.get("/techniques", response_model=list[TechniqueResponse])
async def list_techniques(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    matrix: MitreMatrix | None = None,
    tactic: str | None = Query(default=None, description="Tactic short_name"),
    platform: str | None = None,
    include_subtechniques: bool = True,
    include_deprecated: bool = False,
    q: str | None = Query(default=None, description="Substring on name/external_id/description"),
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    query = select(MitreTechnique)
    if matrix is not None:
        query = query.where(MitreTechnique.matrix == matrix.value)
    if not include_subtechniques:
        query = query.where(MitreTechnique.is_subtechnique == False)  # noqa: E712
    if not include_deprecated:
        query = query.where(
            and_(
                MitreTechnique.deprecated == False,  # noqa: E712
                MitreTechnique.revoked == False,  # noqa: E712
            )
        )
    if tactic:
        query = query.where(MitreTechnique.tactics.any(tactic))
    if platform:
        query = query.where(MitreTechnique.platforms.any(platform))
    if q:
        like = f"%{q}%"
        query = query.where(
            or_(
                MitreTechnique.name.ilike(like),
                MitreTechnique.external_id.ilike(like),
                MitreTechnique.description.ilike(like),
            )
        )
    query = query.order_by(MitreTechnique.external_id).limit(limit).offset(offset)
    return list((await db.execute(query)).scalars().all())


@router.get("/techniques/{external_id}", response_model=TechniqueResponse)
async def get_technique(
    external_id: str,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    matrix: MitreMatrix | None = None,
):
    query = select(MitreTechnique).where(MitreTechnique.external_id == external_id)
    if matrix is not None:
        query = query.where(MitreTechnique.matrix == matrix.value)
    rows = list((await db.execute(query)).scalars().all())
    if not rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Technique not found")
    if len(rows) > 1 and matrix is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Technique exists in multiple matrices; specify matrix= in query",
        )
    return rows[0]


@router.get("/mitigations", response_model=list[MitigationResponse])
async def list_mitigations(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    matrix: MitreMatrix | None = None,
):
    q = select(MitreMitigation)
    if matrix is not None:
        q = q.where(MitreMitigation.matrix == matrix.value)
    return list(
        (await db.execute(q.order_by(MitreMitigation.external_id))).scalars().all()
    )


# --- Attachments --------------------------------------------------------


@router.post("/attachments", response_model=AttachmentResponse, status_code=201)
async def attach_technique(
    body: AttachmentCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    if body.entity_type not in ALLOWED_ENTITY_TYPES:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"entity_type must be one of {ALLOWED_ENTITY_TYPES}",
        )

    # Technique must exist in catalog (catches typos).
    tech = (
        await db.execute(
            select(MitreTechnique).where(
                and_(
                    MitreTechnique.matrix == body.matrix.value,
                    MitreTechnique.external_id == body.technique_external_id,
                )
            )
        )
    ).scalar_one_or_none()
    if tech is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"technique {body.technique_external_id} not found in matrix {body.matrix.value}",
        )

    attach = AttackTechniqueAttachment(
        organization_id=body.organization_id,
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        matrix=body.matrix.value,
        technique_external_id=body.technique_external_id,
        confidence=body.confidence,
        source=body.source.value,
        note=body.note,
        attached_by_user_id=analyst.id,
    )
    db.add(attach)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "This technique is already attached to that entity",
        )

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.MITRE_TECHNIQUE_ATTACH,
        user=analyst,
        resource_type="attack_technique_attachment",
        resource_id=str(attach.id),
        details={
            "entity_type": body.entity_type,
            "entity_id": str(body.entity_id),
            "technique": body.technique_external_id,
            "matrix": body.matrix.value,
            "confidence": body.confidence,
            "source": body.source.value,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(attach)
    return attach


@router.delete("/attachments/{attachment_id}", status_code=204)
async def detach_technique(
    attachment_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    a = await db.get(AttackTechniqueAttachment, attachment_id)
    if not a:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Attachment not found")
    org_id = a.organization_id
    payload = {
        "entity_type": a.entity_type,
        "entity_id": str(a.entity_id),
        "technique": a.technique_external_id,
        "matrix": a.matrix,
    }
    await db.delete(a)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.MITRE_TECHNIQUE_DETACH,
        user=analyst,
        resource_type="attack_technique_attachment",
        resource_id=str(attachment_id),
        details={**payload, "organization_id": str(org_id)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return None


@router.get("/attachments", response_model=list[AttachmentResponse])
async def list_attachments(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    entity_type: str | None = None,
    entity_id: uuid.UUID | None = None,
    technique_external_id: str | None = None,
    matrix: MitreMatrix | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")

    q = select(AttackTechniqueAttachment).where(
        AttackTechniqueAttachment.organization_id == organization_id
    )
    if entity_type is not None:
        q = q.where(AttackTechniqueAttachment.entity_type == entity_type)
    if entity_id is not None:
        q = q.where(AttackTechniqueAttachment.entity_id == entity_id)
    if technique_external_id is not None:
        q = q.where(
            AttackTechniqueAttachment.technique_external_id == technique_external_id
        )
    if matrix is not None:
        q = q.where(AttackTechniqueAttachment.matrix == matrix.value)
    q = q.order_by(AttackTechniqueAttachment.created_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


# --- Groups / Software / Data Sources / Campaigns / Relationships ------


class GroupResponse(BaseModel):
    id: uuid.UUID
    matrix: str
    external_id: str
    name: str
    aliases: list[str]
    description: str | None
    country_codes: list[str]
    sectors_targeted: list[str]
    regions_targeted: list[str]
    references: list[dict[str, Any]]
    deprecated: bool
    revoked: bool
    url: str | None
    sync_version: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class SoftwareResponse(BaseModel):
    id: uuid.UUID
    matrix: str
    external_id: str
    name: str
    aliases: list[str]
    software_type: str
    description: str | None
    platforms: list[str]
    labels: list[str]
    references: list[dict[str, Any]]
    deprecated: bool
    revoked: bool
    url: str | None
    sync_version: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DataSourceResponse(BaseModel):
    id: uuid.UUID
    matrix: str
    external_id: str
    name: str
    description: str | None
    platforms: list[str]
    collection_layers: list[str]
    data_components: list[dict[str, Any]]
    url: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CampaignResponse(BaseModel):
    id: uuid.UUID
    matrix: str
    external_id: str
    name: str
    aliases: list[str]
    description: str | None
    first_seen: datetime | None
    last_seen: datetime | None
    references: list[dict[str, Any]]
    url: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RelationshipResponse(BaseModel):
    id: uuid.UUID
    matrix: str
    source_type: str
    source_external_id: str
    relationship_type: str
    target_type: str
    target_external_id: str
    description: str | None

    model_config = {"from_attributes": True}


@router.get("/groups", response_model=list[GroupResponse])
async def list_groups(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    matrix: MitreMatrix | None = None,
    sector: str | None = None,
    country: str | None = None,
    q: str | None = None,
    include_deprecated: bool = False,
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
):
    query = select(MitreGroup)
    if matrix is not None:
        query = query.where(MitreGroup.matrix == matrix.value)
    if not include_deprecated:
        query = query.where(
            and_(
                MitreGroup.deprecated == False,  # noqa: E712
                MitreGroup.revoked == False,  # noqa: E712
            )
        )
    if sector:
        query = query.where(MitreGroup.sectors_targeted.any(sector))
    if country:
        query = query.where(MitreGroup.country_codes.any(country.upper()))
    if q:
        like = f"%{q}%"
        query = query.where(
            or_(
                MitreGroup.name.ilike(like),
                MitreGroup.external_id.ilike(like),
                MitreGroup.description.ilike(like),
            )
        )
    return list(
        (await db.execute(query.order_by(MitreGroup.external_id).limit(limit)))
        .scalars()
        .all()
    )


@router.get("/groups/{external_id}", response_model=dict)
async def get_group(
    external_id: str,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    matrix: MitreMatrix | None = None,
):
    q = select(MitreGroup).where(MitreGroup.external_id == external_id)
    if matrix is not None:
        q = q.where(MitreGroup.matrix == matrix.value)
    g = (await db.execute(q)).scalar_one_or_none()
    if not g:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Group not found")

    rels = list(
        (
            await db.execute(
                select(MitreRelationship).where(
                    MitreRelationship.source_type == "group",
                    MitreRelationship.source_external_id == external_id,
                )
            )
        )
        .scalars()
        .all()
    )
    techniques = sorted({r.target_external_id for r in rels if r.target_type == "technique"})
    software = sorted({r.target_external_id for r in rels if r.target_type == "software"})
    campaigns = sorted({r.target_external_id for r in rels if r.target_type == "campaign"})
    return {
        "group": GroupResponse.model_validate(g).model_dump(),
        "techniques": techniques,
        "software": software,
        "campaigns": campaigns,
    }


@router.get("/software", response_model=list[SoftwareResponse])
async def list_software(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    matrix: MitreMatrix | None = None,
    software_type: str | None = Query(default=None, pattern=r"^(malware|tool)$"),
    q: str | None = None,
    include_deprecated: bool = False,
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
):
    query = select(MitreSoftware)
    if matrix is not None:
        query = query.where(MitreSoftware.matrix == matrix.value)
    if software_type:
        query = query.where(MitreSoftware.software_type == software_type)
    if not include_deprecated:
        query = query.where(
            and_(
                MitreSoftware.deprecated == False,  # noqa: E712
                MitreSoftware.revoked == False,  # noqa: E712
            )
        )
    if q:
        like = f"%{q}%"
        query = query.where(
            or_(
                MitreSoftware.name.ilike(like),
                MitreSoftware.external_id.ilike(like),
            )
        )
    return list(
        (await db.execute(query.order_by(MitreSoftware.external_id).limit(limit)))
        .scalars()
        .all()
    )


@router.get("/data-sources", response_model=list[DataSourceResponse])
async def list_data_sources(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    matrix: MitreMatrix | None = None,
):
    q = select(MitreDataSource)
    if matrix is not None:
        q = q.where(MitreDataSource.matrix == matrix.value)
    return list(
        (await db.execute(q.order_by(MitreDataSource.external_id))).scalars().all()
    )


@router.get("/campaigns", response_model=list[CampaignResponse])
async def list_campaigns(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    matrix: MitreMatrix | None = None,
):
    q = select(MitreCampaign)
    if matrix is not None:
        q = q.where(MitreCampaign.matrix == matrix.value)
    return list(
        (await db.execute(q.order_by(MitreCampaign.first_seen.desc().nullslast())))
        .scalars()
        .all()
    )


@router.get("/relationships", response_model=list[RelationshipResponse])
async def list_relationships(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    source_type: str | None = None,
    source_external_id: str | None = None,
    target_type: str | None = None,
    target_external_id: str | None = None,
    relationship_type: str | None = None,
    matrix: MitreMatrix | None = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 1000,
):
    q = select(MitreRelationship)
    if matrix is not None:
        q = q.where(MitreRelationship.matrix == matrix.value)
    if source_type:
        q = q.where(MitreRelationship.source_type == source_type)
    if source_external_id:
        q = q.where(MitreRelationship.source_external_id == source_external_id)
    if target_type:
        q = q.where(MitreRelationship.target_type == target_type)
    if target_external_id:
        q = q.where(MitreRelationship.target_external_id == target_external_id)
    if relationship_type:
        q = q.where(MitreRelationship.relationship_type == relationship_type)
    return list((await db.execute(q.limit(limit))).scalars().all())


@router.get("/techniques/{external_id}/groups", response_model=list[GroupResponse])
async def groups_using_technique(
    external_id: str,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    matrix: MitreMatrix | None = None,
):
    rel_q = select(MitreRelationship).where(
        MitreRelationship.relationship_type == "uses",
        MitreRelationship.target_type == "technique",
        MitreRelationship.target_external_id == external_id,
        MitreRelationship.source_type == "group",
    )
    if matrix is not None:
        rel_q = rel_q.where(MitreRelationship.matrix == matrix.value)
    rels = list((await db.execute(rel_q)).scalars().all())
    if not rels:
        return []
    group_ids = {r.source_external_id for r in rels}
    g_q = select(MitreGroup).where(MitreGroup.external_id.in_(group_ids))
    if matrix is not None:
        g_q = g_q.where(MitreGroup.matrix == matrix.value)
    return list((await db.execute(g_q)).scalars().all())


@router.post("/import-actors", response_model=dict)
async def import_actors_from_groups(
    organization_id: uuid.UUID,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Auto-create / refresh ThreatActor rows for an org from MITRE Groups."""
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    written = await upsert_actors_from_groups(db, organization_id=organization_id)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.MITRE_SYNC,
        user=admin,
        resource_type="threat_actor",
        resource_id=str(organization_id),
        details={"action": "import_from_mitre_groups", "written": written},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return {"written": written, "organization_id": str(organization_id)}


@router.get(
    "/entities/{entity_type}/{entity_id}/techniques",
    response_model=list[TechniqueResponse],
)
async def techniques_for_entity(
    entity_type: str,
    entity_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    if entity_type not in ALLOWED_ENTITY_TYPES:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"entity_type must be one of {ALLOWED_ENTITY_TYPES}",
        )
    rows = await db.execute(
        select(AttackTechniqueAttachment)
        .where(
            and_(
                AttackTechniqueAttachment.entity_type == entity_type,
                AttackTechniqueAttachment.entity_id == entity_id,
            )
        )
    )
    attaches = list(rows.scalars().all())
    if not attaches:
        return []
    pairs = [(a.matrix, a.technique_external_id) for a in attaches]
    # Single round-trip fetch using a tuple-IN.
    rows = await db.execute(
        select(MitreTechnique).where(
            or_(
                *[
                    and_(
                        MitreTechnique.matrix == matrix,
                        MitreTechnique.external_id == ext,
                    )
                    for matrix, ext in pairs
                ]
            )
        )
    )
    return list(rows.scalars().all())


# --- Layers + Coverage --------------------------------------------------


class LayerCreate(BaseModel):
    organization_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    matrix: MitreMatrix = MitreMatrix.ENTERPRISE
    technique_scores: dict[str, int] = Field(default_factory=dict)


class LayerResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str | None
    matrix: str
    technique_scores: dict[str, int]
    color_palette: dict[str, str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


@router.post("/layers", response_model=LayerResponse, status_code=201)
async def create_layer(
    body: LayerCreate,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    org = await db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(404, "Organization not found")
    layer = MitreLayer(
        organization_id=body.organization_id,
        name=body.name.strip(),
        description=body.description,
        matrix=body.matrix.value,
        technique_scores=body.technique_scores or {},
        created_by_user_id=getattr(analyst, "id", None),
    )
    db.add(layer)
    await db.commit()
    await db.refresh(layer)
    return layer


@router.get("/layers", response_model=list[LayerResponse])
async def list_layers(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    rows = (
        await db.execute(
            select(MitreLayer)
            .where(MitreLayer.organization_id == organization_id)
            .order_by(MitreLayer.updated_at.desc())
        )
    ).scalars().all()
    return list(rows)


@router.put("/layers/{layer_id}", response_model=LayerResponse)
async def update_layer(
    layer_id: uuid.UUID,
    body: LayerCreate,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    layer = await db.get(MitreLayer, layer_id)
    if not layer:
        raise HTTPException(404, "Layer not found")
    layer.name = body.name.strip()
    layer.description = body.description
    layer.matrix = body.matrix.value
    layer.technique_scores = body.technique_scores or {}
    await db.commit()
    await db.refresh(layer)
    return layer


@router.delete("/layers/{layer_id}", status_code=204)
async def delete_layer(
    layer_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    layer = await db.get(MitreLayer, layer_id)
    if not layer:
        raise HTTPException(404, "Layer not found")
    await db.delete(layer)
    await db.commit()


@router.get("/layers/{layer_id}/navigator")
async def export_layer_navigator(
    layer_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Export as ATT&CK Navigator JSON v4.5 (importable at attack.mitre.org/navigator)."""
    layer = await db.get(MitreLayer, layer_id)
    if not layer:
        raise HTTPException(404, "Layer not found")
    techniques = [
        {"techniqueID": tid, "score": score, "color": "", "comment": "", "enabled": True}
        for tid, score in (layer.technique_scores or {}).items()
    ]
    palette = layer.color_palette or {}
    return {
        "name": layer.name,
        "versions": {"attack": "15", "navigator": "4.9.5", "layer": "4.5"},
        "domain": (
            "enterprise-attack"
            if layer.matrix == "enterprise"
            else f"{layer.matrix}-attack"
        ),
        "description": layer.description or "",
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 3,
        "layout": {"layout": "side", "showName": True, "showID": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": [
                palette.get("low", "#FFE0B2"),
                palette.get("med", "#FFAB00"),
                palette.get("high", "#FF5630"),
            ],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [],
        "metadata": [
            {"name": "argus_layer_id", "value": str(layer.id)},
            {"name": "argus_organization_id", "value": str(layer.organization_id)},
        ],
    }


# --- Per-org coverage map -----------------------------------------------


class CoverageEntry(BaseModel):
    technique_external_id: str
    score: int = Field(ge=0, le=100)
    covered_by: list[str] = []
    notes: str | None = None


class CoverageBulkUpsert(BaseModel):
    organization_id: uuid.UUID
    matrix: MitreMatrix = MitreMatrix.ENTERPRISE
    entries: list[CoverageEntry]


class CoverageResponse(BaseModel):
    id: uuid.UUID
    matrix: str
    technique_external_id: str
    score: int
    covered_by: list[str]
    notes: str | None
    updated_at: datetime

    model_config = {"from_attributes": True}


@router.post("/coverage/bulk", response_model=dict)
async def bulk_upsert_coverage(
    body: CoverageBulkUpsert,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Upsert per-technique coverage rows for an org. Powers the heatmap."""
    upserted = 0
    for e in body.entries:
        existing = (
            await db.execute(
                select(MitreTechniqueCoverage).where(
                    MitreTechniqueCoverage.organization_id == body.organization_id,
                    MitreTechniqueCoverage.matrix == body.matrix.value,
                    MitreTechniqueCoverage.technique_external_id
                    == e.technique_external_id,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                MitreTechniqueCoverage(
                    organization_id=body.organization_id,
                    matrix=body.matrix.value,
                    technique_external_id=e.technique_external_id,
                    score=e.score,
                    covered_by=sorted(set(e.covered_by)),
                    notes=e.notes,
                    updated_by_user_id=getattr(analyst, "id", None),
                )
            )
        else:
            existing.score = e.score
            existing.covered_by = sorted(set(e.covered_by))
            existing.notes = e.notes
            existing.updated_by_user_id = getattr(analyst, "id", None)
        upserted += 1
    await db.commit()
    return {"upserted": upserted}


@router.get("/coverage", response_model=list[CoverageResponse])
async def list_coverage(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    matrix: MitreMatrix | None = None,
):
    q = select(MitreTechniqueCoverage).where(
        MitreTechniqueCoverage.organization_id == organization_id
    )
    if matrix is not None:
        q = q.where(MitreTechniqueCoverage.matrix == matrix.value)
    return list((await db.execute(q)).scalars().all())
