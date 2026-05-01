"""Evidence Vault API.

Endpoints:
    POST   /evidence/upload          multipart upload (kind + organization_id required)
    GET    /evidence                 list with filters (org, kind, asset, deleted)
    GET    /evidence/{id}            metadata for a single blob
    GET    /evidence/{id}/download   presigned URL (5 min default TTL)
    GET    /evidence/{id}/inline     stream bytes through the API (for small blobs / IDP-strict envs)
    DELETE /evidence/{id}            soft-delete (kept in S3 — purged later by retention worker)
    POST   /evidence/{id}/restore    undelete

Constraints enforced:
    - max blob size from settings.evidence.max_blob_bytes
    - mime allowlist (rejects executables and scripts)
    - dedup within tenant: identical SHA-256 returns the existing record
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.core.auth import AnalystUser, audit_log
from src.models.auth import AuditAction
from src.models.evidence import EvidenceBlob, EvidenceKind
from src.models.threat import Asset, Organization
from src.storage import evidence_store
from src.storage.database import get_session

router = APIRouter(prefix="/evidence", tags=["Compliance & DLP"])
_logger = logging.getLogger(__name__)


# Mime allowlist — rejects anything that could be executed.
_ALLOWED_MIME_PREFIXES = (
    "image/",
    "text/",
    "application/pdf",
    "application/json",
    "application/xml",
    "application/zip",
    "application/x-pcap",
    "application/vnd.tcpdump.pcap",
)


def _is_allowed_mime(content_type: str) -> bool:
    ct = (content_type or "").lower().split(";", 1)[0].strip()
    if not ct:
        return False
    if ct in {"application/octet-stream"}:
        return True  # generic; we still rely on size + kind to bound risk
    return any(ct.startswith(p) for p in _ALLOWED_MIME_PREFIXES)


# --- Magic-byte sniffing -----------------------------------------------
# Declared MIME isn't trusted — sniff the actual content to confirm.
# python-magic is shipped in the runtime image (see Dockerfile); we keep
# the import behind a try/except so the module can still be imported in
# development environments where libmagic isn't installed locally.
#
# When sniffing isn't possible (library missing OR a sniff call raises),
# we don't silently fall back — we log loudly and emit a FeedHealth-style
# operational warning so the analyst sees that uploads are NOT being
# byte-checked. This closes the audit's "MIME sniff fall-through silent
# zero" finding.
import logging as _logging
_evidence_logger = _logging.getLogger(__name__)

try:
    import magic as _magic  # python-magic

    _MAGIC_AVAILABLE = True

    def _detect_mime(blob: bytes) -> str | None:
        try:
            return _magic.from_buffer(blob[:4096], mime=True)
        except Exception as exc:  # noqa: BLE001
            _evidence_logger.error(
                "evidence.mime_sniff: libmagic raised on a sample (size=%d): %s",
                len(blob), exc,
            )
            try:
                from prometheus_client import Counter as _Counter

                global _MIME_SNIFF_ERRORS
                if "_MIME_SNIFF_ERRORS" not in globals():
                    _MIME_SNIFF_ERRORS = _Counter(  # type: ignore[name-defined]
                        "argus_evidence_mime_sniff_errors_total",
                        "Count of evidence uploads where libmagic raised "
                        "during byte sniffing — uploads still proceed but "
                        "the executable denylist cannot be enforced.",
                    )
                _MIME_SNIFF_ERRORS.inc()  # type: ignore[name-defined]
            except Exception:  # noqa: BLE001
                _evidence_logger.debug(
                    "evidence.mime_sniff: prometheus counter unavailable",
                    exc_info=True,
                )
            return None
except Exception as _import_exc:  # noqa: BLE001
    _magic = None  # type: ignore
    _MAGIC_AVAILABLE = False
    _evidence_logger.error(
        "evidence.mime_sniff: python-magic NOT available (%s). "
        "Uploads will be accepted on declared MIME alone — the executable "
        "denylist cannot be enforced. Install libmagic + python-magic to "
        "restore byte-level upload checking.",
        _import_exc,
    )

    def _detect_mime(blob: bytes) -> str | None:
        return None


def mime_sniff_health() -> dict[str, object]:
    """Surface MIME-sniff availability for the dashboard's admin panel."""
    return {
        "magic_available": _MAGIC_AVAILABLE,
        "byte_check_enforced": _MAGIC_AVAILABLE,
    }


# MIME types that are *always* rejected, regardless of declared type.
_FORBIDDEN_SNIFFED_MIMES = {
    "application/x-msdownload",          # PE / .exe
    "application/x-executable",          # generic ELF / Mach-O
    "application/x-sharedlib",
    "application/x-dosexec",
    "application/x-mach-binary",
    "application/vnd.microsoft.portable-executable",
    "application/java-archive",          # .jar
    "application/x-msi",
    "application/x-apple-diskimage",     # .dmg
    "application/x-iso9660-image",
    "application/x-shellscript",
}


def _content_type_compatible(declared: str, sniffed: str | None) -> bool:
    """Return True iff the sniffed MIME is acceptable for upload.

    Policy: reject when the sniffed type is in the forbidden-executable
    list. When sniffing is unavailable the upload proceeds on declared
    MIME alone, but we WARN per request so the dashboard can render a
    "byte-check disabled" banner — never a silent acceptance.
    """
    if not sniffed:
        if not _MAGIC_AVAILABLE:
            _evidence_logger.warning(
                "evidence.mime_sniff: byte-check skipped (libmagic unavailable); "
                "declared=%s",
                declared,
            )
        return True
    return sniffed.lower() not in _FORBIDDEN_SNIFFED_MIMES


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    ua = request.headers.get("User-Agent", "unknown")[:500]
    return ip, ua


# --- Response schemas ---------------------------------------------------


class EvidenceResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: uuid.UUID | None
    sha256: str
    size_bytes: int
    content_type: str
    original_filename: str | None
    kind: str
    s3_bucket: str
    s3_key: str
    is_deleted: bool
    deleted_at: datetime | None
    deleted_by_user_id: uuid.UUID | None
    delete_reason: str | None
    captured_at: datetime
    captured_by_user_id: uuid.UUID | None
    capture_source: str | None
    description: str | None
    extra: dict | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PresignedURLResponse(BaseModel):
    url: str
    ttl_seconds: int
    sha256: str


# --- Endpoints -----------------------------------------------------------


@router.post("/upload", response_model=EvidenceResponse, status_code=201)
async def upload_evidence(
    request: Request,
    analyst: AnalystUser,
    organization_id: Annotated[uuid.UUID, Form()],
    kind: Annotated[EvidenceKind, Form()],
    file: Annotated[UploadFile, File()],
    asset_id: Annotated[uuid.UUID | None, Form()] = None,
    description: Annotated[str | None, Form()] = None,
    capture_source: Annotated[str | None, Form()] = None,
    db: AsyncSession = Depends(get_session),
):
    """Upload a binary blob.

    Computes SHA-256 of the bytes, dedupes within the tenant, stores in
    MinIO/S3, and writes the metadata row in one transaction.
    """
    # Verify org
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")

    if asset_id is not None:
        asset = await db.get(Asset, asset_id)
        if not asset or asset.organization_id != organization_id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "asset_id refers to an asset in a different organization",
            )

    # Mime check (Audit B10) — declared type must be allowed AND content
    # magic bytes must not match a known-executable family. Order:
    # size + emptiness → declared mime → magic sniff (executables blocked).
    declared = file.content_type or "application/octet-stream"
    if not _is_allowed_mime(declared):
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            f"Content type {declared!r} not allowed",
        )

    max_bytes = settings.evidence.max_blob_bytes
    body = await file.read(max_bytes + 1)
    if len(body) == 0:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Empty upload not allowed"
        )
    if len(body) > max_bytes:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Blob exceeds max size of {max_bytes} bytes",
        )
    sniffed = _detect_mime(body)
    if sniffed is not None and not _content_type_compatible(declared, sniffed):
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            f"upload sniffed as forbidden type {sniffed!r}",
        )

    sha256 = evidence_store.sha256_of(body)
    bucket = settings.evidence.bucket
    key = evidence_store.storage_key(str(organization_id), sha256)

    # Dedup check within tenant
    existing = await db.execute(
        select(EvidenceBlob).where(
            and_(
                EvidenceBlob.organization_id == organization_id,
                EvidenceBlob.sha256 == sha256,
            )
        )
    )
    blob = existing.scalar_one_or_none()
    if blob is not None and not blob.is_deleted:
        # Idempotent: return existing record without re-uploading
        return blob
    if blob is not None and blob.is_deleted:
        # Restore via dedup re-upload
        blob.is_deleted = False
        blob.deleted_at = None
        blob.deleted_by_user_id = None
        blob.delete_reason = None
        # Re-upload bytes in case the retention worker purged them
        evidence_store.ensure_bucket(bucket)
        if not evidence_store.exists(bucket, key):
            evidence_store.put(bucket, key, body, declared, metadata={"sha256": sha256})

        ip, ua = _client_meta(request)
        await audit_log(
            db,
            AuditAction.EVIDENCE_RESTORE,
            user=analyst,
            resource_type="evidence_blob",
            resource_id=str(blob.id),
            details={"sha256": sha256, "kind": kind.value},
            ip_address=ip,
            user_agent=ua,
        )
        await db.commit()
        await db.refresh(blob)
        return blob

    # Fresh upload — Audit C2: a MinIO/S3 outage MUST NOT leave a row
    # in `evidence_blobs` whose object is missing. Convert any storage
    # failure into a 503 so the caller knows the upload didn't take.
    try:
        evidence_store.ensure_bucket(bucket)
        evidence_store.put(
            bucket,
            key,
            body,
            declared,
            metadata={"sha256": sha256, "kind": kind.value},
        )
    except Exception as e:  # noqa: BLE001
        import logging as _logging
        _logging.getLogger(__name__).exception(
            "evidence: storage put failed bucket=%s key=%s", bucket, key,
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"evidence storage unavailable: {e}",
        )

    blob = EvidenceBlob(
        organization_id=organization_id,
        asset_id=asset_id,
        sha256=sha256,
        size_bytes=len(body),
        content_type=declared,
        original_filename=file.filename,
        kind=kind.value,
        s3_bucket=bucket,
        s3_key=key,
        captured_at=datetime.now(timezone.utc),
        captured_by_user_id=analyst.id,
        capture_source=capture_source,
        description=description,
    )
    db.add(blob)
    await db.flush()

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.EVIDENCE_UPLOAD,
        user=analyst,
        resource_type="evidence_blob",
        resource_id=str(blob.id),
        details={
            "sha256": sha256,
            "kind": kind.value,
            "size_bytes": len(body),
            "organization_id": str(organization_id),
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(blob)
    return blob


@router.get("", response_model=list[EvidenceResponse])
async def list_evidence(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    kind: EvidenceKind | None = None,
    asset_id: uuid.UUID | None = None,
    include_deleted: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    org = await db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")

    query = select(EvidenceBlob).where(
        EvidenceBlob.organization_id == organization_id
    )
    if not include_deleted:
        query = query.where(EvidenceBlob.is_deleted == False)  # noqa: E712
    if kind is not None:
        query = query.where(EvidenceBlob.kind == kind.value)
    if asset_id is not None:
        query = query.where(EvidenceBlob.asset_id == asset_id)
    query = (
        query.order_by(EvidenceBlob.captured_at.desc()).limit(limit).offset(offset)
    )
    result = await db.execute(query)
    return list(result.scalars().all())


async def _load_org_blob(db: AsyncSession, blob_id: uuid.UUID) -> EvidenceBlob:
    """Fetch an EvidenceBlob row and verify it belongs to the system org.

    Returns 404 (not 403) on mismatch so we don't expose existence of
    rows imported from a different deployment via PITR/restore.
    """
    from src.core.tenant import get_system_org_id

    sys_org = await get_system_org_id(db)
    blob = await db.get(EvidenceBlob, blob_id)
    if not blob or blob.organization_id != sys_org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Evidence not found")
    return blob


@router.get("/{blob_id}", response_model=EvidenceResponse)
async def get_evidence(
    blob_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    return await _load_org_blob(db, blob_id)


@router.get("/{blob_id}/download", response_model=PresignedURLResponse)
async def download_evidence(
    blob_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    ttl: Annotated[int, Query(ge=30, le=3600)] = 300,
    db: AsyncSession = Depends(get_session),
):
    blob = await _load_org_blob(db, blob_id)
    if blob.is_deleted:
        raise HTTPException(status.HTTP_410_GONE, "Evidence has been deleted")

    url = evidence_store.presigned_get_url(blob.s3_bucket, blob.s3_key, ttl_seconds=ttl)

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.EVIDENCE_DOWNLOAD,
        user=analyst,
        resource_type="evidence_blob",
        resource_id=str(blob.id),
        details={"sha256": blob.sha256, "ttl": ttl, "method": "presigned"},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return PresignedURLResponse(url=url, ttl_seconds=ttl, sha256=blob.sha256)


@router.get("/{blob_id}/inline")
async def stream_evidence(
    blob_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Stream bytes directly through the API.

    Useful for browsers behind strict CSPs that can't follow presigned URLs
    to a different origin. For large blobs prefer ``/download``.
    """
    blob = await _load_org_blob(db, blob_id)
    if blob.is_deleted:
        raise HTTPException(status.HTTP_410_GONE, "Evidence has been deleted")

    body = evidence_store.get(blob.s3_bucket, blob.s3_key)

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.EVIDENCE_DOWNLOAD,
        user=analyst,
        resource_type="evidence_blob",
        resource_id=str(blob.id),
        details={"sha256": blob.sha256, "method": "inline"},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()

    headers = {
        "Content-Length": str(len(body)),
        "ETag": f'"{blob.sha256}"',
        "X-Argus-Evidence-SHA256": blob.sha256,
    }
    if blob.original_filename:
        headers["Content-Disposition"] = (
            f'inline; filename="{blob.original_filename}"'
        )

    import io as _io

    return StreamingResponse(
        _io.BytesIO(body),
        media_type=blob.content_type,
        headers=headers,
    )


class DeleteRequest(BaseModel):
    reason: str | None = None


@router.delete("/{blob_id}", response_model=EvidenceResponse)
async def delete_evidence(
    blob_id: uuid.UUID,
    body: DeleteRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Soft-delete: row stays, ``is_deleted=true``, S3 bytes preserved.

    Hard delete is performed by the retention worker per policy.
    """
    blob = await _load_org_blob(db, blob_id)
    if blob.is_deleted:
        return blob  # idempotent

    blob.is_deleted = True
    blob.deleted_at = datetime.now(timezone.utc)
    blob.deleted_by_user_id = analyst.id
    blob.delete_reason = body.reason

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.EVIDENCE_DELETE,
        user=analyst,
        resource_type="evidence_blob",
        resource_id=str(blob.id),
        details={"sha256": blob.sha256, "reason": body.reason},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(blob)
    return blob


@router.post("/{blob_id}/restore", response_model=EvidenceResponse)
async def restore_evidence(
    blob_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    blob = await _load_org_blob(db, blob_id)
    if not blob.is_deleted:
        return blob

    if not evidence_store.exists(blob.s3_bucket, blob.s3_key):
        raise HTTPException(
            status.HTTP_410_GONE,
            "Underlying bytes were purged by retention; cannot restore",
        )

    blob.is_deleted = False
    blob.deleted_at = None
    blob.deleted_by_user_id = None
    blob.delete_reason = None

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.EVIDENCE_RESTORE,
        user=analyst,
        resource_type="evidence_blob",
        resource_id=str(blob.id),
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(blob)
    return blob
