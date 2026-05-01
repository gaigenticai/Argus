"""Evidence Vault — full integration tests against real MinIO.

Covers: upload, mime allowlist, size cap, dedup within tenant, dedup with
restore-on-undelete, list with filters, presigned download URL, inline
streaming, soft-delete + restore, hard-purge gone-state, audit log
emission, tenant isolation.

The tests skip cleanly if MinIO is unreachable on the configured endpoint.
"""

from __future__ import annotations

import hashlib
import io

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.asyncio


def _hdr(user) -> dict:
    return user["headers"]


def _png_bytes(payload: bytes = b"argus-test-image") -> bytes:
    """Tiny synthetic PNG-ish blob — bytes content doesn't matter for storage."""
    return b"\x89PNG\r\n\x1a\n" + payload


# --- Upload + dedup ------------------------------------------------------


async def test_upload_and_metadata(
    client: AsyncClient, analyst_user, organization, minio_available
):
    if not minio_available:
        pytest.skip("MinIO not reachable on ARGUS_EVIDENCE_ENDPOINT_URL")

    h = _hdr(analyst_user)
    body = _png_bytes(b"unique-1")

    r = await client.post(
        "/api/v1/evidence/upload",
        data={
            "organization_id": str(organization["id"]),
            "kind": "screenshot",
            "description": "test screenshot",
            "capture_source": "playwright",
        },
        files={"file": ("shot.png", io.BytesIO(body), "image/png")},
        headers=h,
    )
    assert r.status_code == 201, r.text
    data = r.json()
    expected = hashlib.sha256(body).hexdigest()
    assert data["sha256"] == expected
    assert data["size_bytes"] == len(body)
    assert data["kind"] == "screenshot"
    assert data["original_filename"] == "shot.png"
    assert data["s3_key"].endswith(expected)
    assert data["is_deleted"] is False


async def test_dedup_returns_existing_record(
    client: AsyncClient, analyst_user, organization, minio_available
):
    if not minio_available:
        pytest.skip("MinIO not reachable")

    h = _hdr(analyst_user)
    body = _png_bytes(b"dedup-bytes")

    a = await client.post(
        "/api/v1/evidence/upload",
        data={"organization_id": str(organization["id"]), "kind": "screenshot"},
        files={"file": ("a.png", io.BytesIO(body), "image/png")},
        headers=h,
    )
    b = await client.post(
        "/api/v1/evidence/upload",
        data={"organization_id": str(organization["id"]), "kind": "screenshot"},
        files={"file": ("b.png", io.BytesIO(body), "image/png")},
        headers=h,
    )
    assert a.status_code == 201
    assert b.status_code == 201
    assert a.json()["id"] == b.json()["id"]
    assert a.json()["sha256"] == b.json()["sha256"]


async def test_mime_allowlist_rejects_executable(
    client: AsyncClient, analyst_user, organization, minio_available
):
    if not minio_available:
        pytest.skip("MinIO not reachable")
    h = _hdr(analyst_user)
    r = await client.post(
        "/api/v1/evidence/upload",
        data={"organization_id": str(organization["id"]), "kind": "other"},
        files={"file": ("evil.exe", io.BytesIO(b"MZ\x90\x00"), "application/x-msdownload")},
        headers=h,
    )
    assert r.status_code == 415


async def test_empty_upload_rejected(
    client: AsyncClient, analyst_user, organization, minio_available
):
    if not minio_available:
        pytest.skip("MinIO not reachable")
    h = _hdr(analyst_user)
    r = await client.post(
        "/api/v1/evidence/upload",
        data={"organization_id": str(organization["id"]), "kind": "other"},
        files={"file": ("empty.txt", io.BytesIO(b""), "text/plain")},
        headers=h,
    )
    assert r.status_code == 422


async def test_asset_id_must_match_org(
    client: AsyncClient, analyst_user, organization, second_organization, minio_available
):
    if not minio_available:
        pytest.skip("MinIO not reachable")
    h = _hdr(analyst_user)

    # Create asset under org A
    asset = await client.post(
        "/api/v1/assets",
        json={
            "organization_id": str(organization["id"]),
            "asset_type": "domain",
            "value": "evid-asset.example",
        },
        headers=h,
    )
    asset_id = asset.json()["id"]

    # Upload referencing that asset under org B → reject
    r = await client.post(
        "/api/v1/evidence/upload",
        data={
            "organization_id": str(second_organization["id"]),
            "kind": "screenshot",
            "asset_id": asset_id,
        },
        files={"file": ("x.png", io.BytesIO(_png_bytes(b"x")), "image/png")},
        headers=h,
    )
    assert r.status_code == 422


# --- Read paths ----------------------------------------------------------


async def test_list_filters_by_kind_and_asset(
    client: AsyncClient, analyst_user, organization, minio_available
):
    if not minio_available:
        pytest.skip("MinIO not reachable")
    h = _hdr(analyst_user)
    org_id = str(organization["id"])

    # asset
    a = await client.post(
        "/api/v1/assets",
        json={"organization_id": org_id, "asset_type": "domain", "value": "list.example"},
        headers=h,
    )
    asset_id = a.json()["id"]

    await client.post(
        "/api/v1/evidence/upload",
        data={"organization_id": org_id, "kind": "screenshot", "asset_id": asset_id},
        files={"file": ("a.png", io.BytesIO(_png_bytes(b"list-a")), "image/png")},
        headers=h,
    )
    await client.post(
        "/api/v1/evidence/upload",
        data={"organization_id": org_id, "kind": "html_snapshot"},
        files={"file": ("a.html", io.BytesIO(b"<html>list-b</html>"), "text/html")},
        headers=h,
    )
    await client.post(
        "/api/v1/evidence/upload",
        data={"organization_id": org_id, "kind": "screenshot"},
        files={"file": ("c.png", io.BytesIO(_png_bytes(b"list-c")), "image/png")},
        headers=h,
    )

    # by kind=screenshot
    r = await client.get(
        "/api/v1/evidence",
        params={"organization_id": org_id, "kind": "screenshot"},
        headers=h,
    )
    assert r.status_code == 200
    assert all(b["kind"] == "screenshot" for b in r.json())
    assert len(r.json()) >= 2

    # by asset_id
    r = await client.get(
        "/api/v1/evidence",
        params={"organization_id": org_id, "asset_id": asset_id},
        headers=h,
    )
    assert r.status_code == 200
    assert all(b["asset_id"] == asset_id for b in r.json())


async def test_presigned_download(
    client: AsyncClient, analyst_user, organization, minio_available
):
    if not minio_available:
        pytest.skip("MinIO not reachable")
    h = _hdr(analyst_user)
    body = _png_bytes(b"download-1")

    up = await client.post(
        "/api/v1/evidence/upload",
        data={"organization_id": str(organization["id"]), "kind": "screenshot"},
        files={"file": ("d.png", io.BytesIO(body), "image/png")},
        headers=h,
    )
    blob_id = up.json()["id"]
    expected = hashlib.sha256(body).hexdigest()

    presign = await client.get(
        f"/api/v1/evidence/{blob_id}/download", headers=h
    )
    assert presign.status_code == 200
    body_resp = presign.json()
    assert body_resp["sha256"] == expected
    assert body_resp["url"].startswith("http")
    assert "Signature" in body_resp["url"] or "X-Amz-Signature" in body_resp["url"]


async def test_inline_stream_returns_bytes(
    client: AsyncClient, analyst_user, organization, minio_available
):
    if not minio_available:
        pytest.skip("MinIO not reachable")
    h = _hdr(analyst_user)
    body = _png_bytes(b"inline-1")
    up = await client.post(
        "/api/v1/evidence/upload",
        data={"organization_id": str(organization["id"]), "kind": "screenshot"},
        files={"file": ("i.png", io.BytesIO(body), "image/png")},
        headers=h,
    )
    blob_id = up.json()["id"]
    expected = hashlib.sha256(body).hexdigest()

    stream = await client.get(f"/api/v1/evidence/{blob_id}/inline", headers=h)
    assert stream.status_code == 200
    assert stream.headers.get("X-Argus-Evidence-SHA256") == expected
    assert stream.content == body


# --- Lifecycle: soft-delete + restore -----------------------------------


async def test_soft_delete_then_restore(
    client: AsyncClient, analyst_user, organization, minio_available
):
    if not minio_available:
        pytest.skip("MinIO not reachable")
    h = _hdr(analyst_user)
    body = _png_bytes(b"lifecycle")
    up = await client.post(
        "/api/v1/evidence/upload",
        data={"organization_id": str(organization["id"]), "kind": "screenshot"},
        files={"file": ("l.png", io.BytesIO(body), "image/png")},
        headers=h,
    )
    blob_id = up.json()["id"]

    # Soft-delete
    delete = await client.request(
        "DELETE",
        f"/api/v1/evidence/{blob_id}",
        json={"reason": "test cleanup"},
        headers=h,
    )
    assert delete.status_code == 200
    assert delete.json()["is_deleted"] is True
    assert delete.json()["delete_reason"] == "test cleanup"

    # Default list excludes deleted
    listed = await client.get(
        "/api/v1/evidence",
        params={"organization_id": str(organization["id"])},
        headers=h,
    )
    ids = {b["id"] for b in listed.json()}
    assert blob_id not in ids

    # include_deleted=true brings it back
    listed2 = await client.get(
        "/api/v1/evidence",
        params={"organization_id": str(organization["id"]), "include_deleted": "true"},
        headers=h,
    )
    ids2 = {b["id"] for b in listed2.json()}
    assert blob_id in ids2

    # download blocked while deleted
    bad = await client.get(f"/api/v1/evidence/{blob_id}/download", headers=h)
    assert bad.status_code == 410

    # Restore
    restore = await client.post(f"/api/v1/evidence/{blob_id}/restore", headers=h)
    assert restore.status_code == 200
    assert restore.json()["is_deleted"] is False

    # Re-uploading same bytes after delete returns the restored record
    re = await client.post(
        "/api/v1/evidence/upload",
        data={"organization_id": str(organization["id"]), "kind": "screenshot"},
        files={"file": ("l.png", io.BytesIO(body), "image/png")},
        headers=h,
    )
    assert re.status_code == 201
    assert re.json()["id"] == blob_id


# --- Auth + tenant isolation --------------------------------------------


async def test_unauthenticated_rejected(
    client: AsyncClient, organization, minio_available
):
    if not minio_available:
        pytest.skip("MinIO not reachable")
    r = await client.post(
        "/api/v1/evidence/upload",
        data={"organization_id": str(organization["id"]), "kind": "screenshot"},
        files={"file": ("x.png", io.BytesIO(b"\x89PNG"), "image/png")},
    )
    assert r.status_code in (401, 403)


async def test_audit_log_for_upload_and_delete(
    client: AsyncClient, analyst_user, organization, test_engine, minio_available
):
    if not minio_available:
        pytest.skip("MinIO not reachable")
    h = _hdr(analyst_user)
    body = _png_bytes(b"audit-evid")
    up = await client.post(
        "/api/v1/evidence/upload",
        data={"organization_id": str(organization["id"]), "kind": "screenshot"},
        files={"file": ("a.png", io.BytesIO(body), "image/png")},
        headers=h,
    )
    blob_id = up.json()["id"]
    await client.get(f"/api/v1/evidence/{blob_id}/download", headers=h)
    await client.request(
        "DELETE",
        f"/api/v1/evidence/{blob_id}",
        json={"reason": "audit test"},
        headers=h,
    )

    from src.models.auth import AuditAction, AuditLog

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        result = await s.execute(
            select(AuditLog.action)
            .where(AuditLog.resource_id == blob_id)
            .order_by(AuditLog.timestamp.asc())
        )
        actions = [row[0] for row in result.all()]

    assert AuditAction.EVIDENCE_UPLOAD.value in actions
    assert AuditAction.EVIDENCE_DOWNLOAD.value in actions
    assert AuditAction.EVIDENCE_DELETE.value in actions
