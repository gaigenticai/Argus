"""Audit E7 — GDPR right-to-be-forgotten endpoint."""

from __future__ import annotations

import hashlib

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from src.models.auth import AuditAction, AuditLog, User

pytestmark = pytest.mark.asyncio


def _hdr(u): return u["headers"]


async def test_gdpr_forget_deletes_user_preserves_audit(
    client: AsyncClient, admin_user, analyst_user, test_engine
):
    """Admin invokes GDPR forget on the analyst. The User row vanishes,
    api_keys cascade, audit_logs.user_id flips to NULL but the action
    record survives, and a `USER_DELETE` row carries the email-SHA256
    so we can correlate without keeping the address itself."""
    target_id = analyst_user["user_id"]
    target_email = analyst_user["email"]

    r = await client.post(
        "/api/v1/users/gdpr/forget",
        json={
            "user_id": str(target_id),
            "reason": "DPO ticket DPO-2026-042 — subject erasure request",
        },
        headers=_hdr(admin_user),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user_id"] == str(target_id)

    # User row is gone.
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        u = (await s.execute(select(User).where(User.id == target_id))).scalar_one_or_none()
        assert u is None, "user row should be hard-deleted"

        # USER_DELETE audit row exists with hashed email, no plaintext.
        rows = (
            await s.execute(
                select(AuditLog)
                .where(AuditLog.action == AuditAction.USER_DELETE.value)
                .order_by(AuditLog.timestamp.desc())
                .limit(5)
            )
        ).scalars().all()
        gdpr_row = next(
            (r for r in rows if r.details and r.details.get("gdpr") is True),
            None,
        )
        assert gdpr_row is not None, "GDPR audit row not found"
        assert gdpr_row.details["email_sha256"] == hashlib.sha256(
            target_email.encode("utf-8")
        ).hexdigest()
        assert "email" not in gdpr_row.details, "must not retain plaintext email"


async def test_gdpr_forget_self_rejected(client: AsyncClient, admin_user):
    """An admin cannot GDPR-erase their own account — would lock the
    deployment out."""
    r = await client.post(
        "/api/v1/users/gdpr/forget",
        json={
            "user_id": str(admin_user["user_id"]),
            "reason": "self-erase attempt should fail",
        },
        headers=_hdr(admin_user),
    )
    assert r.status_code == 400


async def test_gdpr_forget_requires_admin(
    client: AsyncClient, analyst_user, admin_user
):
    """Non-admin can't invoke GDPR endpoint."""
    r = await client.post(
        "/api/v1/users/gdpr/forget",
        json={
            "user_id": str(admin_user["user_id"]),
            "reason": "regular analyst trying privilege escalation",
        },
        headers=_hdr(analyst_user),
    )
    assert r.status_code == 403
