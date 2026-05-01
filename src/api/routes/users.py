"""User management endpoints — admin CRUD and API key management."""

from __future__ import annotations


import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc, text
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import (
    AdminUser,
    CurrentUser,
    audit_log,
    generate_api_key,
    hash_password,
)
from src.models.auth import APIKey, AuditAction, AuditLog, User, UserRole
from src.storage.database import get_session

router = APIRouter(prefix="/users", tags=["Auth & Identity"])


# --- Schemas ---


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    username: str
    display_name: str
    role: str
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    role: str | None = None
    is_active: bool | None = None
    display_name: str | None = None


class UserListResponse(BaseModel):
    users: list[UserResponse]
    total: int


class APIKeyCreate(BaseModel):
    name: str
    expires_at: datetime | None = None


class APIKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    key_prefix: str
    is_active: bool
    last_used_at: datetime | None
    expires_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class APIKeyCreatedResponse(APIKeyResponse):
    """Returned only on creation — includes the raw key (shown once)."""
    raw_key: str


# --- Helpers ---


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _user_agent(request: Request) -> str:
    return request.headers.get("User-Agent", "unknown")[:500]


def _is_admin_or_self(caller: User, target_user_id: uuid.UUID) -> bool:
    return caller.role == UserRole.ADMIN.value or caller.id == target_user_id


# --- User Admin Endpoints ---


@router.get("/", response_model=UserListResponse)
async def list_users(
    admin: AdminUser,
    limit: int = Query(50, le=200),
    offset: int = 0,
    is_active: bool | None = None,
    role: str | None = None,
    db: AsyncSession = Depends(get_session),
):
    """List all users (admin only)."""
    query = select(User).order_by(desc(User.created_at))

    if is_active is not None:
        query = query.where(User.is_active == is_active)
    if role is not None:
        query = query.where(User.role == role)

    # Total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    users = result.scalars().all()

    return UserListResponse(users=users, total=total)


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: uuid.UUID,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Get user detail (admin only)."""
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return user


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Update user role, active status, or display name (admin only)."""
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    changes: dict = {}

    if body.role is not None:
        try:
            UserRole(body.role)
        except ValueError:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"Invalid role: {body.role}. Must be one of: {', '.join(r.value for r in UserRole)}",
            )
        user.role = body.role
        changes["role"] = body.role

    if body.is_active is not None:
        # Prevent admin from deactivating themselves
        if user.id == admin.id and not body.is_active:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Cannot deactivate your own account",
            )
        user.is_active = body.is_active
        changes["is_active"] = body.is_active

    if body.display_name is not None:
        user.display_name = body.display_name
        changes["display_name"] = body.display_name

    if not changes:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No fields to update")

    await audit_log(
        db,
        AuditAction.USER_UPDATE,
        user=admin,
        resource_type="user",
        resource_id=str(user.id),
        details=changes,
        ip_address=_client_ip(request),
        user_agent=_user_agent(request),
    )
    await db.commit()
    await db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_user(
    user_id: uuid.UUID,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Soft-delete a user by setting is_active=False (admin only)."""
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    if user.id == admin.id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Cannot deactivate your own account",
        )

    user.is_active = False

    await audit_log(
        db,
        AuditAction.USER_DELETE,
        user=admin,
        resource_type="user",
        resource_id=str(user.id),
        details={"email": user.email, "username": user.username},
        ip_address=_client_ip(request),
        user_agent=_user_agent(request),
    )
    await db.commit()


# --- Audit E7 — GDPR right-to-be-forgotten ----------------------------


class GdprForgetRequest(BaseModel):
    user_id: uuid.UUID
    reason: str = Field(
        ..., min_length=10, max_length=500,
        description=(
            "GDPR Art.17 erasure request reference (e.g. ticket id + a "
            "human description). Recorded in the audit trail; the original "
            "email/username are NOT preserved."
        ),
    )


class GdprForgetResponse(BaseModel):
    user_id: uuid.UUID
    purged_at: datetime
    audit_logs_anonymised: int


@router.post(
    "/gdpr/forget",
    response_model=GdprForgetResponse,
    summary="Erase a user's PII (GDPR Art.17)",
)
async def gdpr_forget(
    body: GdprForgetRequest,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Hard-delete a user record and break PII linkage in derivative
    tables. The audit log retains the action+timestamp via the
    ``users.id → audit_logs.user_id`` ON DELETE SET NULL constraint —
    we keep the *fact* of every operation, but the actor pointer
    becomes anonymous.

    The caller logs an audit row before the deletion completes, so
    there is always a paper trail of *who* invoked GDPR erasure on
    *whom* (recorded by user_id and an SHA-256 of the original email
    so future audits can correlate without holding the email itself).
    """
    user = await db.get(User, body.user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.id == admin.id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Cannot GDPR-erase your own account",
        )

    import hashlib as _hashlib
    email_hash = _hashlib.sha256(user.email.encode("utf-8")).hexdigest()

    # 1. Audit log first — we need the row to outlive the user.
    await audit_log(
        db,
        AuditAction.USER_DELETE,
        user=admin,
        resource_type="user",
        resource_id=str(user.id),
        details={
            "gdpr": True,
            "reason": body.reason,
            "email_sha256": email_hash,
            "username_sha256": _hashlib.sha256(
                user.username.encode("utf-8")
            ).hexdigest(),
        },
        ip_address=_client_ip(request),
        user_agent=_user_agent(request),
    )
    await db.flush()

    # 2. Anonymise audit_logs that *this user authored* — change details
    # blob to drop any PII we might have stored there. The user_id
    # pointer is set NULL by the FK; details is a JSONB owned by us.
    from sqlalchemy import update as _update
    anon_result = await db.execute(
        _update(AuditLog)
        .where(AuditLog.user_id == user.id)
        .values(details=text("'{\"anonymised\": true}'::jsonb"))
    )
    anonymised = anon_result.rowcount or 0

    # 3. Hard-delete the user. Cascades wipe api_keys + feedback;
    # FKs with SET NULL (audit_logs, cases.owner_user_id, etc.) flip
    # those columns to NULL.
    await db.delete(user)
    await db.commit()

    return GdprForgetResponse(
        user_id=body.user_id,
        purged_at=datetime.now(timezone.utc),
        audit_logs_anonymised=int(anonymised),
    )


# --- API Key Endpoints ---


@router.post("/{user_id}/api-keys", response_model=APIKeyCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    user_id: uuid.UUID,
    body: APIKeyCreate,
    request: Request,
    caller: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Create an API key for a user (admin or own account)."""
    if not _is_admin_or_self(caller, user_id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Can only manage your own API keys")

    # Verify target user exists
    target_user = await db.get(User, user_id)
    if not target_user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    raw_key, key_hash, key_prefix = generate_api_key()

    api_key = APIKey(
        user_id=user_id,
        name=body.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        is_active=True,
        expires_at=body.expires_at,
    )
    db.add(api_key)
    await db.flush()

    await audit_log(
        db,
        AuditAction.API_KEY_CREATE,
        user=caller,
        resource_type="api_key",
        resource_id=str(api_key.id),
        details={"name": body.name, "target_user_id": str(user_id), "key_prefix": key_prefix},
        ip_address=_client_ip(request),
        user_agent=_user_agent(request),
    )
    await db.commit()
    await db.refresh(api_key)

    return APIKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        is_active=api_key.is_active,
        last_used_at=api_key.last_used_at,
        expires_at=api_key.expires_at,
        created_at=api_key.created_at,
        raw_key=raw_key,
    )


@router.get("/{user_id}/api-keys", response_model=list[APIKeyResponse])
async def list_api_keys(
    user_id: uuid.UUID,
    caller: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """List API keys for a user (admin or own account)."""
    if not _is_admin_or_self(caller, user_id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Can only view your own API keys")

    result = await db.execute(
        select(APIKey)
        .where(APIKey.user_id == user_id)
        .order_by(desc(APIKey.created_at))
    )
    return result.scalars().all()


@router.delete("/{user_id}/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    user_id: uuid.UUID,
    key_id: uuid.UUID,
    request: Request,
    caller: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Revoke an API key (admin or own account)."""
    if not _is_admin_or_self(caller, user_id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Can only manage your own API keys")

    api_key = await db.get(APIKey, key_id)
    if not api_key or api_key.user_id != user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")

    api_key.is_active = False

    await audit_log(
        db,
        AuditAction.API_KEY_REVOKE,
        user=caller,
        resource_type="api_key",
        resource_id=str(key_id),
        details={"name": api_key.name, "key_prefix": api_key.key_prefix},
        ip_address=_client_ip(request),
        user_agent=_user_agent(request),
    )
    await db.commit()
