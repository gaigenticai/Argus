"""Authentication endpoints — login, register, token refresh, profile."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import (
    CurrentUser,
    audit_log,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    needs_rehash,
    verify_password,
)
from src.models.auth import AuditAction, User, UserRole
from src.storage.database import get_session
from src.core.rate_limit import login_limiter, register_limiter

router = APIRouter(prefix="/auth", tags=["auth"])


# --- Schemas ---


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: "UserResponse"


class RefreshRequest(BaseModel):
    refresh_token: str


class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RegisterRequest(BaseModel):
    email: str = Field(..., pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    username: str = Field(..., min_length=2, max_length=100)
    password: str = Field(..., min_length=8, max_length=128)
    display_name: str = Field(..., min_length=1, max_length=255)
    role: str = UserRole.VIEWER.value


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    username: str
    display_name: str
    role: str
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ProfileUpdate(BaseModel):
    display_name: str | None = None
    current_password: str | None = None
    new_password: str | None = None


# --- Helpers ---


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _user_agent(request: Request) -> str:
    return request.headers.get("User-Agent", "unknown")[:500]


# --- Endpoints ---


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_session),
):
    """Authenticate with email and password, receive JWT tokens."""
    await login_limiter.check(request)

    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password_hash):
        # Log failed attempt (with email in details, no user object if not found)
        await audit_log(
            db,
            AuditAction.LOGIN_FAILED,
            user=user,
            resource_type="auth",
            details={"email": body.email},
            ip_address=_client_ip(request),
            user_agent=_user_agent(request),
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    # Rehash password if argon2 parameters have changed
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)

    # Update login metadata
    user.last_login_at = datetime.now(timezone.utc)
    user.last_login_ip = _client_ip(request)

    # Audit log
    await audit_log(
        db,
        AuditAction.LOGIN,
        user=user,
        resource_type="auth",
        ip_address=_client_ip(request),
        user_agent=_user_agent(request),
    )
    await db.commit()

    access_token = create_access_token(str(user.id), user.role, user.email)
    refresh_token = create_refresh_token(str(user.id))

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse.model_validate(user),
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_session),
):
    """Register a new user.

    If no users exist yet, the first user is automatically promoted to admin
    (bootstrap mode). Otherwise, this endpoint requires an admin bearer token.
    """
    await register_limiter.check(request)

    # Count existing users to decide if this is bootstrap
    count_result = await db.execute(select(func.count()).select_from(User))
    user_count = count_result.scalar() or 0

    is_bootstrap = user_count == 0

    if not is_bootstrap:
        # Require admin authentication — resolve caller from bearer token
        caller = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            payload = decode_token(token)
            if payload.get("type") == "access":
                caller = await db.get(User, payload["sub"])
                if caller and not caller.is_active:
                    caller = None

        if caller is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. First user auto-registers as admin; subsequent users require admin.",
            )
        if caller.role != UserRole.ADMIN.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can register new users",
            )
    else:
        caller = None

    # Check uniqueness
    existing_email = await db.execute(select(User).where(User.email == body.email))
    if existing_email.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    existing_username = await db.execute(select(User).where(User.username == body.username))
    if existing_username.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    # Validate role
    try:
        UserRole(body.role)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role: {body.role}. Must be one of: {', '.join(r.value for r in UserRole)}",
        )

    # Bootstrap: first user is always admin
    role = UserRole.ADMIN.value if is_bootstrap else body.role

    user = User(
        email=body.email,
        username=body.username,
        password_hash=hash_password(body.password),
        display_name=body.display_name,
        role=role,
        is_active=True,
    )
    db.add(user)
    await db.flush()

    await audit_log(
        db,
        AuditAction.USER_CREATE,
        user=caller,
        resource_type="user",
        resource_id=str(user.id),
        details={
            "email": user.email,
            "username": user.username,
            "role": role,
            "bootstrap": is_bootstrap,
        },
        ip_address=_client_ip(request),
        user_agent=_user_agent(request),
    )
    await db.commit()
    await db.refresh(user)

    return user


@router.post("/refresh", response_model=RefreshResponse)
async def refresh_token(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_session),
):
    """Exchange a refresh token for a new access token."""
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type — expected refresh token",
        )

    user = await db.get(User, payload["sub"])
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    access_token = create_access_token(str(user.id), user.role, user.email)
    return RefreshResponse(access_token=access_token)


@router.get("/me", response_model=UserResponse)
async def get_profile(user: CurrentUser):
    """Get the current authenticated user's profile."""
    return user


@router.patch("/me", response_model=UserResponse)
async def update_profile(
    body: ProfileUpdate,
    request: Request,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Update the current user's display name or password."""
    changes: dict = {}

    if body.display_name is not None:
        user.display_name = body.display_name
        changes["display_name"] = body.display_name

    if body.new_password is not None:
        if body.current_password is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="current_password is required to change password",
            )
        if not verify_password(body.current_password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect",
            )
        user.password_hash = hash_password(body.new_password)
        changes["password"] = "changed"

    if not changes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update",
        )

    await audit_log(
        db,
        AuditAction.USER_UPDATE,
        user=user,
        resource_type="user",
        resource_id=str(user.id),
        details={"fields": list(changes.keys())},
        ip_address=_client_ip(request),
        user_agent=_user_agent(request),
    )
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Log out (records audit event). Client should discard tokens."""
    await audit_log(
        db,
        AuditAction.LOGOUT,
        user=user,
        resource_type="auth",
        ip_address=_client_ip(request),
        user_agent=_user_agent(request),
    )
    await db.commit()
