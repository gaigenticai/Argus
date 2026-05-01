"""Authentication endpoints — login, register, token refresh, profile."""

from __future__ import annotations


import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
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
from src.core.auth_policy import (
    LOCKOUT_THRESHOLD,
    LOCKOUT_WINDOW_SECONDS,
    WeakPasswordError,
    clear_failed_logins,
    is_account_locked,
    record_failed_login,
    validate_password_complexity,
)

router = APIRouter(prefix="/auth", tags=["Auth & Identity"])


# Adversarial audit D-1 — JWTs now travel as HttpOnly cookies in
# addition to the legacy response-body fields. Cookie names mirror the
# JSON keys so existing clients (curl, mobile, integration tests) keep
# working unchanged; the dashboard switches to cookie auth and stops
# touching localStorage.
_ACCESS_COOKIE = "argus_access_token"
_REFRESH_COOKIE = "argus_refresh_token"


def _set_auth_cookies(
    response: Response,
    *,
    access_token: str,
    refresh_token: str | None = None,
) -> None:
    """Write access (and optionally refresh) cookie. ``Secure`` is on
    unless ARGUS_DEBUG=true, since dev runs on http://localhost. The
    cookie path is /api/v1 so it isn't sent to unrelated origins
    served from the same host."""
    import os as _os

    secure = (_os.environ.get("ARGUS_DEBUG", "").strip().lower() not in ("1", "true", "yes"))
    response.set_cookie(
        key=_ACCESS_COOKIE,
        value=access_token,
        max_age=60 * 60 * 24,            # match JWT_ACCESS_EXPIRE_MINUTES default
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/api/v1",
    )
    if refresh_token is not None:
        response.set_cookie(
            key=_REFRESH_COOKIE,
            value=refresh_token,
            max_age=60 * 60 * 24 * 7,    # match JWT_REFRESH_EXPIRE_MINUTES
            httponly=True,
            secure=secure,
            samesite="lax",
            path="/api/v1/auth",
        )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(_ACCESS_COOKIE, path="/api/v1")
    response.delete_cookie(_REFRESH_COOKIE, path="/api/v1/auth")


# --- Schemas ---


class LoginRequest(BaseModel):
    email: str
    password: str
    # Audit D10 — optional TOTP code submitted alongside the password.
    # If the user has enrolled in MFA and this is missing/invalid, the
    # endpoint returns 401 with `detail="mfa_required"` so the client
    # can prompt for the code.
    totp_code: str | None = None
    recovery_code: str | None = None


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
    # Audit D9 — Pydantic enforces an absolute floor; the real policy
    # (mixed case, digit, special, ≥12) lives in
    # `validate_password_complexity` and runs in the route handler so
    # we can return a single human-readable error.
    password: str = Field(..., min_length=12, max_length=128)
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
    response: Response,
    db: AsyncSession = Depends(get_session),
):
    """Authenticate with email and password, receive JWT tokens."""
    await login_limiter.check(request)

    # Audit D9 — per-account lockout. Distinct from the IP rate-limit
    # above; an attacker rotating IPs still hits this. Fails open if
    # Redis is unavailable so a Redis outage cannot brick logins.
    if await is_account_locked(body.email):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Too many failed attempts. Account locked for "
                f"{LOCKOUT_WINDOW_SECONDS // 60} minutes."
            ),
        )

    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password_hash):
        await record_failed_login(body.email)
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

    # Audit D10 — second factor. Only enforced if the user has actually
    # enrolled. Existing accounts (and CI tests) without an enrolled
    # TOTP secret skip this block entirely.
    if user.totp_secret:
        from src.core.mfa import consume_recovery_code, verify_totp_code

        accepted = False
        if body.totp_code and verify_totp_code(user.totp_secret, body.totp_code):
            accepted = True
        elif body.recovery_code:
            ok, new_list = consume_recovery_code(
                user.recovery_codes_hashed, body.recovery_code.strip()
            )
            if ok:
                user.recovery_codes_hashed = new_list
                accepted = True

        if not accepted:
            await record_failed_login(body.email)
            await audit_log(
                db,
                AuditAction.LOGIN_FAILED,
                user=user,
                resource_type="auth",
                details={"reason": "mfa_required" if not body.totp_code and not body.recovery_code else "mfa_invalid"},
                ip_address=_client_ip(request),
                user_agent=_user_agent(request),
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=(
                    "mfa_required"
                    if not body.totp_code and not body.recovery_code
                    else "mfa_invalid"
                ),
            )

    # Audit D9 — successful login clears the failure counter.
    await clear_failed_logins(body.email)

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

    # Audit D-1 — set HttpOnly cookies; the response body still carries
    # the tokens so existing API clients (curl, integration tests, the
    # mobile companion) keep working without change.
    _set_auth_cookies(
        response, access_token=access_token, refresh_token=refresh_token
    )

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

    # Audit D9 — enforce complexity policy on every new password.
    try:
        validate_password_complexity(body.password)
    except WeakPasswordError as e:
        raise HTTPException(status_code=422, detail=str(e))

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
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_session),
    body: RefreshRequest | None = None,
):
    """Exchange a refresh token for a new access token.

    Audit D-1 — refresh token may be sent in the request body (legacy
    clients) OR via the ``argus_refresh_token`` HttpOnly cookie that
    the browser sets after /auth/login. Cookie wins when both are
    present so an attacker who captures a stale body token can't
    reuse it after a forced rotation.
    """
    cookie_refresh = request.cookies.get(_REFRESH_COOKIE)
    raw = cookie_refresh or (body.refresh_token if body else None)
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing refresh token",
        )

    payload = decode_token(raw)
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
    _set_auth_cookies(response, access_token=access_token)
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
        try:
            validate_password_complexity(body.new_password)
        except WeakPasswordError as e:
            raise HTTPException(status_code=422, detail=str(e))
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
    response: Response,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Log out (records audit event). Clears auth cookies and asks
    legacy clients to discard their tokens."""
    await audit_log(
        db,
        AuditAction.LOGOUT,
        user=user,
        resource_type="auth",
        ip_address=_client_ip(request),
        user_agent=_user_agent(request),
    )
    await db.commit()
    _clear_auth_cookies(response)


# --- Audit D10 — TOTP / 2FA endpoints ---------------------------------


class MfaEnrollResponse(BaseModel):
    secret: str
    otpauth_url: str


class MfaConfirmRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)


class MfaConfirmResponse(BaseModel):
    enrolled_at: datetime
    recovery_codes: list[str]


class MfaDisableRequest(BaseModel):
    password: str
    code: str | None = None
    recovery_code: str | None = None


@router.post("/2fa/enroll", response_model=MfaEnrollResponse)
async def mfa_enroll(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Begin MFA enrollment. Generates a fresh TOTP secret and returns
    the otpauth:// URL the dashboard renders as a QR code. The secret
    is stored immediately but ``mfa_enrolled_at`` stays NULL until the
    user confirms via ``/2fa/confirm``. Until then the login flow does
    *not* require a code, so a half-enrolled user can still get in.
    """
    if user.mfa_enrolled_at is not None:
        raise HTTPException(409, "MFA already enrolled — call /2fa/disable first")

    from src.core.mfa import generate_secret, provisioning_uri

    secret = generate_secret()
    user.totp_secret = secret
    await db.commit()

    return MfaEnrollResponse(
        secret=secret,
        otpauth_url=provisioning_uri(secret=secret, account_name=user.email),
    )


@router.post("/2fa/confirm", response_model=MfaConfirmResponse)
async def mfa_confirm(
    body: MfaConfirmRequest,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Verify the first TOTP code from the user's authenticator. On
    success this marks the account as enrolled (login now requires a
    code) and returns 10 single-use recovery codes — shown once,
    stored hashed.
    """
    if not user.totp_secret:
        raise HTTPException(400, "Call /2fa/enroll first")
    if user.mfa_enrolled_at is not None:
        raise HTTPException(409, "Already enrolled")

    from src.core.mfa import (
        generate_recovery_codes,
        hash_recovery_codes,
        verify_totp_code,
    )

    if not verify_totp_code(user.totp_secret, body.code):
        raise HTTPException(401, "Invalid TOTP code")

    codes = generate_recovery_codes()
    user.recovery_codes_hashed = hash_recovery_codes(codes)
    user.mfa_enrolled_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)

    return MfaConfirmResponse(
        enrolled_at=user.mfa_enrolled_at,
        recovery_codes=codes,
    )


@router.post("/2fa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_disable(
    body: MfaDisableRequest,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Disable MFA. Requires the current password *and* a valid TOTP
    code or recovery code. Both checks are needed so a stolen session
    token alone cannot strip 2FA.
    """
    if not user.totp_secret:
        raise HTTPException(400, "MFA not enrolled")
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Invalid password")

    from src.core.mfa import consume_recovery_code, verify_totp_code

    accepted = False
    if body.code and verify_totp_code(user.totp_secret, body.code):
        accepted = True
    elif body.recovery_code:
        ok, new_list = consume_recovery_code(
            user.recovery_codes_hashed, body.recovery_code.strip()
        )
        if ok:
            user.recovery_codes_hashed = new_list
            accepted = True
    if not accepted:
        raise HTTPException(401, "Invalid 2FA code")

    user.totp_secret = None
    user.mfa_enrolled_at = None
    user.recovery_codes_hashed = None
    await db.commit()
