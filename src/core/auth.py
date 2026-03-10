"""Authentication core — JWT tokens, password hashing, FastAPI dependencies."""

import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Annotated

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.models.auth import APIKey, AuditAction, AuditLog, User, UserRole
from src.storage.database import get_session

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

_bearer_scheme = HTTPBearer(auto_error=False)

# JWT configuration
_configured_secret = settings.jwt_secret
if not _configured_secret:
    import secrets as _s
    _configured_secret = _s.token_hex(64)
    import logging
    logging.getLogger(__name__).warning(
        "ARGUS_JWT_SECRET not set — generated ephemeral secret. "
        "Tokens will not survive restarts. Set ARGUS_JWT_SECRET in .env for persistence."
    )
JWT_SECRET = _configured_secret
JWT_ALGORITHM = "HS256"
JWT_ACCESS_EXPIRE_MINUTES = 60 * 24  # 24 hours
JWT_REFRESH_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days


# --- Password Hashing ---


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password: str, hash: str) -> bool:
    try:
        return ph.verify(hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hash: str) -> bool:
    return ph.check_needs_rehash(hash)


# --- API Key Hashing ---


def generate_api_key() -> tuple[str, str, str]:
    """Generate a new API key. Returns (raw_key, key_hash, key_prefix)."""
    raw_key = f"argus_{secrets.token_urlsafe(48)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:12]
    return raw_key, key_hash, key_prefix


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


# --- JWT ---


def create_access_token(user_id: str, role: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "email": email,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=JWT_ACCESS_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "type": "refresh",
        "iat": now,
        "exp": now + timedelta(minutes=JWT_REFRESH_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


# --- FastAPI Dependencies ---


async def _resolve_user_from_bearer(
    credentials: HTTPAuthorizationCredentials,
    db: AsyncSession,
) -> User:
    """Resolve a user from a JWT bearer token."""
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token type")

    user = await db.get(User, payload["sub"])
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")
    return user


async def _resolve_user_from_api_key(
    api_key_value: str,
    db: AsyncSession,
) -> User:
    """Resolve a user from an API key (X-API-Key header or query param)."""
    key_hash = hash_api_key(api_key_value)
    result = await db.execute(
        select(APIKey).where(APIKey.key_hash == key_hash, APIKey.is_active == True)
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")

    # Check expiry
    if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API key expired")

    # Update last used
    api_key.last_used_at = datetime.now(timezone.utc)
    await db.commit()

    user = await db.get(User, api_key.user_id)
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")
    return user


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_session),
) -> User:
    """Extract authenticated user from JWT bearer token or X-API-Key header."""
    # Try API key header first
    api_key_value = request.headers.get("X-API-Key")
    if api_key_value:
        return await _resolve_user_from_api_key(api_key_value, db)

    # Try bearer token
    if credentials:
        return await _resolve_user_from_bearer(credentials, db)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide Bearer token or X-API-Key header.",
    )


async def get_optional_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    db: AsyncSession = Depends(get_session),
) -> User | None:
    """Like get_current_user but returns None instead of raising for unauthenticated requests."""
    try:
        return await get_current_user(request, credentials, db)
    except HTTPException:
        return None


def require_role(*roles: UserRole):
    """Dependency factory: require the current user to have one of the specified roles."""
    async def _check(user: User = Depends(get_current_user)):
        if user.role not in [r.value for r in roles]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {', '.join(r.value for r in roles)}",
            )
        return user
    return _check


# Type aliases for route signatures
CurrentUser = Annotated[User, Depends(get_current_user)]
AdminUser = Annotated[User, Depends(require_role(UserRole.ADMIN))]
AnalystUser = Annotated[User, Depends(require_role(UserRole.ADMIN, UserRole.ANALYST))]


# --- Audit Logging ---


async def audit_log(
    db: AsyncSession,
    action: AuditAction,
    user: User | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
):
    """Record an action in the audit log."""
    log_entry = AuditLog(
        user_id=user.id if user else None,
        action=action.value,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(log_entry)
    await db.flush()  # don't commit — let the caller's transaction handle it
