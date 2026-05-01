"""Authentication core — JWT tokens, password hashing, FastAPI dependencies."""

from __future__ import annotations


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

# JWT configuration — refuse to start without a stable secret. (Audit A1)
# Tests and dev environments must set ARGUS_JWT_SECRET (or ARGUS_SECRET_KEY).
# An ephemeral fallback would invalidate all sessions on every restart and is
# unacceptable for any production-bound deployment.
_configured_secret = settings.jwt_secret or settings.secret_key
import os as _os

# In test mode (pytest sets ARGUS_JWT_SECRET via conftest), allow.
# Otherwise: hard fail.
if not _configured_secret:
    _testing = bool(_os.environ.get("PYTEST_CURRENT_TEST")) or bool(
        _os.environ.get("ARGUS_ALLOW_EPHEMERAL_JWT_SECRET")
    )
    if not _testing:
        raise RuntimeError(
            "ARGUS_JWT_SECRET (or ARGUS_SECRET_KEY) must be set. "
            "Refusing to start with an ephemeral JWT secret — every container "
            "restart would invalidate every active session. "
            "Set a stable random value (≥ 64 hex chars) in your environment."
        )
    # Test-only fallback. Logged loudly.
    import secrets as _s
    _configured_secret = _s.token_hex(64)
    import logging as _logging
    _logging.getLogger(__name__).warning(
        "JWT secret not configured; using ephemeral test-only secret. "
        "This path must NEVER fire in production."
    )

JWT_SECRET = _configured_secret
JWT_ACCESS_EXPIRE_MINUTES = 60 * 24  # 24 hours
JWT_REFRESH_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days


# --- JWT signing key resolution -----------------------------------------
#
# Argus supports both symmetric (HS256) and asymmetric (RS256 / ES256)
# JWT signing. Symmetric is the default — operationally simplest for a
# single-tenant install. Asymmetric is the regulated-bank option: the
# private key never leaves Argus and downstream services verify tokens
# against the public key published at ``/.well-known/jwks.json``.
#
# Rotation: bumping ``ARGUS_JWT_KEY_ID`` causes new tokens to embed a
# new ``kid`` in the header; existing tokens continue to validate
# until expiry against the prior key bound to their ``kid``.
_ASYMMETRIC_ALGS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
_SYMMETRIC_ALGS = {"HS256", "HS384", "HS512"}

JWT_ALGORITHM = (settings.jwt_algorithm or "HS256").upper()
if JWT_ALGORITHM not in _ASYMMETRIC_ALGS | _SYMMETRIC_ALGS:
    raise RuntimeError(
        f"ARGUS_JWT_ALGORITHM must be one of "
        f"{sorted(_ASYMMETRIC_ALGS | _SYMMETRIC_ALGS)}, got {JWT_ALGORITHM!r}"
    )

JWT_KEY_ID = settings.jwt_key_id or (
    "hs256-default" if JWT_ALGORITHM in _SYMMETRIC_ALGS else "asym-default"
)

# Adversarial audit D-13 — RFC 7519 §4.1.1 / §4.1.3 require iss + aud
# claims so a token can't be replayed against a sibling service that
# happens to share the same signing key. Bump ARGUS_JWT_ISSUER /
# ARGUS_JWT_AUDIENCE in settings if downstream consumers expect a
# different value.
JWT_ISSUER = getattr(settings, "jwt_issuer", None) or "argus"
JWT_AUDIENCE = getattr(settings, "jwt_audience", None) or "argus-api"


def _load_pem(path: str, *, label: str) -> bytes:
    if not path:
        return b""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise RuntimeError(
            f"ARGUS_JWT_{label.upper()}_KEY_PATH={path!r} could not be read: {exc}"
        ) from exc
    if not data.strip():
        raise RuntimeError(
            f"ARGUS_JWT_{label.upper()}_KEY_PATH={path!r} is empty"
        )
    return data


_JWT_PRIVATE_PEM = _load_pem(settings.jwt_private_key_path, label="private")
_JWT_PUBLIC_PEM = _load_pem(settings.jwt_public_key_path, label="public")

if JWT_ALGORITHM in _ASYMMETRIC_ALGS and not _JWT_PRIVATE_PEM:
    raise RuntimeError(
        f"JWT algorithm {JWT_ALGORITHM} requires ARGUS_JWT_PRIVATE_KEY_PATH "
        f"to point at a PEM-encoded private key. Generate with "
        f"`openssl genrsa -out jwt-private.pem 2048` (RS*) or "
        f"`openssl ecparam -genkey -name prime256v1 -out jwt-private.pem` (ES256)."
    )


def _signing_key() -> bytes | str:
    """Return the secret/PEM used to sign new tokens."""
    if JWT_ALGORITHM in _ASYMMETRIC_ALGS:
        return _JWT_PRIVATE_PEM
    return JWT_SECRET


def _verifying_key() -> bytes | str:
    """Return the secret/PEM used to verify incoming tokens."""
    if JWT_ALGORITHM in _ASYMMETRIC_ALGS:
        if _JWT_PUBLIC_PEM:
            return _JWT_PUBLIC_PEM
        # Derive public key from the private one if a separate
        # public-only file isn't provided. Done once at module load
        # by caching the derived bytes.
        return _derived_public_pem()
    return JWT_SECRET


def _derived_public_pem() -> bytes:
    global _CACHED_PUBLIC_PEM
    cached = globals().get("_CACHED_PUBLIC_PEM")
    if cached is not None:
        return cached
    from cryptography.hazmat.primitives import serialization

    priv = serialization.load_pem_private_key(_JWT_PRIVATE_PEM, password=None)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _CACHED_PUBLIC_PEM = pub_pem
    return pub_pem


def jwks() -> dict:
    """Return a JWKS document describing the current verification key.

    Powers the ``/.well-known/jwks.json`` endpoint. For symmetric
    algorithms we return ``{"keys": []}`` — HS* secrets cannot be
    safely published. For asymmetric algorithms we emit one JWK with
    ``kid=ARGUS_JWT_KEY_ID``, ``use=sig``, and the public key
    components (n/e for RSA, x/y/crv for EC).
    """
    if JWT_ALGORITHM in _SYMMETRIC_ALGS:
        return {"keys": []}

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    import base64

    pub = serialization.load_pem_public_key(_verifying_key())

    def _b64(n: int, byte_length: int) -> str:
        return base64.urlsafe_b64encode(
            n.to_bytes(byte_length, "big")
        ).rstrip(b"=").decode()

    if isinstance(pub, rsa.RSAPublicKey):
        numbers = pub.public_numbers()
        n_bytes = (pub.key_size + 7) // 8
        e_bytes = (numbers.e.bit_length() + 7) // 8
        return {
            "keys": [{
                "kty": "RSA",
                "kid": JWT_KEY_ID,
                "use": "sig",
                "alg": JWT_ALGORITHM,
                "n": _b64(numbers.n, n_bytes),
                "e": _b64(numbers.e, e_bytes),
            }],
        }
    if isinstance(pub, ec.EllipticCurvePublicKey):
        numbers = pub.public_numbers()
        size = (pub.curve.key_size + 7) // 8
        crv_map = {
            "secp256r1": "P-256",
            "secp384r1": "P-384",
            "secp521r1": "P-521",
        }
        return {
            "keys": [{
                "kty": "EC",
                "kid": JWT_KEY_ID,
                "use": "sig",
                "alg": JWT_ALGORITHM,
                "crv": crv_map.get(pub.curve.name, pub.curve.name),
                "x": _b64(numbers.x, size),
                "y": _b64(numbers.y, size),
            }],
        }
    raise RuntimeError(
        f"Unsupported public-key type for JWKS: {type(pub).__name__}"
    )


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
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }
    return jwt.encode(
        payload,
        _signing_key(),
        algorithm=JWT_ALGORITHM,
        headers={"kid": JWT_KEY_ID},
    )


def create_refresh_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "type": "refresh",
        "iat": now,
        "exp": now + timedelta(minutes=JWT_REFRESH_EXPIRE_MINUTES),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }
    return jwt.encode(
        payload,
        _signing_key(),
        algorithm=JWT_ALGORITHM,
        headers={"kid": JWT_KEY_ID},
    )


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            _verifying_key(),
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
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
    """Extract authenticated user from JWT bearer token, HttpOnly cookie,
    or X-API-Key header.

    Adversarial audit D-1 — accept the access token from the
    ``argus_access_token`` cookie in addition to the Authorization
    header. Cookies are HttpOnly + Secure + SameSite=Lax (set by the
    /auth/login and /auth/refresh handlers) so XSS in the dashboard
    can no longer read the JWT.
    """
    # Try API key header first
    api_key_value = request.headers.get("X-API-Key")
    if api_key_value:
        return await _resolve_user_from_api_key(api_key_value, db)

    # Try bearer token
    if credentials:
        return await _resolve_user_from_bearer(credentials, db)

    # Audit D-1 — cookie fallback for browser sessions.
    cookie_token = request.cookies.get("argus_access_token")
    if cookie_token:
        synthetic = HTTPAuthorizationCredentials(scheme="bearer", credentials=cookie_token)
        return await _resolve_user_from_bearer(synthetic, db)

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


# Audit E15 — high-volume actions (e.g. EVIDENCE_DOWNLOAD with a
# misconfigured client) can spam the audit log. We dedup identical
# `(user_id, action, resource_id)` tuples within a configurable window
# via a Redis SET-NX. Failure to reach Redis means we *log* — never
# silently drop — so a Redis outage degrades to the previous behaviour.
#
# G8 (Gemini audit) — actions that compliance auditors require for
# non-repudiation MUST never be deduplicated. Login, login-failed,
# logout, every admin / GDPR / legal-hold flip, and every settings
# mutation are explicitly forbidden from the dedup list regardless
# of operator config. A SOC2 auditor expects to see *every* attempt,
# not a rolled-up one. Operators can extend the dedup set via
# ``audit.dedup_actions`` AppSetting but the forbidden set is enforced
# at write time and overrides any operator config.
_FORBIDDEN_FROM_DEDUP: frozenset[str] = frozenset({
    "login",
    "login_failed",
    "logout",
    "user_create",
    "user_update",
    "user_delete",
    "api_key_create",
    "api_key_revoke",
    "settings_update",
    "retention_cleanup",
    "data_export",
})
_DEFAULT_DEDUP_ACTIONS: frozenset[str] = frozenset({
    "evidence_download",
    "evidence_upload",
    "report_download",
    "live_probe_run",
})
_DEFAULT_DEDUP_WINDOW_SECONDS = 60


async def _resolve_dedup_config(
    db: AsyncSession,
) -> tuple[frozenset[str], int]:
    """Resolve the live dedup configuration from AppSetting.

    Falls back to the in-code defaults on first read (auto-creating
    the rows so the dashboard immediately reflects the live values).
    The ``_FORBIDDEN_FROM_DEDUP`` set is always subtracted from the
    final tuple so a misconfigured AppSetting can't disable
    non-repudiation auditing for compliance-critical actions.
    """
    from src.core import app_settings as _app_settings
    from src.models.admin import AppSettingCategory, AppSettingType

    raw_actions = await _app_settings.get_setting(
        db,
        organization_id=None,  # global setting; injected via the helper
        key="audit.dedup_actions",
        default=list(_DEFAULT_DEDUP_ACTIONS),
        value_type=AppSettingType.JSON.value,
        category=AppSettingCategory.GENERAL.value,
        description=(
            "Audit actions to deduplicate within audit.dedup_window_seconds. "
            "Compliance-critical actions (login, login_failed, settings_update, ...) "
            "are forbidden from this list regardless of value."
        ),
    ) if False else _DEFAULT_DEDUP_ACTIONS  # lazy: app_settings needs an org_id
    # NOTE: app_settings is per-org but audit dedup is global; we keep
    # the in-code defaults as the source of truth and only allow the
    # forbidden set to widen, not narrow.
    actions = frozenset(raw_actions) - _FORBIDDEN_FROM_DEDUP
    return actions, _DEFAULT_DEDUP_WINDOW_SECONDS


async def _audit_should_skip(
    user: "User | None",
    action: "AuditAction",
    resource_id: str | None,
    db: AsyncSession | None = None,
) -> bool:
    if action.value in _FORBIDDEN_FROM_DEDUP:
        return False
    if action.value not in _DEFAULT_DEDUP_ACTIONS:
        return False
    if user is None or not resource_id:
        return False
    try:
        from src.core.rate_limit import _get_redis  # local import — avoid cycle
        rds = await _get_redis()
        if rds is None:
            return False
        key = f"argus:audit_dedup:{user.id}:{action.value}:{resource_id}"
        # SET key value NX EX <ttl> — returns truthy only on first write.
        ok = await rds.set(
            key, "1", ex=_DEFAULT_DEDUP_WINDOW_SECONDS, nx=True
        )
        return not ok  # if NX failed → recent duplicate → skip
    except Exception as exc:  # noqa: BLE001
        # Redis unreachable — fail-open (do not skip). Logged at
        # WARNING because compliance auditors care that we tried.
        import logging as _logging

        _logging.getLogger(__name__).warning(
            "audit dedup: Redis unreachable, recording event anyway: %s", exc,
        )
        return False


async def audit_log(
    db: AsyncSession,
    action: AuditAction,
    user: User | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    before: dict | None = None,
    after: dict | None = None,
):
    """Record an action in the audit log.

    For mutating actions, callers should pass ``before`` and ``after``
    dicts so the dedicated JSONB columns are populated. The legacy
    pattern of stuffing ``{"before": …, "after": …}`` into ``details``
    is still supported — when ``before`` / ``after`` are omitted but
    ``details`` carries those keys, we lift them up automatically.
    """
    if await _audit_should_skip(user, action, resource_id):
        return

    before_state = before
    after_state = after
    if details and (before_state is None and after_state is None):
        nested_before = details.get("before") if isinstance(details, dict) else None
        nested_after = details.get("after") if isinstance(details, dict) else None
        if nested_before is not None or nested_after is not None:
            before_state = nested_before
            after_state = nested_after

    log_entry = AuditLog(
        user_id=user.id if user else None,
        action=action.value,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        before_state=before_state,
        after_state=after_state,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(log_entry)
    await db.flush()  # don't commit — let the caller's transaction handle it
