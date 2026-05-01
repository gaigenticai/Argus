"""TOTP-based two-factor authentication (Audit D10).

Why TOTP first, FIDO2 later:
- TOTP works on every device a customer has today (Authy, 1Password,
  Google Authenticator, hardware tokens that emulate TOTP).
- FIDO2 / WebAuthn requires browser flows + a registered authenticator
  per-user. We'll add it under the same `mfa_*` columns when a customer
  asks; until then TOTP closes 99% of the credential-stuffing risk.

Recovery codes:
- 10 single-use codes generated at enrollment, shown to the user once,
  stored hashed (argon2). Each code is consumed by setting it to
  ``None`` in the JSON list — no schema change needed to track use.
"""

from __future__ import annotations

import secrets
from typing import Iterable

import pyotp

from src.core.auth import hash_password, verify_password


_RECOVERY_CODE_COUNT = 10
_RECOVERY_CODE_BYTES = 8  # 8 bytes → 16 hex chars


def generate_secret() -> str:
    """Return a fresh base32-encoded TOTP secret."""
    return pyotp.random_base32()


def provisioning_uri(*, secret: str, account_name: str, issuer: str = "Argus") -> str:
    """Build the otpauth:// URI clients render as a QR code.

    ``account_name`` should be the user's email so it's readable in
    the authenticator app.
    """
    return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=issuer)


def verify_totp_code(secret: str, code: str, *, valid_window: int = 1) -> bool:
    """Constant-time check of a 6-digit code. ``valid_window=1`` accepts
    the previous and next 30-second slots to absorb clock skew.

    NOTE: this is the cheap pure-form check used by tests / re-auth flows.
    The login path must call :func:`verify_totp_code_with_guards`, which
    layers rate-limiting + a replay-window guard on top (adversarial
    audit D-14).
    """
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=valid_window)


# Adversarial audit D-14 — TOTP must be rate-limited and replay-resistant
# at the login boundary. The pure verify_totp_code helper above can't see
# Redis (kept dependency-free for tests), so callers must wire the guards
# in via this thin wrapper.
_MFA_REPLAY_WINDOW_SECONDS = 90  # cover the 30 s window + clock skew


async def verify_totp_code_with_guards(
    *,
    user_id: str,
    secret: str,
    code: str,
    valid_window: int = 1,
) -> tuple[bool, str | None]:
    """Verify a TOTP code with rate-limiting + replay protection.

    Returns ``(ok, error_reason)``. ``error_reason`` is one of
    ``"locked"``, ``"replay"``, ``"invalid"``, ``"empty"`` or ``None``
    on success. Wrapped in an async function so it can talk to Redis
    via the shared rate_limit pool.
    """
    from src.core.auth_policy import (
        is_account_locked,
        record_failed_login,
    )
    from src.core.rate_limit import _get_redis

    if not user_id or not secret or not code:
        return False, "empty"

    scope_key = f"mfa:{user_id}"
    if await is_account_locked(scope_key):
        return False, "locked"

    normalised = code.strip().replace(" ", "")
    if not normalised.isdigit() or len(normalised) != 6:
        await record_failed_login(scope_key)
        return False, "invalid"

    rds = await _get_redis()
    replay_key = f"argus:mfa:used:{user_id}:{normalised}"
    if rds is not None:
        try:
            already = await rds.get(replay_key)
            if already is not None:
                # Same code already accepted in this window — a replay
                # attempt; treat as a failure for lockout purposes.
                await record_failed_login(scope_key)
                return False, "replay"
        except Exception:  # noqa: BLE001
            pass  # Redis blip — fall through; replay still unlikely in 90s.

    if not pyotp.TOTP(secret).verify(normalised, valid_window=valid_window):
        await record_failed_login(scope_key)
        return False, "invalid"

    if rds is not None:
        try:
            await rds.set(replay_key, "1", ex=_MFA_REPLAY_WINDOW_SECONDS, nx=True)
        except Exception:  # noqa: BLE001
            pass

    return True, None


# --- Recovery codes ---------------------------------------------------


def generate_recovery_codes(count: int = _RECOVERY_CODE_COUNT) -> list[str]:
    """Plaintext recovery codes — show to the user once, never persisted."""
    return [secrets.token_hex(_RECOVERY_CODE_BYTES) for _ in range(count)]


def hash_recovery_codes(codes: Iterable[str]) -> list[str]:
    return [hash_password(c) for c in codes]


def consume_recovery_code(
    hashed_codes: list[str | None] | None, supplied: str
) -> tuple[bool, list[str | None]]:
    """If ``supplied`` matches one of the still-valid hashed codes,
    flip that slot to ``None`` and return ``(True, new_list)``. Returns
    ``(False, hashed_codes)`` on no match.
    """
    if not hashed_codes:
        return False, hashed_codes or []
    new_list: list[str | None] = list(hashed_codes)
    for i, h in enumerate(new_list):
        if h is None:
            continue
        try:
            if verify_password(supplied, h):
                new_list[i] = None
                return True, new_list
        except Exception:  # noqa: BLE001
            continue
    return False, new_list


__all__ = [
    "generate_secret",
    "provisioning_uri",
    "verify_totp_code",
    "verify_totp_code_with_guards",
    "generate_recovery_codes",
    "hash_recovery_codes",
    "consume_recovery_code",
]
