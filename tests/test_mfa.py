"""Audit D10 — TOTP-based 2FA tests.

Covers:
- enroll → confirm → recovery codes returned
- login without code blocked once enrolled
- login with valid TOTP code accepted
- recovery code login works and burns the code
- disable requires password + code
"""

from __future__ import annotations

import pyotp
import pytest
from httpx import AsyncClient

from src.core.mfa import (
    consume_recovery_code,
    generate_recovery_codes,
    hash_recovery_codes,
    verify_totp_code,
)

pytestmark = pytest.mark.asyncio


# --- Unit ----------------------------------------------------------


def test_recovery_code_round_trip():
    codes = generate_recovery_codes(3)
    hashed = hash_recovery_codes(codes)
    ok, new = consume_recovery_code(hashed, codes[1])
    assert ok
    assert new[1] is None
    # second use of the same code fails
    ok2, _ = consume_recovery_code(new, codes[1])
    assert ok2 is False


def test_totp_verify_round_trip():
    secret = pyotp.random_base32()
    code = pyotp.TOTP(secret).now()
    assert verify_totp_code(secret, code) is True
    assert verify_totp_code(secret, "000000") is False
    assert verify_totp_code(secret, "abcdef") is False


# --- API: full lifecycle ------------------------------------------


def _hdr(user) -> dict:
    return user["headers"]


async def test_mfa_full_lifecycle(client: AsyncClient, admin_user):
    """Enroll → confirm → recovery codes → login requires TOTP →
    valid code accepted → disable strips MFA."""
    # 1. enroll
    enroll = await client.post("/api/v1/auth/2fa/enroll", headers=_hdr(admin_user))
    assert enroll.status_code == 200, enroll.text
    secret = enroll.json()["secret"]
    assert enroll.json()["otpauth_url"].startswith("otpauth://totp/")

    # 2. confirm with current code
    code = pyotp.TOTP(secret).now()
    confirm = await client.post(
        "/api/v1/auth/2fa/confirm",
        json={"code": code},
        headers=_hdr(admin_user),
    )
    assert confirm.status_code == 200, confirm.text
    recovery = confirm.json()["recovery_codes"]
    assert len(recovery) == 10

    # 3. login WITHOUT code → 401 mfa_required
    bad = await client.post(
        "/api/v1/auth/login",
        json={
            "email": admin_user["email"],
            "password": admin_user["password"],
        },
    )
    assert bad.status_code == 401
    assert bad.json()["detail"] == "mfa_required"

    # 4. login WITH valid TOTP → 200
    good = await client.post(
        "/api/v1/auth/login",
        json={
            "email": admin_user["email"],
            "password": admin_user["password"],
            "totp_code": pyotp.TOTP(secret).now(),
        },
    )
    assert good.status_code == 200, good.text

    # 5. login with a recovery code → 200
    rc = await client.post(
        "/api/v1/auth/login",
        json={
            "email": admin_user["email"],
            "password": admin_user["password"],
            "recovery_code": recovery[0],
        },
    )
    assert rc.status_code == 200

    # 6. same recovery code is now burned
    burnt = await client.post(
        "/api/v1/auth/login",
        json={
            "email": admin_user["email"],
            "password": admin_user["password"],
            "recovery_code": recovery[0],
        },
    )
    assert burnt.status_code == 401

    # 7. disable requires current password + valid TOTP
    disable = await client.post(
        "/api/v1/auth/2fa/disable",
        json={
            "password": admin_user["password"],
            "code": pyotp.TOTP(secret).now(),
        },
        headers=_hdr(admin_user),
    )
    assert disable.status_code == 204

    # 8. login is now password-only again
    after = await client.post(
        "/api/v1/auth/login",
        json={
            "email": admin_user["email"],
            "password": admin_user["password"],
        },
    )
    assert after.status_code == 200
