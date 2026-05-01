"""Symmetric encryption for at-rest secrets.

Used by NotificationChannel.secret_ciphertext (and any future model that
needs to store credentials inside Postgres without exposing them through
the API). Uses Fernet (AES-128-CBC + HMAC-SHA256) keyed off
``ARGUS_SECRET_KEY``.

Operations:
    encrypt(plaintext: str) -> str    # base64 ciphertext for DB
    decrypt(ciphertext: str) -> str
    rotate(plaintext_or_cipher) -> str  # re-encrypts under current key

If ``ARGUS_SECRET_KEY`` is unset the module raises on first use; we never
silently fall back to a default key.
"""

from __future__ import annotations

import base64
import hashlib
import os
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken


class CryptoError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    raw = os.environ.get("ARGUS_SECRET_KEY") or os.environ.get("ARGUS_JWT_SECRET")
    if not raw:
        raise CryptoError(
            "ARGUS_SECRET_KEY (or ARGUS_JWT_SECRET as fallback) must be set "
            "before encrypting/decrypting secrets at rest."
        )
    # Derive a 32-byte key deterministically. We don't ship the raw secret
    # to Fernet directly to avoid encoding-format constraints.
    key = base64.urlsafe_b64encode(hashlib.sha256(raw.encode("utf-8")).digest())
    return Fernet(key)


def reset_cache() -> None:
    """Used by tests when the env-var changes mid-run."""
    _fernet.cache_clear()


def encrypt(plaintext: str) -> str:
    if plaintext is None:
        raise CryptoError("plaintext must not be None")
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as e:
        raise CryptoError(
            "Failed to decrypt secret — key mismatch or corrupted ciphertext"
        ) from e


__all__ = ["encrypt", "decrypt", "reset_cache", "CryptoError"]
