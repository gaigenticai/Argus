"""Audit D9 — password complexity + lockout policy unit tests."""

from __future__ import annotations

import pytest

from src.core.auth_policy import (
    MIN_LENGTH,
    WeakPasswordError,
    validate_password_complexity,
)


def test_password_too_short_rejected():
    with pytest.raises(WeakPasswordError, match=str(MIN_LENGTH)):
        validate_password_complexity("Aa1!short")


def test_password_missing_uppercase_rejected():
    with pytest.raises(WeakPasswordError, match="uppercase"):
        validate_password_complexity("alllower1!alllower")


def test_password_missing_digit_rejected():
    with pytest.raises(WeakPasswordError, match="digit"):
        validate_password_complexity("NoDigitsHere!!")


def test_password_missing_special_rejected():
    with pytest.raises(WeakPasswordError, match="special"):
        validate_password_complexity("NoSpecial1234")


def test_password_strong_accepted():
    validate_password_complexity("Strong-Pass-12345!")
