"""Per-org locale (timezone + calendar) — integration tests (P1 #1.2).

Real Postgres, no mocks. Covers default resolution, validation, and
the round-trip through ``Organization.settings``.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.locale import (
    DEFAULT_CALENDAR,
    DEFAULT_TIMEZONE,
    SUPPORTED_CALENDARS,
    SUPPORTED_TIMEZONES,
    extract_locale,
    list_supported,
    load_locale,
    update_locale,
)
from src.models.threat import Organization

pytestmark = pytest.mark.asyncio


async def test_defaults_for_unconfigured_org(
    session: AsyncSession, organization
):
    locale = await load_locale(session, organization["id"])
    assert locale["timezone"] == DEFAULT_TIMEZONE
    assert locale["calendar_system"] == DEFAULT_CALENDAR


async def test_extract_locale_uses_settings_jsonb(
    session: AsyncSession, organization
):
    org = await session.get(Organization, organization["id"])
    org.settings = {
        "locale": {"timezone": "Asia/Dubai", "calendar_system": "islamic-umalqura"},
    }
    await session.flush()
    locale = extract_locale(org)
    assert locale["timezone"] == "Asia/Dubai"
    assert locale["calendar_system"] == "islamic-umalqura"


async def test_update_locale_round_trip(
    session: AsyncSession, organization
):
    resolved = await update_locale(
        session, organization["id"],
        timezone="Asia/Qatar", calendar_system="islamic-umalqura",
    )
    assert resolved == {"timezone": "Asia/Qatar", "calendar_system": "islamic-umalqura"}

    reloaded = await load_locale(session, organization["id"])
    assert reloaded == resolved


async def test_partial_update_preserves_other_field(
    session: AsyncSession, organization
):
    await update_locale(session, organization["id"], timezone="Asia/Dubai")
    await update_locale(session, organization["id"], calendar_system="islamic-umalqura")
    locale = await load_locale(session, organization["id"])
    assert locale["timezone"] == "Asia/Dubai"
    assert locale["calendar_system"] == "islamic-umalqura"


async def test_rejects_unsupported_timezone(
    session: AsyncSession, organization
):
    with pytest.raises(ValueError):
        await update_locale(session, organization["id"], timezone="Mars/Olympus_Mons")


async def test_rejects_unsupported_calendar(
    session: AsyncSession, organization
):
    with pytest.raises(ValueError):
        await update_locale(session, organization["id"], calendar_system="japanese")


async def test_supported_lists_include_gcc_zones():
    """Each GCC capital + Egypt must be in the picker."""
    assert "Asia/Riyadh" in SUPPORTED_TIMEZONES
    assert "Asia/Dubai" in SUPPORTED_TIMEZONES
    assert "Asia/Qatar" in SUPPORTED_TIMEZONES
    assert "Asia/Kuwait" in SUPPORTED_TIMEZONES
    assert "Asia/Bahrain" in SUPPORTED_TIMEZONES
    assert "Asia/Muscat" in SUPPORTED_TIMEZONES
    assert "Africa/Cairo" in SUPPORTED_TIMEZONES
    assert "islamic-umalqura" in SUPPORTED_CALENDARS


def test_list_supported_shape():
    s = list_supported()
    assert "timezones" in s
    assert "calendars" in s
    assert "defaults" in s
    assert s["defaults"] == {"timezone": "Asia/Riyadh", "calendar_system": "gregorian"}
