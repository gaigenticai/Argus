"""Per-organisation locale (timezone + calendar) — P1 #1.2.

GCC defaults:
    timezone        Asia/Riyadh
    calendar_system gregorian (toggleable to islamic-umalqura)

Stored in ``Organization.settings`` JSONB rather than a migration —
keeps the surface lean and lets future locale knobs (date format,
first-day-of-week) accrete without schema churn.

The frontend reads these via :func:`load_locale` and applies them with
``Intl.DateTimeFormat`` natively (no client-side Hijri lib required;
modern browsers ship the Umm al-Qura calendar in the ICU data).

Server-side stays UTC for storage; the locale is purely a
presentation-layer concern.
"""

from __future__ import annotations

import logging
import uuid
from typing import Iterable, TypedDict

from sqlalchemy.ext.asyncio import AsyncSession

from src.models.threat import Organization

logger = logging.getLogger(__name__)


# ── Constants ─────────────────────────────────────────────────────────


DEFAULT_TIMEZONE = "Asia/Riyadh"
DEFAULT_CALENDAR = "gregorian"

# IANA TZ identifiers offered in the dashboard picker. Keep the GCC
# zones at the top, then the global fallbacks an analyst is likely to
# want when reviewing a regional event from outside the region.
SUPPORTED_TIMEZONES: tuple[str, ...] = (
    "Asia/Riyadh",     # KSA
    "Asia/Dubai",      # UAE
    "Asia/Qatar",      # Qatar
    "Asia/Kuwait",     # Kuwait
    "Asia/Bahrain",    # Bahrain
    "Asia/Muscat",     # Oman
    "Africa/Cairo",    # Egypt
    "UTC",
    "Europe/London",
    "America/New_York",
    "America/Los_Angeles",
    "Asia/Tokyo",
)

# CLDR calendar identifiers accepted by ``Intl.DateTimeFormat``. We ship
# only the two relevant for GCC operations; the picker is intentionally
# narrow to avoid analysts flipping into a calendar Argus has no demo
# coverage for.
SUPPORTED_CALENDARS: tuple[str, ...] = (
    "gregorian",
    "islamic-umalqura",
)


class OrgLocale(TypedDict):
    timezone: str
    calendar_system: str


# ── Helpers ───────────────────────────────────────────────────────────


def _settings_view(org: Organization) -> dict:
    """Return a dict view of ``org.settings`` that's safe to mutate."""
    if isinstance(org.settings, dict):
        return dict(org.settings)
    return {}


def _coerce_timezone(value: str | None) -> str:
    if value and value in SUPPORTED_TIMEZONES:
        return value
    return DEFAULT_TIMEZONE


def _coerce_calendar(value: str | None) -> str:
    if value and value in SUPPORTED_CALENDARS:
        return value
    return DEFAULT_CALENDAR


def extract_locale(org: Organization) -> OrgLocale:
    """Pull the timezone + calendar fields off an organisation row.

    Always returns a complete :class:`OrgLocale` — falls back to the
    GCC defaults when the row was created before this feature shipped.
    """
    settings = _settings_view(org)
    locale = settings.get("locale") or {}
    return OrgLocale(
        timezone=_coerce_timezone(locale.get("timezone")),
        calendar_system=_coerce_calendar(locale.get("calendar_system")),
    )


async def load_locale(
    session: AsyncSession, organization_id: uuid.UUID,
) -> OrgLocale:
    org = await session.get(Organization, organization_id)
    if org is None:
        return OrgLocale(timezone=DEFAULT_TIMEZONE,
                         calendar_system=DEFAULT_CALENDAR)
    return extract_locale(org)


async def update_locale(
    session: AsyncSession,
    organization_id: uuid.UUID,
    *,
    timezone: str | None = None,
    calendar_system: str | None = None,
) -> OrgLocale:
    """Patch one or both locale fields. Returns the resolved locale.

    Validates against ``SUPPORTED_TIMEZONES`` / ``SUPPORTED_CALENDARS``
    — passing an unknown value raises ``ValueError`` so the API can
    return 400 instead of silently accepting an arbitrary IANA string.
    """
    if timezone is not None and timezone not in SUPPORTED_TIMEZONES:
        raise ValueError(
            f"timezone {timezone!r} not supported; choose one of "
            f"{SUPPORTED_TIMEZONES}"
        )
    if calendar_system is not None and calendar_system not in SUPPORTED_CALENDARS:
        raise ValueError(
            f"calendar_system {calendar_system!r} not supported; choose "
            f"one of {SUPPORTED_CALENDARS}"
        )

    org = await session.get(Organization, organization_id)
    if org is None:
        raise LookupError(f"Organization {organization_id} not found")

    current = _settings_view(org)
    locale_block = dict(current.get("locale") or {})
    if timezone is not None:
        locale_block["timezone"] = timezone
    if calendar_system is not None:
        locale_block["calendar_system"] = calendar_system
    current["locale"] = locale_block
    org.settings = current
    await session.flush()

    resolved = extract_locale(org)
    logger.info(
        "[locale] org=%s timezone=%s calendar=%s",
        organization_id, resolved["timezone"], resolved["calendar_system"],
    )
    return resolved


def list_supported() -> dict[str, Iterable[str]]:
    return {
        "timezones": SUPPORTED_TIMEZONES,
        "calendars": SUPPORTED_CALENDARS,
        "defaults": {
            "timezone": DEFAULT_TIMEZONE,
            "calendar_system": DEFAULT_CALENDAR,
        },
    }
