"""Single-tenant context resolver.

Argus is sold and deployed as **single-tenant on-prem**: one customer
per docker install, one ``Organization`` row, one set of monitored
assets. The schema carries an ``organization_id`` on every domain
table because that's how the models were originally generated, but
operationally there is exactly one such id per install — this module
resolves it once and caches the answer for the rest of the process
lifetime.

Routes derive the org id from this module, never from the request
body or query string. The string ``current`` is accepted on the few
``{org_id}`` paths that exist as a deliberate "I want the system org"
spelling so curl pipelines don't need to substitute a UUID.

Resolution order:
    1. ``settings.system_organization_slug`` (set in ``.env`` after
       a backup-restore from another deployment, to disambiguate
       which row to pick if several survived).
    2. Otherwise the first-provisioned row by ``created_at``.

Concurrency: one ``asyncio.Lock`` serialises the first resolve so
parallel startup workers don't all run the same query. Subsequent
calls hit the cache without taking the lock. ``invalidate()`` drops
the cache (called after the bootstrap ``POST /organizations/`` so
the new row is picked up immediately).

Failure modes:
    * No ``Organization`` row exists → :class:`SystemOrganizationMissing`.
      Fatal — every domain operation needs the row. The fix is to
      ``POST /organizations/`` once after install.
    * The slug is set but doesn't match any of the rows present
      (typically after restoring from a different deployment's
      backup) → :class:`SystemOrganizationAmbiguous`. The fix is to
      either correct the slug or delete the unwanted rows.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.models.threat import Organization


class SystemOrganizationMissing(RuntimeError):
    """Raised when the deployment has no Organization row."""


class SystemOrganizationAmbiguous(RuntimeError):
    """Raised when more than one Organization exists and the configured slug
    does not match any of them."""


_cached_org_id: Optional[uuid.UUID] = None
_resolve_lock = asyncio.Lock()


async def _resolve(db: AsyncSession) -> uuid.UUID:
    configured_slug = (settings.system_organization_slug or "").strip().lower()

    rows = (
        await db.execute(select(Organization).order_by(Organization.created_at))
    ).scalars().all()

    if not rows:
        raise SystemOrganizationMissing(
            "No Organization row exists. Run the onboarding wizard or "
            "POST /api/v1/organizations/ once before serving traffic."
        )

    if configured_slug:
        for org in rows:
            org_slug = (org.name or "").strip().lower().replace(" ", "-")
            if org_slug == configured_slug:
                return org.id
        if len(rows) > 1:
            raise SystemOrganizationAmbiguous(
                f"ARGUS_SYSTEM_ORGANIZATION_SLUG={configured_slug!r} does not "
                f"match any of {len(rows)} organisations on file. Either "
                f"correct the slug or unset it to use the first-provisioned "
                f"organisation."
            )

    return rows[0].id


async def get_system_org_id(db: AsyncSession) -> uuid.UUID:
    """Return the single tenant's organisation id, caching after first call."""
    global _cached_org_id
    if _cached_org_id is not None:
        return _cached_org_id
    async with _resolve_lock:
        if _cached_org_id is not None:
            return _cached_org_id
        _cached_org_id = await _resolve(db)
    return _cached_org_id


def invalidate() -> None:
    """Drop the cached org id. Call after a fresh install or test reset."""
    global _cached_org_id
    _cached_org_id = None


async def get_system_org(db: AsyncSession) -> Organization:
    """Return the full Organization row for the single tenant."""
    org_id = await get_system_org_id(db)
    org = await db.get(Organization, org_id)
    if org is None:
        invalidate()
        raise SystemOrganizationMissing(
            f"Cached organisation {org_id} no longer exists in the database."
        )
    return org


__all__ = [
    "SystemOrganizationMissing",
    "SystemOrganizationAmbiguous",
    "get_system_org_id",
    "get_system_org",
    "invalidate",
]
