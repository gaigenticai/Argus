"""Postgres Row-Level Security helpers — vestigial under single-tenant.

Argus is single-tenant on-prem. RLS was originally added (migration
``7f9c1b22a8e3``) on the assumption that the product might one day
host multiple tenants on shared infrastructure; that path was
abandoned in favour of one-customer-per-install. The migration's
policies are still on the schema (removing them is more risk than
reward — they're permissive when the ``app.current_org`` GUC is
unset, which is always under single-tenant), but the helpers below
are no longer used by any production code path.

This module is kept so that an existing test or downstream tool that
imports :func:`set_session_org` doesn't break, and so that a future
operator who wants to tighten policy at the DB layer (e.g. for a
strict separation between the API role and the migration role) has a
ready-made hook. A regulated bank that wants RLS as a hard fence
between an "API user" and "DB superuser" — without changing
application code — can:

    1. Run the API + worker as a non-superuser DB role.
    2. Use the migrations role only for ``alembic upgrade head``.
    3. Add an explicit ``SELECT set_session_org(...)`` call at the
       start of each request via a FastAPI dependency.

Most operators won't need any of that. The module exists for the
ones who do.
"""

from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def set_session_org(db: AsyncSession, organization_id: uuid.UUID | str) -> None:
    """Bind the SQL session's ``app.current_org`` GUC. Optional —
    only useful for operators who want Postgres RLS as a hard fence
    on top of the application-layer org filter."""
    org_str = str(organization_id)
    await db.execute(
        text("SELECT set_config('app.current_org', :org, true)"),
        {"org": org_str},
    )


async def clear_session_org(db: AsyncSession) -> None:
    """Reset the ``app.current_org`` GUC. Pair with ``set_session_org``
    when finishing a request handler that opted into RLS enforcement."""
    await db.execute(
        text("SELECT set_config('app.current_org', '', true)")
    )


__all__ = ["set_session_org", "clear_session_org"]
