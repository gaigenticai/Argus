"""Audit E5 — verify Postgres RLS is actually enforced when the
session GUC is set, and is permissive when it's unset (so existing
endpoints continue to work without per-route opt-in).

RLS is bypassed for SUPERUSER connections regardless of `FORCE ROW
LEVEL SECURITY`. The default test role (``argus``) is a superuser, so
this test creates a dedicated non-superuser role (``argus_app``) and
runs the assertions through a fresh engine bound to that role. In
production you'd run the API + worker as the non-superuser role and
keep the migration role separate.
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.rls import clear_session_org, set_session_org
from src.models.threat import Asset, Organization

pytestmark = pytest.mark.asyncio


async def _ensure_non_superuser_role(test_engine) -> str:
    """Create the ``argus_app`` role once; idempotent. Returns the
    SQLAlchemy URL bound to it."""
    base_url = os.environ["ARGUS_TEST_DB_URL"]
    async with test_engine.begin() as conn:
        await conn.execute(text(
            "DO $$ BEGIN "
            "  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'argus_app') THEN "
            "    CREATE ROLE argus_app LOGIN PASSWORD 'argus_app' NOSUPERUSER; "
            "  END IF; "
            "END $$;"
        ))
        await conn.execute(text("GRANT USAGE ON SCHEMA public TO argus_app"))
        await conn.execute(text(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO argus_app"
        ))
        await conn.execute(text(
            "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO argus_app"
        ))
    # Build the same URL with credentials swapped to argus_app.
    return base_url.replace("argus:argus@", "argus_app:argus_app@")


async def test_rls_filters_assets_by_session_org(test_engine):
    """With ``app.current_org`` set, a query for assets in another org
    must return zero rows even when the WHERE clause is intentionally
    missing — that's the whole point of RLS as defense-in-depth."""
    suffix = uuid.uuid4().hex[:8]

    # Seed two orgs each with one asset using the privileged engine.
    privileged = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with privileged() as s:
        org_a = Organization(name=f"A-{suffix}")
        org_b = Organization(name=f"B-{suffix}")
        s.add_all([org_a, org_b])
        await s.flush()
        s.add(Asset(organization_id=org_a.id, asset_type="domain", value=f"a-{suffix}.test"))
        s.add(Asset(organization_id=org_b.id, asset_type="domain", value=f"b-{suffix}.test"))
        await s.commit()
        org_a_id = org_a.id
        org_b_id = org_b.id

    app_url = await _ensure_non_superuser_role(test_engine)
    app_engine = create_async_engine(app_url, pool_pre_ping=True)
    app_factory = async_sessionmaker(
        app_engine, class_=AsyncSession, expire_on_commit=False
    )
    try:
        # GUC unset → permissive.
        async with app_factory() as s:
            await clear_session_org(s)
            rows = (
                await s.execute(
                    text("SELECT organization_id FROM assets WHERE value LIKE :p"),
                    {"p": f"%-{suffix}.test"},
                )
            ).fetchall()
            seen = {r[0] for r in rows}
            assert org_a_id in seen and org_b_id in seen, "GUC unset should be permissive"

        # GUC bound to org A → only A's row, even with no WHERE filter.
        async with app_factory() as s:
            async with s.begin():
                await set_session_org(s, org_a_id)
                rows = (
                    await s.execute(
                        text("SELECT organization_id FROM assets WHERE value LIKE :p"),
                        {"p": f"%-{suffix}.test"},
                    )
                ).fetchall()
            seen = {r[0] for r in rows}
            assert seen == {org_a_id}, f"RLS leak: saw {seen}, expected only {org_a_id}"
    finally:
        await app_engine.dispose()
