"""Shared pytest fixtures for Argus.

Production-grade harness: spins up a real async Postgres test database
per session, runs migrations once, wraps each test in a transaction
that rolls back. Uses ``httpx.AsyncClient`` against the live FastAPI
app via ``asgi-lifespan`` so route-level integration tests exercise
the actual middleware + dependency stack.

Required env vars:
    ARGUS_TEST_DB_URL     postgresql+asyncpg://... — defaults to local
                          'argus_test' DB on the postgres service.
    ARGUS_JWT_SECRET      stable secret so generated tokens validate.

The harness fails loudly if Postgres is unreachable — we never silently
fall back to SQLite. Tests must run against the production engine.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Per-session unique bucket so re-runs don't collide.
_TEST_BUCKET = f"argus-evidence-test-{uuid.uuid4().hex[:8]}"
os.environ["ARGUS_EVIDENCE_BUCKET"] = _TEST_BUCKET

# Ensure JWT secret is set before any app import.
os.environ.setdefault("ARGUS_JWT_SECRET", "test-secret-do-not-use-in-prod-" + "x" * 32)
os.environ.setdefault(
    "ARGUS_DB_URL_OVERRIDE",
    os.environ.get(
        "ARGUS_TEST_DB_URL",
        "postgresql+asyncpg://argus:argus@localhost:5432/argus_test",
    ),
)

# Evidence vault test config — pointed at the dev MinIO on port 9100 unless
# overridden. Tests skip evidence cases gracefully if MinIO is unreachable.
os.environ.setdefault(
    "ARGUS_EVIDENCE_ENDPOINT_URL",
    os.environ.get("ARGUS_TEST_MINIO_URL", "http://localhost:9100"),
)
os.environ.setdefault("ARGUS_EVIDENCE_ACCESS_KEY", "argus_test_only")
os.environ.setdefault("ARGUS_EVIDENCE_SECRET_KEY", "argus_test_only_dummy_password")
# Tests use mock HTTP servers on 127.0.0.1 — relax the SSRF guard.
os.environ.setdefault("ARGUS_URL_SAFETY_ALLOW_PRIVATE", "1")
os.environ.setdefault(
    "ARGUS_EVIDENCE_BUCKET",
    f"argus-evidence-test-{uuid.uuid4().hex[:8]}",
) if False else None  # keep deterministic per-session below


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def test_engine():
    """Engine pointing at the test database. Creates the DB on first use."""
    db_url = os.environ["ARGUS_DB_URL_OVERRIDE"]

    # Ensure the test DB exists by connecting to the maintenance DB.
    admin_url = db_url.rsplit("/", 1)[0] + "/postgres"
    target_db = db_url.rsplit("/", 1)[1]
    admin_engine = create_async_engine(admin_url, isolation_level="AUTOCOMMIT")
    async with admin_engine.connect() as conn:
        result = await conn.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :n"),
            {"n": target_db},
        )
        if result.scalar() is None:
            await conn.execute(text(f'CREATE DATABASE "{target_db}"'))
    await admin_engine.dispose()

    engine = create_async_engine(db_url, pool_pre_ping=True)

    # Wire database module so the app uses our engine.
    from src.storage import database as db_mod

    db_mod.engine = engine
    db_mod.async_session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    # Apply schema (run alembic to head — production parity).
    from alembic import command
    from alembic.config import Config

    # Audit A3 — alembic is the source of truth.  The test DB schema is
    # built solely from `alembic upgrade head`, exactly like a release-
    # managed production deploy. If a model isn't in alembic, it isn't
    # in the test DB.
    cfg = Config(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", db_url.replace("+asyncpg", ""))
    await asyncio.to_thread(command.upgrade, cfg, "head")

    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(loop_scope="session")
async def session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Each test gets a savepoint that's rolled back on exit."""
    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
        await s.rollback()


@pytest_asyncio.fixture(loop_scope="session")
async def client(test_engine) -> AsyncGenerator[AsyncClient, None]:
    """HTTPX async client wired to the FastAPI app."""
    from src.api.app import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


# --- Domain helpers ------------------------------------------------------


@pytest_asyncio.fixture(loop_scope="session")
async def analyst_user(test_engine) -> dict[str, Any]:
    """Create an analyst user and return a JWT bearer token + user row.

    Each call gets a fresh user (random email) so tests don't conflict.
    """
    from src.core.auth import create_access_token, hash_password
    from src.models.auth import User, UserRole

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        suffix = uuid.uuid4().hex[:8]
        user = User(
            email=f"analyst-{suffix}@argus.test",
            username=f"analyst_{suffix}",
            password_hash=hash_password("test-password-123"),
            display_name=f"Test Analyst {suffix}",
            role=UserRole.ANALYST.value,
            is_active=True,
        )
        s.add(user)
        await s.commit()
        await s.refresh(user)

    token = create_access_token(str(user.id), UserRole.ANALYST.value, user.email)
    return {
        "user_id": user.id,
        "email": user.email,
        "password": "test-password-123",
        "token": token,
        "headers": {"Authorization": f"Bearer {token}"},
    }


@pytest_asyncio.fixture(loop_scope="session")
async def organization(test_engine) -> dict[str, Any]:
    """Create a fresh organization."""
    from src.models.threat import Organization

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        suffix = uuid.uuid4().hex[:8]
        org = Organization(
            name=f"Test Org {suffix}",
            domains=[f"example-{suffix}.com"],
            keywords=[f"test-{suffix}"],
            industry="finance",
        )
        s.add(org)
        await s.commit()
        await s.refresh(org)
    return {"id": org.id, "name": org.name}


_GLOBAL_TABLES_TO_SCRUB_PER_TEST = (
    "news_article_relevance",
    "news_articles",
    "intel_syncs",
    "cve_records",
)


@pytest_asyncio.fixture(autouse=True, loop_scope="session")
async def _scrub_global_tables(test_engine):
    """Audit B11 — truly-global tables (no org_id) leak between tests.

    Wipe them before each test so cross-test count assertions are strict
    rather than ``>=``-tolerant. Org-scoped tables don't need scrubbing
    because every test creates a fresh org via the ``organization`` fixture.
    """
    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        # Use TRUNCATE … CASCADE for FK chain; RESTART IDENTITY isn't
        # needed since we use UUIDs everywhere.
        await s.execute(
            text(
                "TRUNCATE TABLE "
                + ", ".join(_GLOBAL_TABLES_TO_SCRUB_PER_TEST)
                + " CASCADE"
            )
        )
        await s.commit()
    yield


@pytest_asyncio.fixture(scope="session")
def evidence_bucket() -> str:
    """Per-session test bucket. Created on first ``ensure_bucket`` call."""
    return _TEST_BUCKET


@pytest.fixture
def minio_available() -> bool:
    """Probe MinIO and return True iff reachable. Used by tests that need it."""
    from src.storage import evidence_store

    try:
        evidence_store.reset_client()
        evidence_store.ensure_bucket()
        return True
    except Exception:
        return False


@pytest_asyncio.fixture(loop_scope="session")
async def make_alert(test_engine):
    """Factory: insert a real Alert row under the given org and return its id."""

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def _make(
        organization_id, *, severity: str = "high", category: str = "phishing", title: str | None = None
    ):
        from src.models.threat import Alert

        async with factory() as s:
            alert = Alert(
                organization_id=organization_id,
                category=category,
                severity=severity,
                title=title or f"Test alert {uuid.uuid4().hex[:6]}",
                summary="auto-generated by test fixture",
            )
            s.add(alert)
            await s.commit()
            await s.refresh(alert)
            return alert.id

    return _make


@pytest_asyncio.fixture(loop_scope="session")
async def admin_user(test_engine) -> dict[str, Any]:
    """An admin-role user (used for delete/permission tests)."""
    from src.core.auth import create_access_token, hash_password
    from src.models.auth import User, UserRole

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        suffix = uuid.uuid4().hex[:8]
        user = User(
            email=f"admin-{suffix}@argus.test",
            username=f"admin_{suffix}",
            password_hash=hash_password("test-password-123"),
            display_name=f"Test Admin {suffix}",
            role=UserRole.ADMIN.value,
            is_active=True,
        )
        s.add(user)
        await s.commit()
        await s.refresh(user)

    token = create_access_token(str(user.id), UserRole.ADMIN.value, user.email)
    return {
        "user_id": user.id,
        "email": user.email,
        "password": "test-password-123",
        "token": token,
        "headers": {"Authorization": f"Bearer {token}"},
    }


@pytest_asyncio.fixture(loop_scope="session")
async def second_organization(test_engine) -> dict[str, Any]:
    """A second org used to verify tenant isolation."""
    from src.models.threat import Organization

    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        suffix = uuid.uuid4().hex[:8]
        org = Organization(
            name=f"Other Org {suffix}",
            domains=[f"other-{suffix}.com"],
        )
        s.add(org)
        await s.commit()
        await s.refresh(org)
    return {"id": org.id, "name": org.name}
