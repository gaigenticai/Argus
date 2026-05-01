"""Database connection management."""

from __future__ import annotations


from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from src.config.settings import settings
from src.models.base import Base
import src.models.threat  # noqa: F401 — register threat models with Base.metadata
import src.models.auth  # noqa: F401 — register auth models with Base.metadata
import src.models.intel  # noqa: F401 — register intel models with Base.metadata
import src.models.feeds  # noqa: F401 — register feed models with Base.metadata
import src.models.onboarding  # noqa: F401 — register onboarding/discovery models
import src.models.evidence  # noqa: F401 — register evidence vault model
import src.models.cases  # noqa: F401 — register case management models
import src.models.notifications  # noqa: F401 — register notification models
import src.models.mitre  # noqa: F401 — register MITRE ATT&CK models
import src.models.easm  # noqa: F401 — register EASM diff/finding models
import src.models.exposures  # noqa: F401 — register DeepScan exposure model
import src.models.ratings  # noqa: F401 — register Security Rating models
import src.models.dmarc  # noqa: F401 — register DMARC360 report models
import src.models.brand  # noqa: F401 — register Brand Protection models
import src.models.live_probe  # noqa: F401 — register LiveProbe model
import src.models.logo  # noqa: F401 — register Brand Logo + LogoMatch
import src.models.social  # noqa: F401 — register Social + Impersonation models
import src.models.fraud  # noqa: F401 — register Fraud findings
import src.models.leakage  # noqa: F401 — register Data Leakage models
import src.models.intel_polish  # noqa: F401 — register TI Polish models
import src.models.tprm  # noqa: F401 — register TPRM models
import src.models.news  # noqa: F401 — register News + Advisory models
import src.models.sla  # noqa: F401 — register SLA + ticketing models
import src.models.takedown  # noqa: F401 — register Takedown ticketing

engine: AsyncEngine | None = None
async_session_factory: async_sessionmaker[AsyncSession] | None = None


async def init_db() -> None:
    """Initialize database engine and create tables."""
    global engine, async_session_factory

    db_url = settings.db.url
    connect_args: dict = {"timeout": 30}

    # Adversarial audit D-24 — parse the URL host before deciding to skip
    # SSL. A naive substring match on "localhost" passes for hostnames
    # like "localhost.attacker.com" and silently downgrades a WAN
    # connection to plaintext. Only skip TLS when the parsed netloc is a
    # real loopback address AND we are not running in production.
    from urllib.parse import urlparse as _urlparse
    _parsed = _urlparse(db_url.replace("postgresql+asyncpg://", "postgresql://", 1))
    _host = (_parsed.hostname or "").lower()
    _is_loopback = _host in {"localhost", "127.0.0.1", "::1"}
    _is_internal = _host.endswith(".railway.internal") or _host == "postgres"
    _env = (getattr(settings, "environment", None) or "").lower()
    _allow_plain = (_is_loopback or _is_internal) and _env != "production"
    if not _allow_plain:
        import ssl as _ssl
        connect_args["ssl"] = _ssl.create_default_context()

    engine = create_async_engine(
        db_url,
        echo=settings.debug,
        pool_size=settings.db.pool_size,
        max_overflow=settings.db.max_overflow,
        pool_timeout=settings.db.pool_timeout,
        pool_recycle=settings.db.pool_recycle,
        pool_pre_ping=True,
        connect_args=connect_args,
    )

    async_session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    # Audit A3 — schema is owned by alembic. Production deploys must run
    # `alembic upgrade head` before / during boot. Removing metadata.create_all
    # here forces parity with the release-managed migration path.
    # A simple sanity check: ensure the alembic_version row exists.
    from sqlalchemy import text
    async with engine.connect() as conn:
        try:
            r = await conn.execute(text("SELECT version_num FROM alembic_version"))
            row = r.first()
            if row is None:
                import logging as _logging
                _logging.getLogger(__name__).warning(
                    "alembic_version table is empty — DB schema may be incomplete. "
                    "Run `alembic upgrade head` before serving traffic."
                )
        except Exception:
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "alembic_version table missing — DB schema is uninitialised. "
                "Run `alembic upgrade head` before serving traffic."
            )


async def get_session() -> AsyncSession:
    """Get a database session."""
    if async_session_factory is None:
        await init_db()
    async with async_session_factory() as session:
        yield session


async def close_db() -> None:
    """Close database connections."""
    global engine
    if engine:
        await engine.dispose()
