"""Database connection management."""

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

engine: AsyncEngine | None = None
async_session_factory: async_sessionmaker[AsyncSession] | None = None


async def init_db() -> None:
    """Initialize database engine and create tables."""
    global engine, async_session_factory

    import ssl as _ssl
    ssl_ctx = _ssl.create_default_context()

    engine = create_async_engine(
        settings.db.url,
        echo=settings.debug,
        pool_size=5,
        max_overflow=3,
        pool_timeout=30,
        connect_args={"ssl": ssl_ctx, "timeout": 30},
    )

    async_session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


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
