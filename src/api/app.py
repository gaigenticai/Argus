"""FastAPI application."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.config.settings import settings
from src.storage.database import init_db, close_db
from src.core.rate_limit import close_redis_pool
from src.api.routes import organizations, alerts, crawlers, scan, webhooks, reports, activity, auth, users, audit
from src.api.routes import sources, retention, feedback, iocs, actors, stix, threat_map, feeds


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # Seed default threat map layers (idempotent)
    try:
        from src.feeds.seed_layers import seed_default_layers
        from src.storage.database import async_session_factory
        async with async_session_factory() as session:
            await seed_default_layers(session)
            await session.commit()
    except Exception:
        pass  # non-fatal — layers can be seeded later
    yield
    await close_redis_pool()
    await close_db()


app = FastAPI(
    title="Argus",
    description="Agentic Threat Intelligence Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-API-Key"],
)

app.include_router(auth.router, prefix="/api/v1")
app.include_router(users.router, prefix="/api/v1")
app.include_router(audit.router, prefix="/api/v1")
app.include_router(organizations.router, prefix="/api/v1")
app.include_router(alerts.router, prefix="/api/v1")
app.include_router(crawlers.router, prefix="/api/v1")
app.include_router(scan.router, prefix="/api/v1")
app.include_router(webhooks.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")
app.include_router(activity.router, prefix="/api/v1")
app.include_router(sources.router, prefix="/api/v1")
app.include_router(retention.router, prefix="/api/v1")
app.include_router(feedback.router, prefix="/api/v1")
app.include_router(iocs.router, prefix="/api/v1")
app.include_router(actors.router, prefix="/api/v1")
app.include_router(stix.router, prefix="/api/v1")
app.include_router(threat_map.router, prefix="/api/v1")
app.include_router(feeds.router, prefix="/api/v1")


@app.get("/health")
async def health():
    """Deep health check — verifies database connectivity."""
    from sqlalchemy import text
    from src.storage.database import async_session_factory

    checks = {"service": "argus", "status": "ok"}

    # Database check
    try:
        if async_session_factory:
            async with async_session_factory() as session:
                await session.execute(text("SELECT 1"))
            checks["database"] = "connected"
        else:
            checks["database"] = "not initialized"
            checks["status"] = "degraded"
    except Exception as e:
        checks["database"] = f"error: {str(e)[:100]}"
        checks["status"] = "degraded"

    # Tor check (non-blocking — just config status)
    checks["tor_configured"] = bool(settings.tor.socks_host)
    checks["i2p_enabled"] = settings.i2p.enabled
    checks["lokinet_enabled"] = settings.lokinet.enabled

    return checks
