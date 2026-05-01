"""FastAPI application."""

from __future__ import annotations


from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.config.settings import settings
from src.storage.database import init_db, close_db
from src.core.rate_limit import close_redis_pool
from src.api.routes import organizations, alerts, crawlers, scan, webhooks, reports, activity, auth, users, audit
from src.api.routes import sources, retention, feedback, iocs, actors, stix, threat_map, feeds
from src.api.routes import investigations as investigations_routes
from src.api.routes import brand_actions as brand_actions_routes
from src.api.routes import case_copilot as case_copilot_routes
from src.api.routes import threat_hunts as threat_hunts_routes
from src.api.routes import agent_admin as agent_admin_routes
from src.api.routes import integrations as tools_routes
from src.api.routes import assets, onboarding, evidence, cases, notifications, mitre, easm, ratings
from src.api.routes import dmarc as dmarc_routes
from src.api.routes import brand as brand_routes
from src.api.routes import social as social_routes
from src.api.routes import leakage as leakage_routes
from src.api.routes import intel as intel_routes
from src.api.routes import tprm as tprm_routes
from src.api.routes import news as news_routes
from src.api.routes import sla as sla_routes
from src.api.routes import takedown as takedown_routes
from src.api.routes import audit_export as audit_export_routes
from src.api.routes import exec_report as exec_report_routes
from src.api.routes import admin_settings as admin_settings_routes
from src.api.routes import compliance as compliance_routes
from src.api.routes import taxii as taxii_routes


import logging

from src.core.logging import configure_logging, request_id_var
from src.core.metrics import install_http_metrics_middleware, render_metrics

# Audit C5 — switch to JSON structured logging on import so it covers
# the lifespan log lines too. Idempotent; safe in tests.
configure_logging()

_logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle. (Audit A2)

    DB connection failure is fatal: refuse to start. A "running" app with no
    DB returns 200 on health checks, then 500s every request — defeating
    Railway readiness probes and DR drills.

    Seeding errors are non-fatal — they're idempotent and a partial seed
    is recoverable.
    """
    _logger.info("Argus starting — connecting to database...")
    await init_db()  # raises on failure → uvicorn surfaces a real boot error
    _logger.info("Database connected. Seeding layers...")
    try:
        from src.feeds.seed_layers import seed_default_layers, seed_integrations
        from src.storage.database import async_session_factory
        async with async_session_factory() as session:
            await seed_default_layers(session)
            await seed_integrations(session)
            await session.commit()
        _logger.info("Layers & integrations seeded.")
    except Exception as e:  # noqa: BLE001
        _logger.warning("Layer seeding failed (non-fatal): %s", e)
    yield
    try:
        await close_redis_pool()
    except Exception:
        pass
    await close_db()


# Audit D8 — OpenAPI tag metadata. Groups the ~25 routers into buckets
# the way analysts actually think about the surface: External Surface,
# Brand Protection, Threat Intel, Compliance, Operations.
_OPENAPI_TAGS = [
    {
        "name": "Auth & Identity",
        "description": "Login, users, API keys, audit log, organisations.",
    },
    {
        "name": "External Surface",
        "description": (
            "EASM discovery jobs, findings, exposures, security ratings, "
            "asset registry, onboarding wizard."
        ),
    },
    {
        "name": "Brand Protection",
        "description": (
            "Suspect domains, live-probe, logo abuse, social impersonation, "
            "VIP / executive monitoring, mobile-app store, fraud findings."
        ),
    },
    {
        "name": "Threat Intelligence",
        "description": (
            "Crawlers, feeds, IOCs, actor playbooks, MITRE ATT&CK, "
            "intel polish, hardening recommendations, news + advisories."
        ),
    },
    {
        "name": "Compliance & DLP",
        "description": (
            "DMARC360, data-leakage policies, BIN/card-leak, retention, "
            "evidence vault, TPRM scorecards + questionnaires."
        ),
    },
    {
        "name": "Operations",
        "description": (
            "Cases, SLA, takedown, ticket bindings, notifications, exec "
            "summary, scan, webhooks."
        ),
    },
]


import os as _os
_app_version = _os.environ.get("ARGUS_VERSION", "0.1.0")

app = FastAPI(
    title="Argus",
    description=(
        "Digital Risk Protection + Threat Intelligence platform for banks "
        "and other regulated institutions."
    ),
    version=_app_version,
    lifespan=lifespan,
    openapi_tags=_OPENAPI_TAGS,
)


# Audit C6 — Prometheus metrics. Mounted before any other middleware so
# every request is timed regardless of which guard short-circuits it.
install_http_metrics_middleware(app)


@app.get("/metrics", include_in_schema=False)
async def _metrics_endpoint():
    """Prometheus exposition endpoint. No auth: expected to be scraped
    by an in-cluster Prometheus / Grafana Agent and exposed only on a
    private network. If you put Argus on the public internet, gate this
    via ingress (deny / mTLS).
    """
    from fastapi.responses import Response as _Response

    body, content_type = render_metrics()
    return _Response(content=body, media_type=content_type)


@app.get("/health/crawlers", include_in_schema=False)
async def _crawler_health_endpoint():
    """In-process crawler scheduler health.

    Used as a Kubernetes liveness probe target for the worker
    container. The scheduler reports per-kind last-tick + task-alive
    state without a DB roundtrip; richer FeedHealth history is at
    ``/api/v1/admin/feed-health``.
    """
    from src.core.scheduler import Scheduler  # noqa

    # The Scheduler instance lives on the worker process, not in
    # the API process. The API exposes this endpoint as a
    # convenience for ops that prefer one ingress; the worker
    # writes its snapshot into a known shared file (heartbeat) and
    # we read that. Falls back to {"running": false} if the worker
    # isn't running on the same host.
    import json
    import os

    snapshot_path = os.environ.get(
        "ARGUS_WORKER_SCHEDULER_SNAPSHOT", "/var/lib/argus/scheduler-snapshot.json"
    )
    try:
        with open(snapshot_path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {"running": False, "kinds": {}, "reason": "snapshot file not found"}
    except (OSError, json.JSONDecodeError) as exc:
        return {"running": False, "kinds": {}, "reason": f"snapshot read error: {exc}"}


@app.get("/.well-known/jwks.json", include_in_schema=False)
async def _jwks_endpoint():
    """JSON Web Key Set for asymmetric JWT verification.

    Returned shape: ``{"keys": [...]}`` per RFC 7517. Empty when the
    deployment uses HS* — symmetric secrets cannot be safely
    published, and downstream services don't need a JWKS in that
    case (they share the secret directly).

    G6 — required by regulated buyers who want their other systems
    (SIEM, API gateway) to verify Argus tokens without sharing the
    signing key.
    """
    from src.core.auth import jwks

    return jwks()


# --- Request ID middleware (Audit C5 prep) ----------------------------
@app.middleware("http")
async def _request_id_mw(request, call_next):
    """Inject an X-Request-Id header so SOC analysts can grep one trace
    across logs, metrics, and audit entries."""
    import uuid as _uuid
    rid = request.headers.get("X-Request-Id") or _uuid.uuid4().hex
    request.state.request_id = rid
    token = request_id_var.set(rid)
    try:
        response = await call_next(request)
    finally:
        request_id_var.reset(token)
    response.headers["X-Request-Id"] = rid
    return response


# --- Audit D2 — uniform error envelope --------------------------------
# Every error response — validation, HTTPException, unhandled — shares
# the same shape so clients can write one parser:
#     {"detail": <str|list|object>, "request_id": <str>}
# `detail` keeps FastAPI's native semantics (422 returns a list of
# field errors; 4xx HTTPException returns the string passed in). The
# *contract* is stable across all error paths.
from fastapi import HTTPException as _HTTPException, Request as _Request
from fastapi.exceptions import RequestValidationError as _RVE
from fastapi.responses import JSONResponse as _JSONResponse


def _error_envelope(detail, request) -> dict:
    rid = getattr(request.state, "request_id", None) or "unknown"
    return {"detail": detail, "request_id": rid}


@app.exception_handler(_HTTPException)
async def _http_exception_handler(request: _Request, exc: _HTTPException):
    headers = getattr(exc, "headers", None)
    return _JSONResponse(
        status_code=exc.status_code,
        content=_error_envelope(exc.detail, request),
        headers=headers,
    )


@app.exception_handler(_RVE)
async def _request_validation_handler(request: _Request, exc: _RVE):
    return _JSONResponse(
        status_code=422,
        content=_error_envelope(exc.errors(), request),
    )


# --- Global exception handler (Audit D3) ------------------------------
@app.exception_handler(Exception)
async def _unhandled_exception_handler(request, exc):
    """Convert unhandled exceptions into safe JSON. Never leak stack
    traces or internal paths to the client. Logs full detail server-side.
    """
    import traceback as _tb
    rid = getattr(request.state, "request_id", "unknown")
    _logger.error(
        "unhandled exception (request_id=%s): %s\n%s",
        rid,
        exc,
        "".join(_tb.format_exception(type(exc), exc, exc.__traceback__)),
    )
    return _JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "request_id": rid,
        },
    )

# --- CORS (Audit A4) ----------------------------------------------------
# Wildcard origins are catastrophic for finance. The list comes from
# `ARGUS_CORS_ORIGINS` (settings.cors_origins), which defaults to
# localhost during dev. In production, customers set a strict allowlist
# that includes only their dashboard origin(s).
_cors_origins = settings.cors_origins or []
if not _cors_origins:
    _logger.warning(
        "ARGUS_CORS_ORIGINS is empty — only same-origin requests allowed."
    )
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_origin_regex=None,  # never use regex wildcards in prod
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-API-Key"],
    max_age=86400,
)


# --- Request-body size limit (Audit B5) --------------------------------
# Global ceiling on Content-Length; the largest legitimate upload is
# the evidence vault max blob (50 MB by default). Anything bigger is
# rejected before the body is consumed.
import os as _os
_MAX_BODY_BYTES = int(_os.environ.get("ARGUS_MAX_REQUEST_BYTES", str(64 * 1024 * 1024)))


@app.middleware("http")
async def _request_size_guard(request, call_next):
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > _MAX_BODY_BYTES:
                from fastapi.responses import JSONResponse as _JR
                return _JR(
                    status_code=413,
                    content={
                        "detail": (
                            f"request body {cl} bytes exceeds the global "
                            f"limit of {_MAX_BODY_BYTES}"
                        )
                    },
                )
        except ValueError:
            pass
    return await call_next(request)


# --- Security headers (Audit A5) ---------------------------------------
# Inject the standard hardening headers on every response. Defaults
# match a strict configuration; CSP can be overridden per-deployment via
# settings if the dashboard needs a different policy.

@app.middleware("http")
async def _security_headers(request, call_next):
    response = await call_next(request)
    headers = response.headers
    headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
    headers.setdefault("X-Content-Type-Options", "nosniff")
    headers.setdefault("X-Frame-Options", "DENY")
    headers.setdefault("Referrer-Policy", "no-referrer")
    headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
    )
    # Strict CSP for the API surface. The dashboard deploys at a separate
    # origin and ships its own CSP via meta tags / Cloudflare headers.
    headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    )
    headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
    headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    headers.setdefault("Cross-Origin-Resource-Policy", "same-site")
    return response

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
app.include_router(tools_routes.router, prefix="/api/v1")
app.include_router(assets.router, prefix="/api/v1")
app.include_router(onboarding.router, prefix="/api/v1")
app.include_router(evidence.router, prefix="/api/v1")
app.include_router(cases.router, prefix="/api/v1")
app.include_router(notifications.router, prefix="/api/v1")
app.include_router(mitre.router, prefix="/api/v1")
app.include_router(easm.router, prefix="/api/v1")
app.include_router(ratings.router, prefix="/api/v1")
app.include_router(dmarc_routes.router, prefix="/api/v1")
app.include_router(brand_routes.router, prefix="/api/v1")
app.include_router(social_routes.router, prefix="/api/v1")
app.include_router(leakage_routes.router, prefix="/api/v1")
app.include_router(intel_routes.router, prefix="/api/v1")
app.include_router(tprm_routes.router, prefix="/api/v1")
app.include_router(news_routes.router, prefix="/api/v1")
app.include_router(sla_routes.router, prefix="/api/v1")
app.include_router(takedown_routes.router, prefix="/api/v1")
app.include_router(audit_export_routes.router, prefix="/api/v1")
app.include_router(exec_report_routes.router, prefix="/api/v1")
app.include_router(admin_settings_routes.router, prefix="/api/v1")
app.include_router(investigations_routes.router, prefix="/api/v1")
app.include_router(brand_actions_routes.router, prefix="/api/v1")
app.include_router(case_copilot_routes.router, prefix="/api/v1")
app.include_router(threat_hunts_routes.router, prefix="/api/v1")
app.include_router(agent_admin_routes.router, prefix="/api/v1")
app.include_router(compliance_routes.router, prefix="/api/v1")
# TAXII 2.1 publish — mounted at /taxii2/, NO /api/v1 prefix because
# TAXII clients expect the canonical TAXII 2.1 URL shape.
app.include_router(taxii_routes.router)


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
