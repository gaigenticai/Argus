"""Admin onboarding — OSS-tool catalog + install.

Routes (all admin-gated):

  GET  /oss-tools/catalog          static catalog of selectable tools
  GET  /oss-tools/preflight        installer readiness (sock mount, gate)
  GET  /oss-tools/                 per-tool current state
  POST /oss-tools/install          start install for a list of tools
  GET  /oss-tools/onboarding       has the wizard been completed?
  POST /oss-tools/onboarding/skip  mark wizard as skipped (admin opted
                                    out of the install flow)
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser, audit_log
from src.integrations.oss_tools import list_catalog, tool_by_name
from src.integrations.oss_tools.catalog import to_dict as tool_to_dict
from src.integrations.oss_tools.installer import (
    disable_unselected,
    install_selected,
    installer_enabled,
    list_states,
    onboarding_complete,
    preflight_status,
)
from src.models.auth import AuditAction
from src.storage.database import get_session
from src.storage import database as _db_mod


def _session_factory():
    """Return the global async session factory.

    BackgroundTasks runs after the request's session has been closed,
    so we can't reuse the request-scoped session — we need a fresh
    factory to mint independent sessions inside the install task.
    """
    f = _db_mod.async_session_factory
    if f is None:
        raise RuntimeError(
            "async_session_factory not initialised — init_db() must run first"
        )
    return f

router = APIRouter(prefix="/oss-tools", tags=["Operations"])


def _client_meta(request: Request) -> tuple[str, str]:
    fwd = request.headers.get("X-Forwarded-For")
    ip = (
        fwd.split(",")[0].strip() if fwd
        else (request.client.host if request.client else "unknown")
    )
    return ip, request.headers.get("User-Agent", "unknown")[:500]


# ── Catalog & preflight ────────────────────────────────────────────


@router.get("/catalog")
async def get_catalog(admin: AdminUser):
    """Static catalog of OSS tools the admin can pick."""
    return {"tools": [tool_to_dict(t) for t in list_catalog()]}


@router.get("/preflight")
async def get_preflight(admin: AdminUser):
    """Surface the docker.sock mount + gate-flag state so the dashboard
    can render setup instructions before the admin hits Install."""
    return preflight_status()


# ── State ─────────────────────────────────────────────────────────


@router.get("/")
async def get_states(
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    return {"tools": await list_states(db)}


@router.get("/onboarding")
async def get_onboarding_status(
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Has the wizard been completed? The dashboard auth-provider
    polls this on first admin login and redirects to the onboarding
    page if False."""
    done = await onboarding_complete(db)
    return {
        "complete": done,
        "installer_enabled": installer_enabled(),
    }


# ── Install ───────────────────────────────────────────────────────


class InstallRequest(BaseModel):
    tools: list[str] = Field(default_factory=list)


@router.post("/install", status_code=202)
async def post_install(
    body: InstallRequest,
    request: Request,
    background: BackgroundTasks,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Start install for the listed tools. Returns immediately with
    202 + per-tool ``pending`` rows; the dashboard polls
    ``GET /oss-tools/`` for state transitions.

    Tools the admin DIDN'T select are recorded as ``disabled`` so the
    onboarding wizard treats the choice as "done" and doesn't re-prompt
    on the next admin login.
    """
    valid: list[str] = []
    for name in body.tools:
        t = tool_by_name(name)
        if t is None:
            raise HTTPException(400, f"unknown OSS tool {name!r}")
        valid.append(name)

    # Mark every non-selected tool DISABLED right now so completion
    # state flips even when the install itself fails.
    await disable_unselected(db, selected=valid)
    ip, ua = _client_meta(request)
    await audit_log(
        db, AuditAction.SETTINGS_UPDATE, user=admin,
        resource_type="oss_onboarding", resource_id="install",
        details={
            "selected": valid,
            "installer_enabled": installer_enabled(),
        },
        ip_address=ip, user_agent=ua,
    )
    await db.commit()

    background.add_task(
        install_selected,
        _session_factory(),
        tool_names=valid,
        requested_by_user_id=admin.id,
    )
    return {
        "started": valid,
        "preflight": preflight_status(),
    }


@router.post("/onboarding/skip", status_code=200)
async def post_skip(
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Admin opted out of installing any OSS tools. Records every
    catalog tool as ``disabled`` so the wizard doesn't re-prompt."""
    await disable_unselected(db, selected=[])
    ip, ua = _client_meta(request)
    await audit_log(
        db, AuditAction.SETTINGS_UPDATE, user=admin,
        resource_type="oss_onboarding", resource_id="skip",
        details={"installed": []},
        ip_address=ip, user_agent=ua,
    )
    await db.commit()
    return {"complete": True}
