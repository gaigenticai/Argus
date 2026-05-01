"""Integration management endpoints — configure, test, and sync external security tools."""

from __future__ import annotations


import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import CurrentUser, AdminUser
from src.models.intel import IntegrationConfig, TriageRun
from src.storage.database import get_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/tools", tags=["Operations"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class IntegrationResponse(BaseModel):
    id: str
    tool_name: str
    enabled: bool
    api_url: str
    health_status: str
    last_sync_at: str | None
    last_error: str | None
    sync_interval_seconds: int
    extra_settings: dict | None
    created_at: str
    updated_at: str


class IntegrationUpdateRequest(BaseModel):
    enabled: bool | None = None
    api_url: str | None = None
    api_key: str | None = None
    extra_settings: dict | None = None
    sync_interval_seconds: int | None = None


class ConnectionTestResult(BaseModel):
    tool_name: str
    connected: bool
    message: str
    details: dict | None = None


class TriageRunResponse(BaseModel):
    id: str
    trigger: str
    hours_window: int
    entries_processed: int
    iocs_created: int
    alerts_generated: int
    duration_seconds: float
    status: str
    error_message: str | None
    created_at: str

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Available integrations registry
# ---------------------------------------------------------------------------

AVAILABLE_INTEGRATIONS = [
    {
        "tool_name": "opencti",
        "display_name": "OpenCTI",
        "category": "Threat Intelligence",
        "description": "Cyber threat intelligence platform — STIX 2.1 knowledge graph",
        "license": "Apache-2.0",
    },
    {
        "tool_name": "wazuh",
        "display_name": "Wazuh",
        "category": "SIEM / EDR",
        "description": "Unified XDR + SIEM — endpoint monitoring, log analysis",
        "license": "GPL-2.0",
    },
    {
        "tool_name": "nuclei",
        "display_name": "Nuclei",
        "category": "Vulnerability Scanning",
        "description": "Template-based vulnerability scanner — 11,000+ templates",
        "license": "MIT",
    },
    {
        "tool_name": "yara",
        "display_name": "YARA",
        "category": "Malware Analysis",
        "description": "Pattern matching engine for malware classification",
        "license": "BSD-3",
    },
    {
        "tool_name": "sigma",
        "display_name": "Sigma Rules",
        "category": "Detection Rules",
        "description": "Universal detection rule format — 3,000+ community rules",
        "license": "DRL 1.1",
    },
    {
        "tool_name": "spiderfoot",
        "display_name": "SpiderFoot",
        "category": "OSINT",
        "description": "OSINT automation with 200+ modules",
        "license": "MIT",
    },
    {
        "tool_name": "suricata",
        "display_name": "Suricata",
        "category": "Network IDS",
        "description": "High-performance network IDS/IPS",
        "license": "GPL-2.0",
    },
    {
        "tool_name": "shuffle",
        "display_name": "Shuffle SOAR",
        "category": "SOAR",
        "description": "SOAR platform — automated playbooks and workflows",
        "license": "AGPL-3.0",
    },
    {
        "tool_name": "gophish",
        "display_name": "GoPhish",
        "category": "Phishing Simulation",
        "description": "Phishing simulation and security awareness framework",
        "license": "MIT",
    },
    {
        "tool_name": "prowler",
        "display_name": "Prowler",
        "category": "Cloud Security",
        "description": "Cloud security posture management — AWS, Azure, GCP",
        "license": "Apache-2.0",
    },
]

_TOOLS_BY_NAME = {t["tool_name"]: t for t in AVAILABLE_INTEGRATIONS}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/")
async def list_integrations(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """List all available integrations with their configuration status."""
    # Get configs from DB
    result = await db.execute(select(IntegrationConfig))
    configs = {c.tool_name: c for c in result.scalars().all()}

    integrations = []
    for tool in AVAILABLE_INTEGRATIONS:
        config = configs.get(tool["tool_name"])
        integrations.append({
            **tool,
            "enabled": config.enabled if config else False,
            "health_status": config.health_status if config else "unconfigured",
            "api_url": config.api_url if config else "",
            "last_sync_at": config.last_sync_at.isoformat() if config and config.last_sync_at else None,
            "last_error": config.last_error if config else None,
            "sync_interval_seconds": config.sync_interval_seconds if config else 3600,
            "id": str(config.id) if config else None,
        })

    return integrations


@router.get("/{tool_name}")
async def get_integration(
    tool_name: str,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Get configuration for a specific integration."""
    if tool_name not in _TOOLS_BY_NAME:
        raise HTTPException(404, f"Unknown integration: {tool_name}")

    result = await db.execute(
        select(IntegrationConfig).where(IntegrationConfig.tool_name == tool_name)
    )
    config = result.scalar_one_or_none()

    tool = _TOOLS_BY_NAME[tool_name]
    return {
        **tool,
        "enabled": config.enabled if config else False,
        "health_status": config.health_status if config else "unconfigured",
        "api_url": config.api_url if config else "",
        "has_api_key": bool(config.api_key) if config else False,
        "last_sync_at": config.last_sync_at.isoformat() if config and config.last_sync_at else None,
        "last_error": config.last_error if config else None,
        "extra_settings": config.extra_settings if config else None,
        "sync_interval_seconds": config.sync_interval_seconds if config else 3600,
    }


@router.put("/{tool_name}")
async def update_integration(
    tool_name: str,
    data: IntegrationUpdateRequest,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Configure an integration — set API URL, key, and enable/disable."""
    if tool_name not in _TOOLS_BY_NAME:
        raise HTTPException(404, f"Unknown integration: {tool_name}")

    result = await db.execute(
        select(IntegrationConfig).where(IntegrationConfig.tool_name == tool_name)
    )
    config = result.scalar_one_or_none()

    if not config:
        config = IntegrationConfig(tool_name=tool_name)
        db.add(config)

    if data.enabled is not None:
        config.enabled = data.enabled
    if data.api_url is not None:
        config.api_url = data.api_url
    if data.api_key is not None:
        # Adversarial audit D-8 — encrypt-at-rest. ``set_api_key`` lives
        # on the model so the raw plaintext never reaches the column.
        config.set_api_key(data.api_key)
    if data.extra_settings is not None:
        config.extra_settings = data.extra_settings
    if data.sync_interval_seconds is not None:
        config.sync_interval_seconds = data.sync_interval_seconds

    await db.commit()
    await db.refresh(config)

    return {
        "tool_name": tool_name,
        "enabled": config.enabled,
        "api_url": config.api_url,
        "health_status": config.health_status,
        "message": f"Integration '{tool_name}' updated",
    }


@router.post("/{tool_name}/test", response_model=ConnectionTestResult)
async def test_integration(
    tool_name: str,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Test connectivity to an external tool."""
    if tool_name not in _TOOLS_BY_NAME:
        raise HTTPException(404, f"Unknown integration: {tool_name}")

    result = await db.execute(
        select(IntegrationConfig).where(IntegrationConfig.tool_name == tool_name)
    )
    config = result.scalar_one_or_none()

    # Local tools (nuclei, yara, sigma) run as subprocesses — they
    # have no api_url because there's nothing to dial. Connection
    # testing for them is "is the binary on PATH and responsive?"
    _LOCAL_TOOLS = {"nuclei", "yara", "sigma"}

    if not config:
        # G4 (Gemini audit): no auto-create. Surface the missing
        # config explicitly so an operator wires it up via
        # `POST /integrations/{tool}` instead of silently inheriting a
        # stub that pretends the integration is ready.
        if tool_name in _LOCAL_TOOLS:
            return ConnectionTestResult(
                tool_name=tool_name,
                connected=False,
                message=(
                    f"{tool_name} integration not registered. "
                    f"POST /api/v1/integrations/ with tool_name={tool_name!r} "
                    f"to register it before testing connectivity."
                ),
            )
        return ConnectionTestResult(
            tool_name=tool_name,
            connected=False,
            message="Integration not configured — set API URL first",
        )
    if tool_name not in _LOCAL_TOOLS and not config.api_url:
        return ConnectionTestResult(
            tool_name=tool_name,
            connected=False,
            message="Integration not configured — set API URL first",
        )

    # Get the integration client
    client = _get_client(tool_name, config)
    if not client:
        return ConnectionTestResult(
            tool_name=tool_name,
            connected=False,
            message=f"Client for '{tool_name}' could not be initialized — check server dependencies",
        )

    try:
        async with client:
            test_result = await client.test_connection()
            connected = test_result.get("connected", False)
            config.health_status = "connected" if connected else "error"
            if not connected:
                config.last_error = test_result.get("message", "Connection failed")
            else:
                config.last_error = None
            await db.commit()

            return ConnectionTestResult(
                tool_name=tool_name,
                connected=connected,
                message=test_result.get("message", ""),
                details=test_result.get("details"),
            )
    except Exception as e:
        config.health_status = "error"
        config.last_error = str(e)[:500]
        await db.commit()
        return ConnectionTestResult(
            tool_name=tool_name,
            connected=False,
            message=f"Connection test failed: {e}",
        )


@router.post("/{tool_name}/sync", status_code=202)
async def trigger_sync(
    tool_name: str,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Trigger a manual sync with an external tool."""
    if tool_name not in _TOOLS_BY_NAME:
        raise HTTPException(404, f"Unknown integration: {tool_name}")

    result = await db.execute(
        select(IntegrationConfig).where(IntegrationConfig.tool_name == tool_name)
    )
    config = result.scalar_one_or_none()

    if not config or not config.enabled:
        raise HTTPException(400, f"Integration '{tool_name}' is not enabled")

    client = _get_client(tool_name, config)
    if not client:
        raise HTTPException(501, f"Client for '{tool_name}' could not be initialized — check dependencies")

    async def _run_sync():
        from src.storage.database import async_session_factory
        if async_session_factory:
            async with async_session_factory() as session:
                cfg_result = await session.execute(
                    select(IntegrationConfig).where(IntegrationConfig.tool_name == tool_name)
                )
                cfg = cfg_result.scalar_one_or_none()
                if cfg:
                    try:
                        sync_client = _get_client(tool_name, cfg)
                        if sync_client:
                            async with sync_client:
                                summary = await sync_client.sync()
                                from datetime import datetime, timezone
                                cfg.last_sync_at = datetime.now(timezone.utc)
                                cfg.health_status = "connected"
                                cfg.last_error = None
                                await session.commit()
                                logger.info("[%s] Sync complete: %s", tool_name, summary)
                    except Exception as e:
                        cfg.health_status = "error"
                        cfg.last_error = str(e)[:500]
                        await session.commit()
                        logger.error("[%s] Sync failed: %s", tool_name, e)

    asyncio.get_running_loop().create_task(_run_sync())

    return {"tool_name": tool_name, "message": f"Sync dispatched for {tool_name}", "status": "running"}


# ---------------------------------------------------------------------------
# Triage history endpoint
# ---------------------------------------------------------------------------


@router.get("/triage/history", response_model=list[TriageRunResponse])
async def triage_history(
    user: CurrentUser,
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_session),
):
    """Get recent triage run history."""
    result = await db.execute(
        select(TriageRun)
        .order_by(TriageRun.created_at.desc())
        .limit(limit)
    )
    runs = result.scalars().all()
    return [
        TriageRunResponse(
            id=str(r.id),
            trigger=r.trigger,
            hours_window=r.hours_window,
            entries_processed=r.entries_processed,
            iocs_created=r.iocs_created,
            alerts_generated=r.alerts_generated,
            duration_seconds=r.duration_seconds,
            status=r.status,
            error_message=r.error_message,
            created_at=r.created_at.isoformat(),
        )
        for r in runs
    ]


# ---------------------------------------------------------------------------
# Client factory
# ---------------------------------------------------------------------------


def _get_client(tool_name: str, config: IntegrationConfig):
    """Create an integration client from DB config.

    Returns an object supporting test_connection(), sync(), and async-with.
    All 10 integrations are wired — API-based tools use their HTTP clients,
    local tools use adapter classes that wrap CLI/engine tooling.
    """
    try:
        if tool_name == "opencti":
            from src.integrations.opencti.client import OpenCTIClient
            return OpenCTIClient(api_url=config.api_url, api_key=config.api_key_plain)
        elif tool_name == "wazuh":
            from src.integrations.wazuh.client import WazuhClient
            return WazuhClient(api_url=config.api_url, api_key=config.api_key_plain)
        elif tool_name == "spiderfoot":
            from src.integrations.spiderfoot.client import SpiderFootIntegration
            return SpiderFootIntegration(api_url=config.api_url, api_key=config.api_key_plain)
        elif tool_name == "shuffle":
            from src.integrations.shuffle.client import ShuffleIntegration
            return ShuffleIntegration(api_url=config.api_url, api_key=config.api_key_plain)
        elif tool_name == "gophish":
            from src.integrations.gophish.client import GoPhishIntegration
            return GoPhishIntegration(api_url=config.api_url, api_key=config.api_key_plain)
        elif tool_name == "nuclei":
            from src.integrations.nuclei.adapter import NucleiIntegration
            return NucleiIntegration(api_url=config.api_url or "", api_key=config.api_key_plain)
        elif tool_name == "yara":
            from src.integrations.yara_engine.adapter import YaraIntegration
            return YaraIntegration(api_url=config.api_url or "data/yara_rules", api_key=config.api_key_plain)
        elif tool_name == "sigma":
            from src.integrations.sigma.adapter import SigmaAdapter
            return SigmaAdapter(api_url=config.api_url or "data/sigma_rules", api_key=config.api_key_plain)
        elif tool_name == "suricata":
            from src.integrations.suricata.adapter import SuricataAdapter
            return SuricataAdapter(api_url=config.api_url or "/var/log/suricata/eve.json", api_key=config.api_key_plain)
        elif tool_name == "prowler":
            from src.integrations.prowler.adapter import ProwlerIntegration
            return ProwlerIntegration(api_url=config.api_url or "aws", api_key=config.api_key_plain)
    except ImportError as e:
        logger.warning("Integration %s not available: %s", tool_name, e)
    return None
