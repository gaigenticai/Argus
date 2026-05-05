"""Organisation endpoints — single-tenant.

Argus is single-tenant on-prem: one customer per docker install, one
``Organization`` row, end of story. The endpoints in this module
exist because the schema FKs every domain table to ``organizations.id``,
not because the API is supposed to grow into a multi-tenant SaaS.
``GET /`` returns the one row; ``{org_id}`` accepts either ``current``
or the matching UUID — anything else is a 404.

All mutations write before/after JSON to the audit log.
"""

from __future__ import annotations


import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser, AnalystUser, audit_log
from src.core.tenant import (
    SystemOrganizationMissing,
    get_system_org_id,
    invalidate as invalidate_tenant_cache,
)
from src.models.auth import AuditAction
from src.models.threat import Asset, Organization, VIPTarget
from src.storage.database import get_session

router = APIRouter(prefix="/organizations", tags=["Auth & Identity"])


# --- Schemas -------------------------------------------------------------


class VIPCreate(BaseModel):
    name: str
    title: str | None = None
    emails: list[str] = []
    usernames: list[str] = []
    phone_numbers: list[str] = []
    keywords: list[str] = []
    social_profiles: dict[str, str] | None = None


class AssetCreate(BaseModel):
    asset_type: str
    value: str
    details: dict[str, Any] | None = None


class OrgCreate(BaseModel):
    name: str
    domains: list[str] = []
    keywords: list[str] = []
    industry: str | None = None
    tech_stack: dict[str, Any] | None = None


class OrgUpdate(BaseModel):
    name: str | None = None
    domains: list[str] | None = None
    keywords: list[str] | None = None
    industry: str | None = None
    tech_stack: dict[str, Any] | None = None


class OrgResponse(BaseModel):
    id: uuid.UUID
    name: str
    domains: list[str]
    keywords: list[str]
    industry: str | None
    tech_stack: dict | None

    model_config = {"from_attributes": True}


# --- Helpers -------------------------------------------------------------


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    ua = request.headers.get("User-Agent", "unknown")[:500]
    return ip, ua


async def _resolve(db: AsyncSession, org_id_or_current: str) -> Organization:
    """Accept ``current`` or the system org's UUID; reject anything else."""
    sys_id = None
    try:
        sys_id = await get_system_org_id(db)
    except SystemOrganizationMissing:
        pass

    if org_id_or_current == "current":
        if sys_id is None:
            raise HTTPException(
                404,
                "No organisation provisioned. POST /organizations/ once to bootstrap.",
            )
        org = await db.get(Organization, sys_id)
        if org is None:
            invalidate_tenant_cache()
            raise HTTPException(404, "Organisation not found")
        return org

    try:
        candidate = uuid.UUID(org_id_or_current)
    except ValueError:
        raise HTTPException(404, "Organisation not found")

    if sys_id is not None and candidate != sys_id:
        # Single-tenant: only one org is addressable.
        raise HTTPException(404, "Organisation not found")

    org = await db.get(Organization, candidate)
    if org is None:
        raise HTTPException(404, "Organisation not found")
    return org


# --- Endpoints -----------------------------------------------------------


@router.post("/", response_model=OrgResponse)
async def create_organization(
    body: OrgCreate,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Bootstrap the (one and only) Organisation row.

    Subsequent calls fail with 409 — single-tenant deploys never need
    more than one. To rename or otherwise edit, use ``PATCH /current``.
    """
    existing = (await db.execute(select(Organization))).scalars().first()
    if existing is not None:
        raise HTTPException(
            409,
            "Organisation already provisioned. PATCH /organizations/current to update.",
        )

    org = Organization(
        name=body.name,
        domains=body.domains,
        keywords=body.keywords,
        industry=body.industry,
        tech_stack=body.tech_stack,
    )
    db.add(org)
    await db.flush()

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ORG_CREATE,
        user=admin,
        resource_type="organization",
        resource_id=str(org.id),
        details={"after": body.model_dump()},
        ip_address=ip,
        user_agent=ua,
    )

    # Run the per-org intel-collection scaffold. Idempotent + resilient
    # — failure of any individual step is logged but doesn't roll back
    # org creation. The report (which steps are configured vs need
    # operator input) is attached to the audit log rather than the
    # response so we don't leak internal scaffolding state to clients.
    try:
        from src.onboarding.intel_setup import seed_org_intel
        report = await seed_org_intel(db, org)
        await audit_log(
            db,
            AuditAction.ORG_CREATE,
            user=admin,
            resource_type="organization_intel_setup",
            resource_id=str(org.id),
            details=report.to_dict(),
            ip_address=ip,
            user_agent=ua,
        )
    except Exception:  # noqa: BLE001 — never wedge org creation
        import logging
        logging.getLogger(__name__).exception(
            "[org_create] intel_setup orchestrator failed for %s — "
            "org row created, but scaffold incomplete. Re-run via "
            "POST /admin/organizations/{id}/seed-intel.", org.id,
        )

    await db.commit()
    await db.refresh(org)
    invalidate_tenant_cache()
    return org


@router.get("/", response_model=list[OrgResponse])
async def list_organizations(
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    """Return the (single) organisation. Always either zero or one row."""
    rows = (await db.execute(select(Organization))).scalars().all()
    return list(rows)


@router.get("/current", response_model=OrgResponse)
async def get_current_organization(
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    return await _resolve(db, "current")


@router.patch("/current", response_model=OrgResponse)
async def update_current_organization(
    body: OrgUpdate,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    org = await _resolve(db, "current")
    before = {
        "name": org.name,
        "domains": list(org.domains or []),
        "keywords": list(org.keywords or []),
        "industry": org.industry,
        "tech_stack": dict(org.tech_stack or {}),
    }
    after: dict = {}
    if body.name is not None and body.name != org.name:
        after["name"] = body.name
        org.name = body.name
    if body.domains is not None and list(body.domains) != list(org.domains or []):
        after["domains"] = body.domains
        org.domains = body.domains
    if body.keywords is not None and list(body.keywords) != list(org.keywords or []):
        after["keywords"] = body.keywords
        org.keywords = body.keywords
    if body.industry is not None and body.industry != org.industry:
        after["industry"] = body.industry
        org.industry = body.industry
    if body.tech_stack is not None and dict(body.tech_stack) != dict(org.tech_stack or {}):
        after["tech_stack"] = body.tech_stack
        org.tech_stack = body.tech_stack

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ORG_UPDATE,
        user=admin,
        resource_type="organization",
        resource_id=str(org.id),
        details={"before": {k: before[k] for k in after}, "after": after} if after else {"no_change": True},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(org)
    invalidate_tenant_cache()
    return org


@router.get("/current/locale")
async def get_current_locale(
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    """Return the tenant's timezone + calendar (for the dashboard's
    formatDate helper) along with the picker's allowed values."""
    from src.core.locale import extract_locale, list_supported

    org = await _resolve(db, "current")
    locale = extract_locale(org)
    return {**locale, "supported": list_supported()}


@router.patch("/current/locale")
async def update_current_locale(
    body: dict,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Patch one or both locale fields. Body: {timezone?, calendar_system?}."""
    from src.core.locale import update_locale

    org = await _resolve(db, "current")
    try:
        resolved = await update_locale(
            db,
            org.id,
            timezone=body.get("timezone"),
            calendar_system=body.get("calendar_system"),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ORG_UPDATE,
        user=admin,
        resource_type="organization",
        resource_id=str(org.id),
        details={"locale": resolved},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return resolved


# --- Monitored sources (Telegram channels + breach-check emails) ----
#
# Two pieces of operator-curated config that drive scope-sensitive
# harvesters:
#   - ``settings.telegram_monitor_channels`` — public Telegram channel
#     handles to scrape via t.me/s/. Read by ``social.telegram_monitor``
#     and the worker tick at ``src/workers/runner.py:722``.
#   - ``settings.breach_check_emails`` — addresses to query against
#     HIBP / IntelX / DeHashed. Read by the smoketest today; future
#     credential-monitor worker will iterate the same list on a tick.
# The catalog endpoints exposed here let the dashboard render a
# pickable list backed by the curated channel library at
# ``src.integrations.telegram_collector.channels`` and a derived
# role-email suggestion list keyed off the verified domains. Without
# this surface, operators have to hand-edit JSONB — which defeats the
# product.

_TELEGRAM_HANDLE_RE = __import__("re").compile(r"^[A-Za-z0-9_]{3,32}$")


class TelegramChannelCatalogEntry(BaseModel):
    handle: str
    cluster: str
    language: str
    rationale: str
    actor_link: str | None = None
    status: str
    region_focus: list[str]


class MonitoredSourcesResponse(BaseModel):
    telegram_channels: list[str]
    breach_emails: list[str]
    catalog: dict[str, Any]


class MonitoredSourcesUpdate(BaseModel):
    telegram_channels: list[str] = Field(default_factory=list, max_length=200)
    breach_emails: list[EmailStr] = Field(default_factory=list, max_length=200)

    @field_validator("telegram_channels")
    @classmethod
    def _validate_handles(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in value:
            handle = (raw or "").strip().lstrip("@").lower()
            if not handle:
                continue
            if not _TELEGRAM_HANDLE_RE.match(handle):
                raise ValueError(
                    f"Invalid Telegram handle {raw!r}: expected 3-32 chars "
                    "of letters, digits, or underscore (Telegram's own rule)."
                )
            if handle not in cleaned:  # de-dup, preserve order
                cleaned.append(handle)
        return cleaned


def _suggested_role_emails(domains: list[str]) -> list[str]:
    """Role-based addresses guaranteed to exist on a corporate domain.
    Mirrors ``scripts.seed.load_real_target._default_breach_emails`` so
    the dashboard suggestion is identical to what the seed wrote."""
    roles = ("info", "support", "careers", "security", "press", "noreply", "hello", "contact")
    return [f"{r}@{d}" for d in domains for r in roles]


@router.get("/current/monitored-sources", response_model=MonitoredSourcesResponse)
async def get_monitored_sources(
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Current selection + the catalog the dashboard renders to choose
    from. Returns the curated Telegram catalog (so operators can pick
    by cluster/region without inventing handles) and a suggested
    role-email list derived from the org's verified domains."""
    from src.integrations.telegram_collector.channels import (
        list_curated_channels,
    )

    org = await _resolve(db, "current")
    settings = org.settings or {}
    selected_channels = list(settings.get("telegram_monitor_channels") or [])
    selected_emails = list(settings.get("breach_check_emails") or [])

    catalog_channels = [
        TelegramChannelCatalogEntry(**c.to_dict()).model_dump()
        for c in list_curated_channels()
    ]
    suggested_emails = _suggested_role_emails(list(org.domains or []))

    return MonitoredSourcesResponse(
        telegram_channels=selected_channels,
        breach_emails=selected_emails,
        catalog={
            "telegram_channels": catalog_channels,
            "suggested_emails": suggested_emails,
        },
    )


@router.put("/current/monitored-sources", response_model=MonitoredSourcesResponse)
async def update_monitored_sources(
    body: MonitoredSourcesUpdate,
    request: Request,
    admin: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Replace both the channel selection and the breach-check email
    list atomically. Telegram handles are validated against Telegram's
    own naming rule; emails go through Pydantic EmailStr."""
    from sqlalchemy.orm.attributes import flag_modified

    org = await _resolve(db, "current")
    settings = dict(org.settings or {})
    before = {
        "telegram_monitor_channels": list(settings.get("telegram_monitor_channels") or []),
        "breach_check_emails": list(settings.get("breach_check_emails") or []),
    }
    settings["telegram_monitor_channels"] = list(body.telegram_channels)
    settings["breach_check_emails"] = [str(e) for e in body.breach_emails]
    org.settings = settings
    flag_modified(org, "settings")

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ORG_UPDATE,
        user=admin,
        resource_type="organization",
        resource_id=str(org.id),
        details={
            "action": "monitored_sources_update",
            "before": before,
            "after": {
                "telegram_monitor_channels": settings["telegram_monitor_channels"],
                "breach_check_emails": settings["breach_check_emails"],
            },
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(org)

    # Re-render the response shape so the dashboard gets the catalog
    # back in the same payload — saves an extra round-trip.
    from src.integrations.telegram_collector.channels import (
        list_curated_channels,
    )
    catalog_channels = [
        TelegramChannelCatalogEntry(**c.to_dict()).model_dump()
        for c in list_curated_channels()
    ]
    return MonitoredSourcesResponse(
        telegram_channels=settings["telegram_monitor_channels"],
        breach_emails=settings["breach_check_emails"],
        catalog={
            "telegram_channels": catalog_channels,
            "suggested_emails": _suggested_role_emails(list(org.domains or [])),
        },
    )


@router.get("/{org_id}", response_model=OrgResponse)
async def get_organization(
    org_id: str = Path(...),
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    return await _resolve(db, org_id)


@router.post("/{org_id}/vips")
async def add_vip(
    body: VIPCreate,
    request: Request,
    analyst: AnalystUser,
    org_id: str = Path(...),
    db: AsyncSession = Depends(get_session),
):
    org = await _resolve(db, org_id)
    vip = VIPTarget(
        organization_id=org.id,
        name=body.name,
        title=body.title,
        emails=body.emails,
        usernames=body.usernames,
        phone_numbers=body.phone_numbers,
        keywords=body.keywords,
        social_profiles=body.social_profiles,
    )
    db.add(vip)
    await db.flush()

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ORG_UPDATE,
        user=analyst,
        resource_type="vip_target",
        resource_id=str(vip.id),
        details={"after": body.model_dump()},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(vip)
    return {
        "id": str(vip.id),
        "name": vip.name,
        "title": vip.title,
        "emails": vip.emails,
    }


@router.post("/{org_id}/seed-intel")
async def seed_org_intel_endpoint(
    org_id: str = Path(...),
    admin: AdminUser = None,  # noqa: B008
    request: Request = None,
    db: AsyncSession = Depends(get_session),
):
    """Re-run the per-org intel scaffold. Safe to call multiple times.

    For backfilling orgs that existed before the orchestrator landed,
    or for re-running after the operator has changed keywords/domains
    and wants the placeholders refreshed.
    """
    org = await _resolve(db, org_id)
    from src.onboarding.intel_setup import seed_org_intel
    report = await seed_org_intel(db, org)
    if request is not None and admin is not None:
        ip, ua = _client_meta(request)
        await audit_log(
            db,
            AuditAction.ORG_UPDATE,
            user=admin,
            resource_type="organization_intel_setup",
            resource_id=str(org.id),
            details=report.to_dict(),
            ip_address=ip,
            user_agent=ua,
        )
    await db.commit()
    return report.to_dict()


@router.get("/{org_id}/vips")
async def list_vips(
    org_id: str = Path(...),
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    org = await _resolve(db, org_id)
    result = await db.execute(
        select(VIPTarget).where(VIPTarget.organization_id == org.id)
    )
    return [
        {
            "id": str(v.id),
            "name": v.name,
            "title": v.title,
            "emails": v.emails,
            "usernames": v.usernames,
            "phone_numbers": v.phone_numbers,
        }
        for v in result.scalars().all()
    ]


@router.get("/{org_id}/assets")
async def list_assets(
    org_id: str = Path(...),
    analyst: AnalystUser = None,  # noqa: B008
    db: AsyncSession = Depends(get_session),
):
    org = await _resolve(db, org_id)
    result = await db.execute(
        select(Asset).where(Asset.organization_id == org.id)
    )
    return [
        {
            "id": str(a.id),
            "type": a.asset_type,
            "value": a.value,
            "details": a.details,
        }
        for a in result.scalars().all()
    ]


@router.post("/{org_id}/assets")
async def add_asset(
    body: AssetCreate,
    request: Request,
    analyst: AnalystUser,
    org_id: str = Path(...),
    db: AsyncSession = Depends(get_session),
):
    org = await _resolve(db, org_id)
    asset = Asset(
        organization_id=org.id,
        asset_type=body.asset_type,
        value=body.value,
        details=body.details,
    )
    db.add(asset)
    await db.flush()

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ORG_UPDATE,
        user=analyst,
        resource_type="asset",
        resource_id=str(asset.id),
        details={"after": body.model_dump()},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(asset)
    return {"id": str(asset.id), "type": asset.asset_type, "value": asset.value}


# ── Domain management (add / remove / list) ────────────────────────


class DomainListItem(BaseModel):
    domain: str
    is_primary: bool
    verification_status: str  # "unverified" | "pending" | "verified" | "expired"
    verified_at: str | None = None
    expires_at: str | None = None


class DomainAddPayload(BaseModel):
    domain: str
    make_primary: bool = False


@router.get("/{org_id}/domains", response_model=list[DomainListItem])
async def list_org_domains(
    org_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
) -> list[DomainListItem]:
    """List every domain registered on the org with its verification
    state. The first entry in ``Organization.domains`` is treated as
    primary. The dashboard uses this to render the verify-your-domain
    banner with a per-domain status pill."""
    from src.core.domain_verification import get_state
    org = await db.get(Organization, org_id)
    if org is None:
        raise HTTPException(404, "Organization not found")
    out: list[DomainListItem] = []
    for idx, domain in enumerate(org.domains or []):
        st = get_state(org.settings, domain)
        out.append(
            DomainListItem(
                domain=domain,
                is_primary=(idx == 0),
                verification_status=(st.status if st else "unverified"),
                verified_at=(st.verified_at if st else None),
                expires_at=(st.expires_at if st else None),
            )
        )
    return out


@router.post("/{org_id}/domains", response_model=list[DomainListItem], status_code=201)
async def add_org_domain(
    org_id: uuid.UUID,
    payload: DomainAddPayload,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
) -> list[DomainListItem]:
    """Add a domain to the org and auto-issue a verification token.

    ``make_primary=true`` moves the new domain to position 0 (the
    "primary" slot) — used when the operator realises they typed
    the wrong primary at onboarding time and wants to swap. The
    old primary remains in ``domains`` (verification state untouched)
    so the operator can re-promote it later if they want."""
    from sqlalchemy.orm.attributes import flag_modified
    from src.core.domain_verification import request_token

    raw = (payload.domain or "").strip().lower()
    for prefix in ("https://", "http://", "www."):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    raw = raw.split("/", 1)[0].split(":", 1)[0]
    if not raw or "." not in raw:
        raise HTTPException(400, "Provide a valid apex domain (e.g. example.com)")

    org = await db.get(Organization, org_id)
    if org is None:
        raise HTTPException(404, "Organization not found")

    domains = list(org.domains or [])
    if raw not in domains:
        if payload.make_primary:
            domains = [raw] + [d for d in domains if d != raw]
        else:
            domains.append(raw)
    elif payload.make_primary and domains[0] != raw:
        domains = [raw] + [d for d in domains if d != raw]

    new_settings, _state = request_token(org.settings, raw)
    org.domains = domains
    org.settings = new_settings
    flag_modified(org, "domains")
    flag_modified(org, "settings")

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ORG_UPDATE,
        user=analyst,
        resource_type="organization",
        resource_id=str(org.id),
        ip_address=ip,
        user_agent=ua,
        details={"action": "domain_added", "domain": raw, "make_primary": payload.make_primary},
    )
    await db.commit()
    await db.refresh(org)
    return await list_org_domains(org_id, analyst, db)  # type: ignore[arg-type]


@router.delete("/{org_id}/domains/{domain}", response_model=list[DomainListItem])
async def remove_org_domain(
    org_id: uuid.UUID,
    domain: str,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
) -> list[DomainListItem]:
    """Remove a domain from the org. Drops its verification state
    too — the operator can always re-add it later, which mints a
    fresh token. We don't allow removing the last domain (an org
    needs at least one entry to be monitorable)."""
    from sqlalchemy.orm.attributes import flag_modified
    org = await db.get(Organization, org_id)
    if org is None:
        raise HTTPException(404, "Organization not found")
    domains = list(org.domains or [])
    if domain not in domains:
        raise HTTPException(404, f"{domain!r} is not a registered domain on this org")
    if len(domains) <= 1:
        raise HTTPException(
            400,
            "Cannot remove the last domain. Add another domain first, "
            "then promote it to primary, then delete this one.",
        )
    domains = [d for d in domains if d != domain]
    org.domains = domains
    new_settings = dict(org.settings or {})
    block = dict(new_settings.get("domain_verification") or {})
    block.pop(domain, None)
    new_settings["domain_verification"] = block
    org.settings = new_settings
    flag_modified(org, "domains")
    flag_modified(org, "settings")

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ORG_UPDATE,
        user=analyst,
        resource_type="organization",
        resource_id=str(org.id),
        ip_address=ip,
        user_agent=ua,
        details={"action": "domain_removed", "domain": domain},
    )
    await db.commit()
    await db.refresh(org)
    return await list_org_domains(org_id, analyst, db)  # type: ignore[arg-type]


# ── Domain ownership verification ───────────────────────────────────


class VerificationStatusResponse(BaseModel):
    domain: str
    status: str  # "unverified" | "pending" | "verified" | "expired"
    token: str | None
    requested_at: str | None
    expires_at: str | None
    expires_in_hours: int | None
    ttl_hours: int
    verified_at: str | None
    last_checked_at: str | None
    last_error: str | None
    gate_required: bool  # whether ARGUS_REQUIRE_DOMAIN_VERIFICATION is on
    dns: dict[str, Any] | None  # challenge spec, present once pending
    resolvers: list[str]  # which DoH resolvers we'll consult
    quorum_required: int  # how many must match (typically 2)
    last_check_report: dict[str, Any] | None  # per-resolver result on last check


class VerificationCheckResponse(BaseModel):
    domain: str
    verified: bool
    status: str
    matches: int
    quorum_required: int
    resolvers_consulted: int
    votes: list[dict[str, Any]]  # [{resolver, matched, error}]
    last_checked_at: str | None
    last_error: str | None


def _state_to_response(
    state: Any | None,  # DomainVerificationState | None
    domain: str,
    gate_required: bool,
) -> VerificationStatusResponse:
    from src.core.domain_verification import (
        TOKEN_TTL_HOURS,
        instructions,
        _resolvers,
    )

    if state is None:
        return VerificationStatusResponse(
            domain=domain,
            status="unverified",
            token=None,
            requested_at=None,
            expires_at=None,
            expires_in_hours=None,
            ttl_hours=TOKEN_TTL_HOURS,
            verified_at=None,
            last_checked_at=None,
            last_error=None,
            gate_required=gate_required,
            dns=None,
            resolvers=[name for name, _ in _resolvers()],
            quorum_required=2,
            last_check_report=None,
        )
    inst = instructions(state)
    return VerificationStatusResponse(
        domain=domain,
        status=state.status,
        token=state.token,
        requested_at=state.requested_at,
        expires_at=state.expires_at,
        expires_in_hours=inst.get("expires_in_hours"),
        ttl_hours=TOKEN_TTL_HOURS,
        verified_at=state.verified_at,
        last_checked_at=state.last_checked_at,
        last_error=state.last_error,
        gate_required=gate_required,
        dns=inst["dns"],
        resolvers=inst["resolvers"],
        quorum_required=inst["quorum_required"],
        last_check_report=state.last_check_report,
    )


@router.get("/{org_id}/verification", response_model=VerificationStatusResponse)
async def get_verification_status(
    org_id: uuid.UUID,
    domain: str,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
) -> VerificationStatusResponse:
    """Read the current verification state for ``domain`` on this
    organization. Returns ``status='unverified'`` if no challenge has
    been issued yet — the dashboard treats that as a CTA to call
    /verification/request."""
    from src.core.domain_verification import _gate_required, get_state
    from src.models.threat import Organization

    org = await db.get(Organization, org_id)
    if org is None:
        raise HTTPException(404, "Organization not found")
    state = get_state(org.settings, domain)
    return _state_to_response(state, domain, gate_required=_gate_required())


@router.post(
    "/{org_id}/verification/request",
    response_model=VerificationStatusResponse,
)
async def request_verification(
    org_id: uuid.UUID,
    domain: str,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
) -> VerificationStatusResponse:
    """Issue (or reuse) a verification token for ``domain``. The
    response carries the DNS TXT + HTTP-file challenge specs. Calling
    twice for a still-pending domain returns the same token so
    operator instructions stay stable across browser refreshes."""
    from src.core.domain_verification import _gate_required, request_token
    from src.models.threat import Organization
    from sqlalchemy.orm.attributes import flag_modified

    org = await db.get(Organization, org_id)
    if org is None:
        raise HTTPException(404, "Organization not found")
    if domain not in (org.domains or []):
        raise HTTPException(
            400, f"{domain!r} is not registered as a domain on this organization"
        )

    new_settings, state = request_token(org.settings, domain)
    org.settings = new_settings
    flag_modified(org, "settings")
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ORG_UPDATE,
        user=analyst,
        resource_type="organization",
        resource_id=str(org.id),
        ip_address=ip,
        user_agent=ua,
        details={"action": "domain_verification_requested", "domain": domain},
    )
    await db.commit()
    return _state_to_response(state, domain, gate_required=_gate_required())


@router.post(
    "/{org_id}/verification/check",
    response_model=VerificationCheckResponse,
)
async def check_verification(
    org_id: uuid.UUID,
    domain: str,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
) -> VerificationCheckResponse:
    """Run the DNS + HTTP challenges and update state. Either one
    matching the issued token marks the domain verified."""
    from src.core.domain_verification import check
    from src.models.threat import Organization
    from sqlalchemy.orm.attributes import flag_modified

    org = await db.get(Organization, org_id)
    if org is None:
        raise HTTPException(404, "Organization not found")

    try:
        new_settings, state, report = await check(org.settings, domain)
    except ValueError as e:
        raise HTTPException(400, str(e))

    org.settings = new_settings
    flag_modified(org, "settings")
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.ORG_UPDATE,
        user=analyst,
        resource_type="organization",
        resource_id=str(org.id),
        ip_address=ip,
        user_agent=ua,
        details={
            "action": "domain_verification_checked",
            "domain": domain,
            "verified": report["verified"],
        },
    )
    await db.commit()

    return VerificationCheckResponse(
        domain=domain,
        verified=report["verified"],
        status=state.status,
        matches=report.get("matches", 0),
        quorum_required=report.get("quorum_required", 2),
        resolvers_consulted=report.get("resolvers_consulted", 0),
        votes=report.get("votes", []),
        last_checked_at=state.last_checked_at,
        last_error=state.last_error,
    )
