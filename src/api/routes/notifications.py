"""Notification Router API.

Endpoints
---------
    GET    /notifications/adapters                         list supported adapter kinds
    POST   /notifications/channels                         create
    GET    /notifications/channels?organization_id=…       list
    GET    /notifications/channels/{id}                    fetch
    PATCH  /notifications/channels/{id}                    update (rotate secret optional)
    DELETE /notifications/channels/{id}                    delete
    POST   /notifications/channels/{id}/test               send a synthetic test event

    POST   /notifications/rules                            create
    GET    /notifications/rules?organization_id=…          list
    GET    /notifications/rules/{id}                       fetch
    PATCH  /notifications/rules/{id}                       update
    DELETE /notifications/rules/{id}                       delete

    GET    /notifications/deliveries?organization_id=…     list with filters
    POST   /notifications/dispatch                         manually fire an event (dry_run optional)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, audit_log
from src.core.crypto import decrypt, encrypt
from src.core.url_safety import UnsafeUrlError, assert_safe_url
from src.models.auth import AuditAction
from src.core.auth import CurrentUser
from src.models.notification_inbox import NotificationInboxItem
from src.models.notifications import (
    SEVERITY_ORDER,
    ChannelKind,
    DeliveryStatus,
    EventKind,
    NotificationChannel,
    NotificationDelivery,
    NotificationRule,
    SeverityLevel,
)
from src.models.threat import Organization
from src.notifications.adapters import (
    NotificationEvent,
    supported_kinds,
)
from src.notifications.router import dispatch
from src.storage.database import get_session

router = APIRouter(prefix="/notifications", tags=["Operations"])


# --- Auditless audit-action shorthand for this domain -------------------


def _client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    ua = request.headers.get("User-Agent", "unknown")[:500]
    return ip, ua


# --- Schemas ------------------------------------------------------------


class ChannelCreate(BaseModel):
    organization_id: uuid.UUID
    name: str = Field(min_length=1, max_length=200)
    kind: ChannelKind
    config: dict[str, Any] = Field(default_factory=dict)
    secret: str | None = None  # plaintext on the wire, encrypted at rest
    description: str | None = None
    enabled: bool = True


class ChannelUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    config: dict[str, Any] | None = None
    secret: str | None = None  # supplying any value rotates the secret; null = no change
    rotate_clear: bool = False  # if true, removes the stored secret
    description: str | None = None
    enabled: bool | None = None


class ChannelResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    kind: str
    config: dict
    has_secret: bool
    description: str | None
    enabled: bool
    last_used_at: datetime | None
    last_status: str | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RuleCreate(BaseModel):
    organization_id: uuid.UUID
    name: str = Field(min_length=1, max_length=200)
    enabled: bool = True
    event_kinds: list[EventKind] = Field(default_factory=list)
    min_severity: SeverityLevel = SeverityLevel.LOW
    asset_criticalities: list[str] = Field(default_factory=list)
    asset_types: list[str] = Field(default_factory=list)
    tags_any: list[str] = Field(default_factory=list)
    channel_ids: list[uuid.UUID]
    dedup_window_seconds: int = Field(default=300, ge=0, le=24 * 3600)
    description: str | None = None
    # Quiet hours config — stored as ``description`` JSON tail so we
    # don't need a new column. Format: {start:"22:00", end:"07:00",
    # tz:"Asia/Dubai", except_severity:"critical"}
    quiet_hours: dict[str, Any] | None = None


class RuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    enabled: bool | None = None
    event_kinds: list[EventKind] | None = None
    min_severity: SeverityLevel | None = None
    asset_criticalities: list[str] | None = None
    asset_types: list[str] | None = None
    tags_any: list[str] | None = None
    channel_ids: list[uuid.UUID] | None = None
    dedup_window_seconds: int | None = Field(default=None, ge=0, le=24 * 3600)
    description: str | None = None
    quiet_hours: dict[str, Any] | None = None


class RuleResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    enabled: bool
    event_kinds: list[str]
    min_severity: str
    asset_criticalities: list[str]
    asset_types: list[str]
    tags_any: list[str]
    channel_ids: list[uuid.UUID]
    dedup_window_seconds: int
    description: str | None
    quiet_hours: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DeliveryResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    rule_id: uuid.UUID | None
    channel_id: uuid.UUID | None
    event_kind: str
    event_severity: str
    event_dedup_key: str | None
    event_payload: dict
    status: str
    attempts: int
    latency_ms: int | None
    response_status: int | None
    response_body: str | None
    error_message: str | None
    delivered_at: datetime | None
    rendered_payload: dict | None = None
    cluster_count: int | None = None
    cluster_dedup_key: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DispatchRequest(BaseModel):
    organization_id: uuid.UUID
    kind: EventKind
    severity: SeverityLevel
    title: str
    summary: str
    dedup_key: str | None = None
    asset_criticality: str | None = None
    asset_type: str | None = None
    tags: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False


# --- Helpers ------------------------------------------------------------


async def _ensure_org(db: AsyncSession, org_id: uuid.UUID) -> Organization:
    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    return org


def _validate_channel_urls(kind: str, config: dict, secret: str | None) -> None:
    """Audit B9 — apply SSRF guards to any user-supplied URL.

    Rules per channel kind:
        slack / teams       webhook URL is the secret OR config.webhook_url
        webhook             config.url required
        pagerduty           optional config.events_url override
        opsgenie            optional config.alerts_url override
        jasmin_sms          config.endpoint
        email               no URL
    """
    kind_str = kind if isinstance(kind, str) else kind.value
    cfg = config or {}
    urls: list[str] = []
    if kind_str in ("slack", "teams"):
        url = secret or cfg.get("webhook_url")
        if url:
            urls.append(url)
    elif kind_str == "webhook":
        url = cfg.get("url")
        if url:
            urls.append(url)
    elif kind_str == "pagerduty":
        if cfg.get("events_url"):
            urls.append(cfg["events_url"])
    elif kind_str == "opsgenie":
        if cfg.get("alerts_url"):
            urls.append(cfg["alerts_url"])
    elif kind_str == "jasmin_sms":
        if cfg.get("endpoint"):
            urls.append(cfg["endpoint"])
    for u in urls:
        try:
            assert_safe_url(u, allow_http=True)  # internal Jasmin/PD/etc may be HTTP within VPC
        except UnsafeUrlError as e:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, f"unsafe url: {e}"
            )


# Quiet hours are stored inline in `description` to avoid a schema
# migration. The convention: ``description`` may end with a marker
# line ``\n##QH##{json}`` carrying the quiet-hours config.
import json as _json

_QH_MARKER = "\n##QH##"


def _split_qh(description: str | None) -> tuple[str | None, dict[str, Any] | None]:
    if not description:
        return description, None
    idx = description.find(_QH_MARKER)
    if idx < 0:
        return description, None
    head = description[:idx] or None
    tail = description[idx + len(_QH_MARKER):]
    try:
        return head, _json.loads(tail)
    except Exception:  # noqa: BLE001
        return head, None


def _join_qh(description: str | None, quiet_hours: dict[str, Any] | None) -> str | None:
    base = description or ""
    if quiet_hours:
        base = f"{base}{_QH_MARKER}{_json.dumps(quiet_hours, separators=(',', ':'))}"
    return base or None


def _rule_to_response(rule: NotificationRule) -> RuleResponse:
    head, qh = _split_qh(rule.description)
    return RuleResponse(
        id=rule.id,
        organization_id=rule.organization_id,
        name=rule.name,
        enabled=rule.enabled,
        event_kinds=list(rule.event_kinds or []),
        min_severity=rule.min_severity,
        asset_criticalities=list(rule.asset_criticalities or []),
        asset_types=list(rule.asset_types or []),
        tags_any=list(rule.tags_any or []),
        channel_ids=list(rule.channel_ids or []),
        dedup_window_seconds=rule.dedup_window_seconds,
        description=head,
        quiet_hours=qh,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


def _channel_to_response(ch: NotificationChannel) -> ChannelResponse:
    return ChannelResponse(
        id=ch.id,
        organization_id=ch.organization_id,
        name=ch.name,
        kind=ch.kind,
        config=dict(ch.config or {}),
        has_secret=bool(ch.secret_ciphertext),
        description=ch.description,
        enabled=ch.enabled,
        last_used_at=ch.last_used_at,
        last_status=ch.last_status,
        last_error=ch.last_error,
        created_at=ch.created_at,
        updated_at=ch.updated_at,
    )


# --- Adapters meta ------------------------------------------------------


@router.get("/adapters")
async def list_adapters(analyst: AnalystUser):
    return {"kinds": supported_kinds()}


# --- Channels -----------------------------------------------------------


@router.post("/channels", response_model=ChannelResponse, status_code=201)
async def create_channel(
    body: ChannelCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    await _ensure_org(db, body.organization_id)
    # Audit B9 — SSRF defence on user-supplied webhook / endpoint URLs.
    _validate_channel_urls(body.kind, body.config, body.secret)
    ciphertext = encrypt(body.secret) if body.secret else None
    ch = NotificationChannel(
        organization_id=body.organization_id,
        name=body.name.strip(),
        kind=body.kind.value,
        config=body.config,
        secret_ciphertext=ciphertext,
        description=body.description,
        enabled=body.enabled,
    )
    db.add(ch)
    await db.flush()

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=analyst,
        resource_type="notification_channel",
        resource_id=str(ch.id),
        details={"action": "create", "kind": body.kind.value, "name": body.name},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(ch)
    return _channel_to_response(ch)


@router.get("/channels", response_model=list[ChannelResponse])
async def list_channels(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    kind: ChannelKind | None = None,
    enabled: bool | None = None,
):
    await _ensure_org(db, organization_id)
    query = select(NotificationChannel).where(
        NotificationChannel.organization_id == organization_id
    )
    if kind is not None:
        query = query.where(NotificationChannel.kind == kind.value)
    if enabled is not None:
        query = query.where(NotificationChannel.enabled == enabled)
    rows = (await db.execute(query.order_by(NotificationChannel.created_at.desc()))).scalars().all()
    return [_channel_to_response(c) for c in rows]


@router.get("/channels/{channel_id}", response_model=ChannelResponse)
async def get_channel(
    channel_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    ch = await db.get(NotificationChannel, channel_id)
    if not ch:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Channel not found")
    return _channel_to_response(ch)


@router.patch("/channels/{channel_id}", response_model=ChannelResponse)
async def update_channel(
    channel_id: uuid.UUID,
    body: ChannelUpdate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    ch = await db.get(NotificationChannel, channel_id)
    if not ch:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Channel not found")

    # Audit B9 — re-validate URL on every update (catches DNS rebinding too).
    new_config = body.config if body.config is not None else (ch.config or {})
    new_secret = body.secret if body.secret is not None else None
    _validate_channel_urls(ch.kind, new_config, new_secret)

    changes: dict[str, Any] = {}
    if body.name is not None:
        ch.name = body.name.strip()
        changes["name"] = ch.name
    if body.config is not None:
        ch.config = body.config
        changes["config"] = True
    if body.secret is not None:
        ch.secret_ciphertext = encrypt(body.secret)
        changes["secret"] = "rotated"
    if body.rotate_clear:
        ch.secret_ciphertext = None
        changes["secret"] = "cleared"
    if body.description is not None:
        ch.description = body.description
        changes["description"] = True
    if body.enabled is not None:
        ch.enabled = body.enabled
        changes["enabled"] = body.enabled

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=analyst,
        resource_type="notification_channel",
        resource_id=str(ch.id),
        details={"action": "update", "changes": changes},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(ch)
    return _channel_to_response(ch)


@router.delete("/channels/{channel_id}", status_code=204)
async def delete_channel(
    channel_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    ch = await db.get(NotificationChannel, channel_id)
    if not ch:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Channel not found")
    org_id = ch.organization_id
    name = ch.name
    await db.delete(ch)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=analyst,
        resource_type="notification_channel",
        resource_id=str(channel_id),
        details={"action": "delete", "organization_id": str(org_id), "name": name},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return None


@router.post("/channels/{channel_id}/test", response_model=DeliveryResponse)
async def test_channel(
    channel_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Fire a synthetic ``test`` event through this single channel.

    Bypasses rule matching by creating a temporary in-memory rule that
    points only at this channel.
    """
    ch = await db.get(NotificationChannel, channel_id)
    if not ch:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Channel not found")
    if not ch.enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Channel is disabled")

    # Create a one-shot rule scoped to this channel + a unique kind so
    # other rules don't match.
    one_shot = NotificationRule(
        organization_id=ch.organization_id,
        name=f"__test_{ch.id}__",
        enabled=True,
        event_kinds=[EventKind.TEST.value],
        min_severity=SeverityLevel.INFO.value,
        channel_ids=[ch.id],
        dedup_window_seconds=0,
    )
    db.add(one_shot)
    await db.flush()

    event = NotificationEvent(
        kind=EventKind.TEST.value,
        severity=SeverityLevel.INFO.value,
        title="Argus test notification",
        summary=f"This is a synthetic test of channel {ch.name!r}.",
        organization_id=str(ch.organization_id),
        dedup_key=f"test:{ch.id}:{uuid.uuid4()}",
        tags=("test",),
        extra={"channel_id": str(ch.id)},
    )
    deliveries = await dispatch(db, event)

    # Cleanup the one-shot rule
    await db.delete(one_shot)
    await db.commit()

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=analyst,
        resource_type="notification_channel",
        resource_id=str(ch.id),
        details={"action": "test", "deliveries": len(deliveries)},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()

    if not deliveries:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Test produced no delivery — adapter or matcher misconfigured",
        )
    return DeliveryResponse.model_validate(deliveries[0])


# --- Rules --------------------------------------------------------------


def _validate_channel_ownership(
    db: AsyncSession, channel_ids: list[uuid.UUID], organization_id: uuid.UUID
):
    """All referenced channels must belong to the same org as the rule."""

    async def _check():
        if not channel_ids:
            return
        rows = (
            await db.execute(
                select(NotificationChannel).where(
                    NotificationChannel.id.in_(channel_ids)
                )
            )
        ).scalars().all()
        found = {c.id for c in rows}
        missing = set(channel_ids) - found
        if missing:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                f"channel_ids contain unknown values: {sorted(map(str, missing))}",
            )
        wrong_org = [
            str(c.id) for c in rows if c.organization_id != organization_id
        ]
        if wrong_org:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                f"channel_ids belong to a different organization: {wrong_org}",
            )

    return _check()


@router.post("/rules", response_model=RuleResponse, status_code=201)
async def create_rule(
    body: RuleCreate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    await _ensure_org(db, body.organization_id)
    await _validate_channel_ownership(db, body.channel_ids, body.organization_id)
    rule = NotificationRule(
        organization_id=body.organization_id,
        name=body.name.strip(),
        enabled=body.enabled,
        event_kinds=[k.value for k in body.event_kinds],
        min_severity=body.min_severity.value,
        asset_criticalities=body.asset_criticalities,
        asset_types=body.asset_types,
        tags_any=body.tags_any,
        channel_ids=body.channel_ids,
        dedup_window_seconds=body.dedup_window_seconds,
        description=_join_qh(body.description, body.quiet_hours),
    )
    db.add(rule)
    await db.flush()
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=analyst,
        resource_type="notification_rule",
        resource_id=str(rule.id),
        details={"action": "create", "name": body.name},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(rule)
    return _rule_to_response(rule)


@router.get("/rules", response_model=list[RuleResponse])
async def list_rules(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    enabled: bool | None = None,
):
    await _ensure_org(db, organization_id)
    q = select(NotificationRule).where(
        NotificationRule.organization_id == organization_id
    )
    if enabled is not None:
        q = q.where(NotificationRule.enabled == enabled)
    rows = (await db.execute(q.order_by(NotificationRule.created_at.desc()))).scalars().all()
    return [_rule_to_response(r) for r in rows]


@router.get("/rules/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    rule = await db.get(NotificationRule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    return _rule_to_response(rule)


@router.patch("/rules/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: uuid.UUID,
    body: RuleUpdate,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    rule = await db.get(NotificationRule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    if body.channel_ids is not None:
        await _validate_channel_ownership(
            db, body.channel_ids, rule.organization_id
        )
        rule.channel_ids = body.channel_ids
    if body.name is not None:
        rule.name = body.name.strip()
    if body.enabled is not None:
        rule.enabled = body.enabled
    if body.event_kinds is not None:
        rule.event_kinds = [k.value for k in body.event_kinds]
    if body.min_severity is not None:
        rule.min_severity = body.min_severity.value
    if body.asset_criticalities is not None:
        rule.asset_criticalities = body.asset_criticalities
    if body.asset_types is not None:
        rule.asset_types = body.asset_types
    if body.tags_any is not None:
        rule.tags_any = body.tags_any
    if body.dedup_window_seconds is not None:
        rule.dedup_window_seconds = body.dedup_window_seconds
    # description + quiet_hours roll into the same column.
    if body.description is not None or body.quiet_hours is not None:
        cur_desc, cur_qh = _split_qh(rule.description)
        new_desc = body.description if body.description is not None else cur_desc
        new_qh = body.quiet_hours if body.quiet_hours is not None else cur_qh
        rule.description = _join_qh(new_desc, new_qh)

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=analyst,
        resource_type="notification_rule",
        resource_id=str(rule.id),
        details={"action": "update"},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    await db.refresh(rule)
    return _rule_to_response(rule)


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: uuid.UUID,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    rule = await db.get(NotificationRule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    org_id = rule.organization_id
    name = rule.name
    await db.delete(rule)
    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=analyst,
        resource_type="notification_rule",
        resource_id=str(rule_id),
        details={"action": "delete", "organization_id": str(org_id), "name": name},
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return None


# --- Deliveries ---------------------------------------------------------


@router.get("/deliveries", response_model=list[DeliveryResponse])
async def list_deliveries(
    organization_id: uuid.UUID,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
    status_filter: Annotated[DeliveryStatus | None, Query(alias="status")] = None,
    channel_id: uuid.UUID | None = None,
    rule_id: uuid.UUID | None = None,
    event_kind: EventKind | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    await _ensure_org(db, organization_id)
    q = select(NotificationDelivery).where(
        NotificationDelivery.organization_id == organization_id
    )
    if status_filter is not None:
        q = q.where(NotificationDelivery.status == status_filter.value)
    if channel_id is not None:
        q = q.where(NotificationDelivery.channel_id == channel_id)
    if rule_id is not None:
        q = q.where(NotificationDelivery.rule_id == rule_id)
    if event_kind is not None:
        q = q.where(NotificationDelivery.event_kind == event_kind.value)
    q = q.order_by(NotificationDelivery.created_at.desc()).limit(limit)
    return list((await db.execute(q)).scalars().all())


# --- Manual dispatch ----------------------------------------------------


@router.post("/dispatch", response_model=list[DeliveryResponse])
async def dispatch_event(
    body: DispatchRequest,
    request: Request,
    analyst: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    await _ensure_org(db, body.organization_id)

    event = NotificationEvent(
        kind=body.kind.value,
        severity=body.severity.value,
        title=body.title,
        summary=body.summary,
        organization_id=str(body.organization_id),
        dedup_key=body.dedup_key,
        asset_criticality=body.asset_criticality,
        asset_type=body.asset_type,
        tags=tuple(body.tags),
        extra=body.extra,
    )
    deliveries = await dispatch(db, event, dry_run=body.dry_run)

    ip, ua = _client_meta(request)
    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=analyst,
        resource_type="notification_event",
        resource_id=str(uuid.uuid4()),
        details={
            "action": "dispatch",
            "kind": body.kind.value,
            "severity": body.severity.value,
            "deliveries": len(deliveries),
            "dry_run": body.dry_run,
        },
        ip_address=ip,
        user_agent=ua,
    )
    await db.commit()
    return deliveries


# --- Inbox --------------------------------------------------------------


class InboxResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    user_id: uuid.UUID | None
    rule_id: uuid.UUID | None
    delivery_id: uuid.UUID | None
    event_kind: str
    severity: str
    title: str
    summary: str | None
    link_path: str | None
    payload: dict
    read_at: datetime | None
    archived_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


@router.get("/inbox", response_model=list[InboxResponse])
async def list_inbox(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
    unread_only: bool = False,
    include_archived: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    q = select(NotificationInboxItem).where(
        NotificationInboxItem.user_id == user.id
    )
    if unread_only:
        q = q.where(NotificationInboxItem.read_at.is_(None))
    if not include_archived:
        q = q.where(NotificationInboxItem.archived_at.is_(None))
    # Hide the synthetic preferences row.
    q = q.where(NotificationInboxItem.event_kind != "user_pref")
    q = q.order_by(NotificationInboxItem.created_at.desc()).limit(limit)
    rows = (await db.execute(q)).scalars().all()
    return list(rows)


@router.get("/inbox/unread-count")
async def inbox_unread_count(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    from sqlalchemy import func
    res = await db.execute(
        select(func.count(NotificationInboxItem.id)).where(
            and_(
                NotificationInboxItem.user_id == user.id,
                NotificationInboxItem.read_at.is_(None),
                NotificationInboxItem.archived_at.is_(None),
                NotificationInboxItem.event_kind != "user_pref",
            )
        )
    )
    return {"unread": int(res.scalar_one() or 0)}


@router.post("/inbox/{item_id}/read", response_model=InboxResponse)
async def mark_inbox_read(
    item_id: uuid.UUID,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
    unread: bool = False,
):
    from datetime import timezone as _tz
    item = await db.get(NotificationInboxItem, item_id)
    if not item or item.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Inbox item not found")
    item.read_at = None if unread else datetime.now(_tz.utc)
    await db.commit()
    await db.refresh(item)
    return item


@router.post("/inbox/read-all")
async def mark_inbox_read_all(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    from datetime import timezone as _tz
    from sqlalchemy import update as sa_update
    now = datetime.now(_tz.utc)
    res = await db.execute(
        sa_update(NotificationInboxItem)
        .where(
            and_(
                NotificationInboxItem.user_id == user.id,
                NotificationInboxItem.read_at.is_(None),
                NotificationInboxItem.archived_at.is_(None),
                NotificationInboxItem.event_kind != "user_pref",
            )
        )
        .values(read_at=now)
    )
    await db.commit()
    return {"updated": int(res.rowcount or 0)}


@router.post("/inbox/{item_id}/archive", response_model=InboxResponse)
async def archive_inbox(
    item_id: uuid.UUID,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
    unarchive: bool = False,
):
    from datetime import timezone as _tz
    item = await db.get(NotificationInboxItem, item_id)
    if not item or item.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Inbox item not found")
    item.archived_at = None if unarchive else datetime.now(_tz.utc)
    await db.commit()
    await db.refresh(item)
    return item


# --- Per-user preferences ----------------------------------------------
#
# We don't add a migration. Preferences are stored as a single
# notification_inbox row per user with event_kind="user_pref" and the
# preferences encoded in ``payload``. Read-time we look it up; write-
# time we upsert. The list_inbox endpoint filters this row out.


class PreferencesPayload(BaseModel):
    """Per-user delivery preferences.

    opt_out_channels        list of channel ids the user does not want pinged
    max_per_rule_per_hour   simple frequency cap (0 = unlimited)
    escalation_after_min    if alert unread for N minutes, repeat to escalation channel
    do_not_disturb          fully mute everything until ``dnd_until`` ISO ts
    dnd_until               ISO timestamp; null = indefinite when do_not_disturb=true
    """

    opt_out_channels: list[uuid.UUID] = Field(default_factory=list)
    max_per_rule_per_hour: int = Field(default=0, ge=0, le=1000)
    escalation_after_min: int = Field(default=0, ge=0, le=24 * 60)
    do_not_disturb: bool = False
    dnd_until: datetime | None = None


async def _get_pref_row(
    db: AsyncSession, user_id: uuid.UUID, organization_id: uuid.UUID | None = None
) -> NotificationInboxItem | None:
    q = select(NotificationInboxItem).where(
        and_(
            NotificationInboxItem.user_id == user_id,
            NotificationInboxItem.event_kind == "user_pref",
        )
    )
    return (await db.execute(q.limit(1))).scalar_one_or_none()


@router.get("/preferences/me")
async def get_my_preferences(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    row = await _get_pref_row(db, user.id)
    if row is None:
        return PreferencesPayload().model_dump(mode="json")
    return row.payload or PreferencesPayload().model_dump(mode="json")


@router.put("/preferences/me")
async def put_my_preferences(
    body: PreferencesPayload,
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    row = await _get_pref_row(db, user.id)
    payload = body.model_dump(mode="json")
    if row is None:
        # Need an org id for the row. Use the first org the user can see;
        # fall back to a NIL UUID — preferences are user-scoped anyway.
        org_q = await db.execute(select(Organization).limit(1))
        org = org_q.scalar_one_or_none()
        org_id = org.id if org else uuid.UUID("00000000-0000-0000-0000-000000000000")
        row = NotificationInboxItem(
            organization_id=org_id,
            user_id=user.id,
            event_kind="user_pref",
            severity="info",
            title="user preferences",
            summary=None,
            payload=payload,
        )
        db.add(row)
    else:
        row.payload = payload
    await db.commit()
    return payload
