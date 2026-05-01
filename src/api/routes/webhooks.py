"""Webhook / integration management endpoints — complete rewrite."""

from __future__ import annotations


import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AdminUser, CurrentUser, audit_log
from src.models.auth import AuditAction
from src.models.intel import (
    WebhookDelivery,
    WebhookDeliveryStatus,
    WebhookEndpoint,
)
from src.storage.database import get_session

router = APIRouter(prefix="/integrations", tags=["Operations"])


# --- Schemas ---


class EndpointCreate(BaseModel):
    name: str
    url: str
    endpoint_type: str = "generic"  # "slack", "siem", "generic"
    secret: str | None = None
    headers: dict | None = None
    enabled: bool = True
    min_severity: str = "medium"
    organization_id: uuid.UUID | None = None


class EndpointUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    endpoint_type: str | None = None
    secret: str | None = None
    headers: dict | None = None
    enabled: bool | None = None
    min_severity: str | None = None
    organization_id: uuid.UUID | None = None


class EndpointResponse(BaseModel):
    id: uuid.UUID
    name: str
    url: str
    endpoint_type: str
    headers: dict | None
    enabled: bool
    min_severity: str
    organization_id: uuid.UUID | None
    last_delivery_at: datetime | None
    failure_count: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DeliveryResponse(BaseModel):
    id: uuid.UUID
    endpoint_id: uuid.UUID
    alert_id: uuid.UUID | None
    payload: dict
    status: str
    status_code: int | None
    response_body: str | None
    attempt_count: int
    delivered_at: datetime | None
    next_retry_at: datetime | None

    model_config = {"from_attributes": True}


class TestDeliveryResult(BaseModel):
    success: bool
    status_code: int | None
    response_body: str | None
    error: str | None


# --- Helpers ---


def _sign_payload(payload_bytes: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 signature for webhook payload."""
    return hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()


async def _deliver_payload(url: str, payload: dict, secret: str | None, custom_headers: dict | None) -> tuple[bool, int | None, str | None, str | None]:
    """Actually POST a JSON payload to a webhook URL. Returns (success, status_code, response_body, error)."""
    payload_bytes = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}

    if secret:
        signature = _sign_payload(payload_bytes, secret)
        headers["X-Argus-Signature"] = signature

    if custom_headers:
        headers.update(custom_headers)

    timeout = aiohttp.ClientTimeout(total=30)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, data=payload_bytes, headers=headers) as resp:
                body = await resp.text(errors="replace")
                success = 200 <= resp.status < 300
                return success, resp.status, body[:2000], None
    except Exception as exc:
        return False, None, None, str(exc)


# --- Routes ---


@router.get("/endpoints", response_model=list[EndpointResponse])
async def list_endpoints(
    user: CurrentUser,
    endpoint_type: str | None = None,
    enabled: bool | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_session),
):
    """List all webhook endpoints."""
    query = select(WebhookEndpoint).order_by(WebhookEndpoint.name)

    if endpoint_type:
        query = query.where(WebhookEndpoint.endpoint_type == endpoint_type)
    if enabled is not None:
        query = query.where(WebhookEndpoint.enabled == enabled)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/endpoints", response_model=EndpointResponse, status_code=201)
async def create_endpoint(
    body: EndpointCreate,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Create a new webhook endpoint."""
    endpoint = WebhookEndpoint(
        name=body.name,
        url=body.url,
        endpoint_type=body.endpoint_type,
        secret=body.secret,
        headers=body.headers,
        enabled=body.enabled,
        min_severity=body.min_severity,
        organization_id=body.organization_id,
    )
    db.add(endpoint)

    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=user,
        resource_type="webhook_endpoint",
        resource_id=str(endpoint.id),
        details={"action": "create", "name": body.name, "type": body.endpoint_type},
    )

    await db.commit()
    await db.refresh(endpoint)
    return endpoint


@router.patch("/endpoints/{endpoint_id}", response_model=EndpointResponse)
async def update_endpoint(
    endpoint_id: uuid.UUID,
    body: EndpointUpdate,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Update a webhook endpoint."""
    endpoint = await db.get(WebhookEndpoint, endpoint_id)
    if not endpoint:
        raise HTTPException(404, "Webhook endpoint not found")

    changes = {}
    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        old_value = getattr(endpoint, field)
        if old_value != value:
            setattr(endpoint, field, value)
            # Don't log secret values
            if field == "secret":
                changes[field] = {"old": "***", "new": "***"}
            else:
                changes[field] = {"old": str(old_value), "new": str(value)}

    if changes:
        await audit_log(
            db,
            AuditAction.SETTINGS_UPDATE,
            user=user,
            resource_type="webhook_endpoint",
            resource_id=str(endpoint_id),
            details=changes,
        )

    await db.commit()
    await db.refresh(endpoint)
    return endpoint


@router.delete("/endpoints/{endpoint_id}", status_code=204)
async def delete_endpoint(
    endpoint_id: uuid.UUID,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Delete a webhook endpoint and all its delivery records."""
    endpoint = await db.get(WebhookEndpoint, endpoint_id)
    if not endpoint:
        raise HTTPException(404, "Webhook endpoint not found")

    endpoint_name = endpoint.name
    await db.delete(endpoint)

    await audit_log(
        db,
        AuditAction.SETTINGS_UPDATE,
        user=user,
        resource_type="webhook_endpoint",
        resource_id=str(endpoint_id),
        details={"action": "delete", "name": endpoint_name},
    )

    await db.commit()


@router.post("/endpoints/{endpoint_id}/test", response_model=TestDeliveryResult)
async def test_endpoint(
    endpoint_id: uuid.UUID,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Send a test payload to a webhook endpoint."""
    endpoint = await db.get(WebhookEndpoint, endpoint_id)
    if not endpoint:
        raise HTTPException(404, "Webhook endpoint not found")

    test_payload = _build_test_payload(endpoint)

    success, status_code, response_body, error = await _deliver_payload(
        endpoint.url,
        test_payload,
        endpoint.secret,
        endpoint.headers,
    )

    # Record the test delivery
    delivery = WebhookDelivery(
        endpoint_id=endpoint.id,
        alert_id=None,
        payload=test_payload,
        status=WebhookDeliveryStatus.DELIVERED.value if success else WebhookDeliveryStatus.FAILED.value,
        status_code=status_code,
        response_body=response_body[:2000] if response_body else None,
        attempt_count=1,
        delivered_at=datetime.now(timezone.utc) if success else None,
    )
    db.add(delivery)
    await db.commit()

    return TestDeliveryResult(
        success=success,
        status_code=status_code,
        response_body=response_body,
        error=error,
    )


def _build_test_payload(endpoint: WebhookEndpoint) -> dict:
    """Build a test payload appropriate for the endpoint type."""
    if endpoint.endpoint_type == "slack":
        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "\U0001f6ce\ufe0f Test Notification \u2014 Argus",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": "*Type*\nTest"},
                        {"type": "mrkdwn", "text": "*Status*\nConnectivity Check"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "This is a test notification from Argus to verify your Slack webhook integration is working correctly.",
                    },
                },
            ],
        }
    else:
        return {
            "event": "test",
            "source": "argus",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": "This is a test delivery from Argus to verify webhook connectivity.",
        }


@router.get("/deliveries", response_model=list[DeliveryResponse])
async def list_deliveries(
    user: CurrentUser,
    endpoint_id: uuid.UUID | None = None,
    status: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_session),
):
    """List recent webhook deliveries with optional filters."""
    query = select(WebhookDelivery).order_by(desc(WebhookDelivery.id))

    if endpoint_id:
        query = query.where(WebhookDelivery.endpoint_id == endpoint_id)
    if status:
        query = query.where(WebhookDelivery.status == status)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/deliveries/{delivery_id}/retry", response_model=DeliveryResponse)
async def retry_delivery(
    delivery_id: uuid.UUID,
    user: AdminUser,
    db: AsyncSession = Depends(get_session),
):
    """Retry a failed webhook delivery."""
    delivery = await db.get(WebhookDelivery, delivery_id)
    if not delivery:
        raise HTTPException(404, "Delivery not found")

    if delivery.status == WebhookDeliveryStatus.DELIVERED.value:
        raise HTTPException(400, "Delivery already succeeded — nothing to retry")

    endpoint = await db.get(WebhookEndpoint, delivery.endpoint_id)
    if not endpoint:
        raise HTTPException(404, "Associated webhook endpoint no longer exists")

    success, status_code, response_body, error = await _deliver_payload(
        endpoint.url,
        delivery.payload,
        endpoint.secret,
        endpoint.headers,
    )

    now = datetime.now(timezone.utc)
    delivery.attempt_count += 1
    delivery.status_code = status_code
    delivery.response_body = response_body[:2000] if response_body else error

    if success:
        delivery.status = WebhookDeliveryStatus.DELIVERED.value
        delivery.delivered_at = now
        delivery.next_retry_at = None
        endpoint.failure_count = max(0, endpoint.failure_count - 1)
        endpoint.last_delivery_at = now
    else:
        delivery.status = WebhookDeliveryStatus.FAILED.value
        endpoint.failure_count += 1

    await audit_log(
        db,
        AuditAction.WEBHOOK_DELIVER,
        user=user,
        resource_type="webhook_delivery",
        resource_id=str(delivery_id),
        details={"retry": True, "success": success, "attempt": delivery.attempt_count},
    )

    await db.commit()
    await db.refresh(delivery)
    return delivery
