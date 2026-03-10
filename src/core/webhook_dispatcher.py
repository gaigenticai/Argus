"""Webhook delivery engine — dispatches alerts to configured webhook endpoints."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone, timedelta

import aiohttp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.intel import (
    CrawlerSource,
    WebhookDelivery,
    WebhookDeliveryStatus,
    WebhookEndpoint,
)
from src.models.threat import Alert

logger_wh = logging.getLogger("argus.webhook")

# Severity ordering for min_severity filtering
SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Retry backoff schedule: attempt -> delay in minutes
RETRY_BACKOFF = {
    1: 1,     # 1 minute
    2: 5,     # 5 minutes
    3: 30,    # 30 minutes
}

MAX_RETRY_ATTEMPTS = 3


def _sign_payload(payload_bytes: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 signature."""
    return hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()


def _severity_meets_threshold(alert_severity: str, min_severity: str) -> bool:
    """Check if alert severity meets or exceeds the endpoint's minimum threshold."""
    alert_level = SEVERITY_ORDER.get(alert_severity, 0)
    min_level = SEVERITY_ORDER.get(min_severity, 0)
    return alert_level >= min_level


def _severity_color(severity: str) -> str:
    """Map severity to Slack attachment color."""
    return {
        "critical": "#FF0000",
        "high": "#FF5630",
        "medium": "#FFAB00",
        "low": "#00BBD9",
        "info": "#8E33FF",
    }.get(severity, "#636363")


def _severity_emoji(severity: str) -> str:
    """Map severity to emoji for Slack header."""
    return {
        "critical": "\U0001f6a8",
        "high": "\U0001f525",
        "medium": "\u26a0\ufe0f",
        "low": "\U0001f535",
        "info": "\u2139\ufe0f",
    }.get(severity, "\U0001f514")


def build_generic_payload(alert: Alert) -> dict:
    """Build a generic JSON webhook payload for an alert."""
    return {
        "event": "alert.created",
        "source": "argus",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert": {
            "id": str(alert.id),
            "title": alert.title,
            "summary": alert.summary,
            "category": alert.category,
            "severity": alert.severity,
            "status": alert.status,
            "confidence": alert.confidence,
            "organization_id": str(alert.organization_id),
            "recommended_actions": alert.recommended_actions,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        },
    }


def build_slack_payload(alert: Alert) -> dict:
    """Build a Slack Block Kit webhook payload for an alert."""
    emoji = _severity_emoji(alert.severity)
    color = _severity_color(alert.severity)
    severity_display = alert.severity.capitalize() if alert.severity else "Unknown"
    category_display = (alert.category or "unknown").replace("_", " ").title()

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} {severity_display} Alert \u2014 Argus",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Category*\n{category_display}"},
                {"type": "mrkdwn", "text": f"*Severity*\n{severity_display}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{alert.title}*\n{alert.summary[:2000]}",
            },
        },
    ]

    # Add confidence score
    confidence_pct = round(alert.confidence * 100, 1) if alert.confidence else 0
    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": f"Confidence: {confidence_pct}% | Alert ID: `{alert.id}`",
            },
        ],
    })

    # Add recommended actions if present
    if alert.recommended_actions:
        actions_text = "\n".join(f"\u2022 {a}" for a in alert.recommended_actions[:5])
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Recommended Actions*\n{actions_text}",
            },
        })

    # Action button
    blocks.append({
        "type": "actions",
        "elements": [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "View in Argus"},
                "url": f"https://argus.local/alerts/{alert.id}",
                "style": "primary",
            },
        ],
    })

    return {
        "blocks": blocks,
        "attachments": [{"color": color, "blocks": []}],
    }


def build_payload(alert: Alert, endpoint: WebhookEndpoint) -> dict:
    """Build the appropriate payload based on endpoint type."""
    if endpoint.endpoint_type == "slack":
        return build_slack_payload(alert)
    return build_generic_payload(alert)


async def _send_http(
    url: str,
    payload: dict,
    secret: str | None,
    custom_headers: dict | None,
) -> tuple[bool, int | None, str | None]:
    """POST a JSON payload to a URL. Returns (success, status_code, response_body)."""
    payload_bytes = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}

    if secret:
        headers["X-Argus-Signature"] = _sign_payload(payload_bytes, secret)

    if custom_headers:
        headers.update(custom_headers)

    timeout = aiohttp.ClientTimeout(total=30)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, data=payload_bytes, headers=headers) as resp:
                body = await resp.text(errors="replace")
                success = 200 <= resp.status < 300
                return success, resp.status, body[:2000]
    except Exception as exc:
        return False, None, str(exc)


async def dispatch_alert(alert: Alert, db: AsyncSession) -> list[WebhookDelivery]:
    """
    Find all matching webhook endpoints and deliver the alert.
    Returns a list of WebhookDelivery records created.
    """
    # Get all enabled endpoints
    query = select(WebhookEndpoint).where(WebhookEndpoint.enabled == True)
    result = await db.execute(query)
    endpoints = result.scalars().all()

    deliveries = []
    now = datetime.now(timezone.utc)

    for endpoint in endpoints:
        # Check org match: endpoint with org_id only gets alerts for that org
        if endpoint.organization_id and endpoint.organization_id != alert.organization_id:
            continue

        # Check severity threshold
        if not _severity_meets_threshold(alert.severity, endpoint.min_severity):
            continue

        # Build payload
        payload = build_payload(alert, endpoint)

        # Attempt delivery
        success, status_code, response_body = await _send_http(
            endpoint.url,
            payload,
            endpoint.secret,
            endpoint.headers,
        )

        # Create delivery record
        delivery = WebhookDelivery(
            endpoint_id=endpoint.id,
            alert_id=alert.id,
            payload=payload,
            status_code=status_code,
            response_body=response_body,
            attempt_count=1,
        )

        if success:
            delivery.status = WebhookDeliveryStatus.DELIVERED.value
            delivery.delivered_at = now
            delivery.next_retry_at = None
            endpoint.last_delivery_at = now
            endpoint.failure_count = max(0, endpoint.failure_count - 1)
        else:
            delivery.status = WebhookDeliveryStatus.RETRYING.value
            delivery.next_retry_at = now + timedelta(minutes=RETRY_BACKOFF.get(1, 1))
            endpoint.failure_count += 1

        db.add(delivery)
        deliveries.append(delivery)

    await db.flush()
    return deliveries


async def dispatch_health_alert(
    source: CrawlerSource,
    db: AsyncSession,
    reason: str | None = None,
) -> None:
    """Dispatch a health-degraded system alert for a crawler source to all enabled webhooks.

    Unlike ``dispatch_alert``, this bypasses severity filtering because health
    alerts are infrastructure-level events that every integration should receive.
    """
    now = datetime.now(timezone.utc)

    payload = {
        "event": "source.health_degraded",
        "source": "argus",
        "timestamp": now.isoformat(),
        "crawler_source": {
            "id": str(source.id),
            "name": source.name,
            "url": source.url,
            "source_type": source.source_type,
            "health_status": source.health_status,
            "consecutive_failures": source.consecutive_failures,
            "last_success_at": (
                source.last_success_at.isoformat() if source.last_success_at else None
            ),
            "last_structure_hash": source.last_structure_hash,
        },
        "reason": reason or "Health status degraded",
    }

    # Query ALL enabled endpoints — no severity filter for system alerts
    query = select(WebhookEndpoint).where(WebhookEndpoint.enabled == True)  # noqa: E712
    result = await db.execute(query)
    endpoints = result.scalars().all()

    if not endpoints:
        logger_wh.info(
            "No enabled webhook endpoints — skipping health alert for source %s",
            source.name,
        )
        return

    for endpoint in endpoints:
        success, status_code, response_body = await _send_http(
            endpoint.url,
            payload,
            endpoint.secret,
            endpoint.headers,
        )

        delivery = WebhookDelivery(
            endpoint_id=endpoint.id,
            alert_id=None,
            payload=payload,
            status_code=status_code,
            response_body=response_body,
            attempt_count=1,
        )

        if success:
            delivery.status = WebhookDeliveryStatus.DELIVERED.value
            delivery.delivered_at = now
            delivery.next_retry_at = None
            endpoint.last_delivery_at = now
            endpoint.failure_count = max(0, endpoint.failure_count - 1)
            logger_wh.info(
                "Health alert delivered to %s (%s) for source %s",
                endpoint.name,
                endpoint.url,
                source.name,
            )
        else:
            delivery.status = WebhookDeliveryStatus.RETRYING.value
            delivery.next_retry_at = now + timedelta(minutes=RETRY_BACKOFF.get(1, 1))
            endpoint.failure_count += 1
            logger_wh.warning(
                "Health alert delivery FAILED to %s (%s) for source %s — status=%s",
                endpoint.name,
                endpoint.url,
                source.name,
                status_code,
            )

        db.add(delivery)

    await db.flush()


async def process_retries(db: AsyncSession) -> list[WebhookDelivery]:
    """
    Process pending retries: find deliveries with next_retry_at <= now and retry them.
    Called by the scheduler.
    """
    now = datetime.now(timezone.utc)
    query = (
        select(WebhookDelivery)
        .where(
            WebhookDelivery.status == WebhookDeliveryStatus.RETRYING.value,
            WebhookDelivery.next_retry_at <= now,
            WebhookDelivery.attempt_count < MAX_RETRY_ATTEMPTS,
        )
        .limit(50)
    )
    result = await db.execute(query)
    deliveries = result.scalars().all()

    processed = []
    for delivery in deliveries:
        endpoint = await db.get(WebhookEndpoint, delivery.endpoint_id)
        if not endpoint or not endpoint.enabled:
            delivery.status = WebhookDeliveryStatus.FAILED.value
            delivery.next_retry_at = None
            processed.append(delivery)
            continue

        success, status_code, response_body = await _send_http(
            endpoint.url,
            delivery.payload,
            endpoint.secret,
            endpoint.headers,
        )

        delivery.attempt_count += 1
        delivery.status_code = status_code
        delivery.response_body = response_body

        if success:
            delivery.status = WebhookDeliveryStatus.DELIVERED.value
            delivery.delivered_at = now
            delivery.next_retry_at = None
            endpoint.last_delivery_at = now
            endpoint.failure_count = max(0, endpoint.failure_count - 1)
        elif delivery.attempt_count >= MAX_RETRY_ATTEMPTS:
            delivery.status = WebhookDeliveryStatus.FAILED.value
            delivery.next_retry_at = None
            endpoint.failure_count += 1
        else:
            backoff_minutes = RETRY_BACKOFF.get(delivery.attempt_count, 30)
            delivery.next_retry_at = now + timedelta(minutes=backoff_minutes)

        processed.append(delivery)

    await db.flush()
    return processed
