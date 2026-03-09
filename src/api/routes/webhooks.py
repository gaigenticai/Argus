"""Webhook / notification management endpoints."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel

from src.config.settings import settings
from src.core.notifier import send_alert_notification
from src.models.threat import Alert, AlertStatus, ThreatCategory, ThreatSeverity

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


class ChannelStatus(BaseModel):
    configured: bool
    detail: str


class WebhookConfigResponse(BaseModel):
    slack: ChannelStatus
    email: ChannelStatus
    pagerduty: ChannelStatus


class TestNotificationResponse(BaseModel):
    results: dict[str, bool]
    message: str


def _channel_config() -> WebhookConfigResponse:
    cfg = settings.notify
    return WebhookConfigResponse(
        slack=ChannelStatus(
            configured=bool(cfg.slack_webhook_url),
            detail="Webhook URL set" if cfg.slack_webhook_url else "Not configured",
        ),
        email=ChannelStatus(
            configured=bool(cfg.email_smtp_host and cfg.email_to),
            detail=(
                f"SMTP {cfg.email_smtp_host}:{cfg.email_smtp_port} -> {len(cfg.email_to)} recipient(s)"
                if cfg.email_smtp_host and cfg.email_to
                else "Not configured"
            ),
        ),
        pagerduty=ChannelStatus(
            configured=bool(cfg.pagerduty_routing_key),
            detail="Routing key set" if cfg.pagerduty_routing_key else "Not configured",
        ),
    )


@router.get("/config", response_model=WebhookConfigResponse)
async def get_webhook_config():
    """Return which notification channels are configured (no secrets exposed)."""
    return _channel_config()


@router.post("/test", response_model=TestNotificationResponse)
async def test_notification():
    """Send a test notification to all configured channels."""
    # Build a synthetic Alert object (not persisted) for the test
    test_alert = Alert()
    test_alert.id = uuid.uuid4()
    test_alert.organization_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
    test_alert.category = ThreatCategory.DATA_BREACH.value
    test_alert.severity = ThreatSeverity.HIGH.value
    test_alert.status = AlertStatus.NEW.value
    test_alert.title = "Test Alert — Argus Notification System"
    test_alert.summary = (
        "This is a test notification from Argus to verify that your "
        "notification channels are working correctly."
    )
    test_alert.confidence = 0.95
    test_alert.recommended_actions = [
        "Verify you received this notification",
        "No further action required",
    ]
    test_alert.created_at = datetime.now(timezone.utc)

    results = await send_alert_notification(test_alert)

    if not results:
        return TestNotificationResponse(
            results={},
            message="No notification channels are configured.",
        )

    succeeded = sum(1 for v in results.values() if v)
    total = len(results)
    return TestNotificationResponse(
        results=results,
        message=f"Sent to {succeeded}/{total} configured channel(s).",
    )
