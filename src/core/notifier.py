"""Notification dispatcher — Slack, Email, PagerDuty."""

import logging
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import aiohttp

from src.config.settings import settings
from src.models.threat import Alert, ThreatSeverity

logger = logging.getLogger("argus.notifier")

# Severity → hex colour for Slack attachment bars / email badges
SEVERITY_COLORS: dict[str, str] = {
    ThreatSeverity.CRITICAL.value: "#FF0000",  # red
    ThreatSeverity.HIGH.value: "#FF8C00",      # orange
    ThreatSeverity.MEDIUM.value: "#FFD600",    # yellow
    ThreatSeverity.LOW.value: "#2196F3",       # blue
    ThreatSeverity.INFO.value: "#9E9E9E",      # grey
}

# PagerDuty severity mapping (their API only accepts these four)
PD_SEVERITY_MAP: dict[str, str] = {
    ThreatSeverity.CRITICAL.value: "critical",
    ThreatSeverity.HIGH.value: "error",
    ThreatSeverity.MEDIUM.value: "warning",
    ThreatSeverity.LOW.value: "info",
    ThreatSeverity.INFO.value: "info",
}


def _severity_emoji(severity: str) -> str:
    return {
        "critical": ":red_circle:",
        "high": ":large_orange_circle:",
        "medium": ":large_yellow_circle:",
        "low": ":large_blue_circle:",
        "info": ":white_circle:",
    }.get(severity, ":grey_question:")


def _format_actions(actions: list | None) -> str:
    if not actions:
        return "_None specified_"
    return "\n".join(f"• {a}" for a in actions)


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

async def _send_slack(alert: Alert) -> bool:
    """Post a rich-formatted message to a Slack incoming webhook."""
    url = settings.notify.slack_webhook_url
    if not url:
        return False

    color = SEVERITY_COLORS.get(alert.severity, "#9E9E9E")
    emoji = _severity_emoji(alert.severity)

    payload: dict[str, Any] = {
        "text": f"{emoji} *Argus Alert* — {alert.title}",
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"Argus Alert: {alert.title}",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Severity:*\n{emoji} {alert.severity.upper()}"},
                            {"type": "mrkdwn", "text": f"*Category:*\n{alert.category}"},
                            {"type": "mrkdwn", "text": f"*Confidence:*\n{alert.confidence:.0%}"},
                            {"type": "mrkdwn", "text": f"*Status:*\n{alert.status}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Summary*\n{alert.summary}",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Recommended Actions*\n{_format_actions(alert.recommended_actions)}",
                        },
                    },
                ],
            }
        ],
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.error("Slack webhook returned %s: %s", resp.status, body)
                    return False
                logger.info("Slack notification sent for alert %s", alert.id)
                return True
    except Exception:
        logger.exception("Failed to send Slack notification")
        return False


# ---------------------------------------------------------------------------
# Email (aiosmtplib)
# ---------------------------------------------------------------------------

def _build_email_html(alert: Alert) -> str:
    color = SEVERITY_COLORS.get(alert.severity, "#9E9E9E")
    actions_html = "".join(f"<li>{a}</li>" for a in (alert.recommended_actions or []))
    if not actions_html:
        actions_html = "<li><em>None specified</em></li>"

    return f"""\
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1a1a1a; max-width: 640px; margin: 0 auto;">
  <div style="border-left: 6px solid {color}; padding: 16px 20px; background: #fafafa; border-radius: 4px;">
    <h2 style="margin: 0 0 8px;">Argus Alert</h2>
    <h3 style="margin: 0 0 16px; color: #333;">{alert.title}</h3>
    <table style="border-collapse: collapse; width: 100%; margin-bottom: 16px;">
      <tr>
        <td style="padding: 6px 12px; font-weight: 600;">Severity</td>
        <td style="padding: 6px 12px;">
          <span style="background: {color}; color: #fff; padding: 2px 10px; border-radius: 12px; font-size: 13px;">
            {alert.severity.upper()}
          </span>
        </td>
      </tr>
      <tr>
        <td style="padding: 6px 12px; font-weight: 600;">Category</td>
        <td style="padding: 6px 12px;">{alert.category}</td>
      </tr>
      <tr>
        <td style="padding: 6px 12px; font-weight: 600;">Confidence</td>
        <td style="padding: 6px 12px;">{alert.confidence:.0%}</td>
      </tr>
      <tr>
        <td style="padding: 6px 12px; font-weight: 600;">Status</td>
        <td style="padding: 6px 12px;">{alert.status}</td>
      </tr>
    </table>
    <h4 style="margin: 0 0 4px;">Summary</h4>
    <p style="margin: 0 0 16px;">{alert.summary}</p>
    <h4 style="margin: 0 0 4px;">Recommended Actions</h4>
    <ul style="margin: 0; padding-left: 20px;">{actions_html}</ul>
  </div>
  <p style="color: #999; font-size: 12px; margin-top: 16px;">Sent by Argus Threat Intelligence Platform</p>
</body>
</html>"""


async def _send_email(alert: Alert) -> bool:
    """Send an HTML email via SMTP using aiosmtplib."""
    cfg = settings.notify
    if not cfg.email_smtp_host or not cfg.email_to:
        return False

    try:
        import aiosmtplib
    except ImportError:
        logger.error("aiosmtplib is not installed — cannot send email notifications")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[Argus][{alert.severity.upper()}] {alert.title}"
    msg["From"] = cfg.email_from
    msg["To"] = ", ".join(cfg.email_to)
    msg.attach(MIMEText(_build_email_html(alert), "html"))

    try:
        await aiosmtplib.send(
            msg,
            hostname=cfg.email_smtp_host,
            port=cfg.email_smtp_port,
            username=cfg.email_smtp_user or None,
            password=cfg.email_smtp_password or None,
            start_tls=True,
            timeout=15,
        )
        logger.info("Email notification sent for alert %s", alert.id)
        return True
    except Exception:
        logger.exception("Failed to send email notification")
        return False


# ---------------------------------------------------------------------------
# PagerDuty (Events API v2)
# ---------------------------------------------------------------------------

async def _send_pagerduty(alert: Alert) -> bool:
    """Trigger an incident via PagerDuty Events API v2."""
    routing_key = settings.notify.pagerduty_routing_key
    if not routing_key:
        return False

    pd_severity = PD_SEVERITY_MAP.get(alert.severity, "info")

    payload: dict[str, Any] = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": str(alert.id),
        "payload": {
            "summary": f"[{alert.severity.upper()}] {alert.title}",
            "source": "argus",
            "severity": pd_severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": alert.category,
            "custom_details": {
                "summary": alert.summary,
                "confidence": alert.confidence,
                "category": alert.category,
                "recommended_actions": alert.recommended_actions,
            },
        },
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status not in (200, 202):
                    body = await resp.text()
                    logger.error("PagerDuty returned %s: %s", resp.status, body)
                    return False
                logger.info("PagerDuty event triggered for alert %s", alert.id)
                return True
    except Exception:
        logger.exception("Failed to send PagerDuty notification")
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def send_alert_notification(alert: Alert) -> dict[str, bool]:
    """Dispatch an alert to all configured notification channels.

    Returns a dict mapping channel name → success boolean.
    Channels that aren't configured are omitted from the result.
    """
    results: dict[str, bool] = {}

    if settings.notify.slack_webhook_url:
        results["slack"] = await _send_slack(alert)

    if settings.notify.email_smtp_host and settings.notify.email_to:
        results["email"] = await _send_email(alert)

    if settings.notify.pagerduty_routing_key:
        results["pagerduty"] = await _send_pagerduty(alert)

    if not results:
        logger.warning("No notification channels configured — alert %s was not dispatched", alert.id)

    return results
