"""Notification adapters — pluggable, async, all production-grade.

Implementations
---------------
EmailAdapter      SMTP via aiosmtplib. Supports TLS/STARTTLS and plaintext.
SlackAdapter      Incoming webhook (POST application/json).
TeamsAdapter      Microsoft Teams Adaptive Card via Office 365 connector
                  webhook.
WebhookAdapter    Generic HTTP POST with optional HMAC-SHA256 signing
                  (signature header: ``X-Argus-Signature``).
PagerDutyAdapter  Events API v2 (https://events.pagerduty.com/v2/enqueue).
OpsgenieAdapter   Alerts API v2 (https://api.opsgenie.com/v2/alerts).
JasminSmsAdapter  Jasmin HTTP API — POST /send with username/password,
                  body, dlr-method and "to" recipients.

Every adapter exposes:
    async def send(event: NotificationEvent, channel: ChannelContext) -> AdapterResult

Errors are returned (never raised). The router records the result.
"""

from __future__ import annotations

import abc
import asyncio
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import aiohttp
import aiosmtplib
from email.message import EmailMessage

from src.core.http_circuit import CircuitBreakerOpenError, get_breaker
from src.core.url_safety import UnsafeUrlError, assert_safe_url


# --- DTOs ---------------------------------------------------------------


@dataclass(frozen=True)
class NotificationEvent:
    kind: str
    severity: str
    title: str
    summary: str
    organization_id: str
    dedup_key: str | None = None
    asset_criticality: str | None = None
    asset_type: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ChannelContext:
    """Decrypted snapshot of a NotificationChannel passed to adapters."""

    id: str
    name: str
    kind: str
    config: dict[str, Any]
    secret: str | None  # decrypted bearer/password/api-key/HMAC secret


@dataclass
class AdapterResult:
    success: bool
    response_status: int | None = None
    response_body: str | None = None
    error_message: str | None = None
    latency_ms: int | None = None


# --- Helpers ------------------------------------------------------------


_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=15)


def _truncate(text: str | None, n: int = 4096) -> str | None:
    if text is None:
        return None
    return text if len(text) <= n else text[: n - 3] + "..."


# Audit C13 — exponential-backoff retry on transient failures. We retry
# on any aiohttp client exception (network blips, DNS hiccups) and on
# HTTP 5xx / 429. We never retry 4xx (other than 429): a malformed
# webhook URL or auth failure is the customer's bug, retrying just adds
# log noise and delays the failure surfacing in the UI.
_RETRY_ATTEMPTS = 3
_RETRY_BASE_DELAY = 0.5  # seconds; doubles per attempt → 0.5, 1.0, 2.0


def _is_retriable_status(status: int) -> bool:
    return status == 429 or 500 <= status < 600


def _breaker_key(url: str) -> str:
    """Key breakers by destination host so one bad webhook doesn't trip
    every other channel sharing this codepath."""
    host = urlsplit(url).hostname or "unknown"
    return f"notify:{host}"


async def _post_json(
    url: str,
    body: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
) -> AdapterResult:
    import asyncio as _asyncio

    started = time.perf_counter()

    # Adversarial audit D-23 — re-validate the URL on every dispatch.
    # Slack/Teams/Webhook channel configs are operator-supplied; without
    # this gate an admin could point a notification channel at AWS IMDS
    # (169.254.169.254) and exfiltrate cloud credentials by reading
    # delivery responses.
    try:
        await _asyncio.to_thread(assert_safe_url, url, allow_http=True)
    except UnsafeUrlError as exc:
        return AdapterResult(
            success=False,
            error_message=f"blocked_unsafe_url: {exc}",
            latency_ms=int((time.perf_counter() - started) * 1000),
        )

    breaker = get_breaker(_breaker_key(url))

    try:
        async with breaker:
            last_error: str | None = None
            last_status: int | None = None
            last_body: str | None = None
            success_result: AdapterResult | None = None

            for attempt in range(_RETRY_ATTEMPTS):
                try:
                    async with aiohttp.ClientSession(timeout=_HTTP_TIMEOUT) as sess:
                        async with sess.post(url, json=body, headers=headers or {}) as resp:
                            text = await resp.text()
                            latency = int((time.perf_counter() - started) * 1000)
                            if 200 <= resp.status < 300:
                                success_result = AdapterResult(
                                    success=True,
                                    response_status=resp.status,
                                    response_body=_truncate(text),
                                    latency_ms=latency,
                                )
                                break
                            last_status = resp.status
                            last_body = text
                            last_error = f"HTTP {resp.status}"
                            if not _is_retriable_status(resp.status):
                                break
                except Exception as e:  # noqa: BLE001 — adapter never raises
                    last_error = str(e)[:500]
                if attempt < _RETRY_ATTEMPTS - 1:
                    await _asyncio.sleep(_RETRY_BASE_DELAY * (2 ** attempt))

            if success_result is not None:
                return success_result
            # Trip the breaker by raising so __aexit__ records the failure.
            raise _UpstreamFailure(last_status, last_body, last_error)
    except CircuitBreakerOpenError as e:
        return AdapterResult(
            success=False,
            error_message=str(e),
            latency_ms=int((time.perf_counter() - started) * 1000),
        )
    except _UpstreamFailure as f:
        return AdapterResult(
            success=False,
            response_status=f.status,
            response_body=_truncate(f.body),
            error_message=f.error,
            latency_ms=int((time.perf_counter() - started) * 1000),
        )


class _UpstreamFailure(Exception):
    """Sentinel used inside ``_post_json`` to signal the breaker that
    every retry exhausted without a 2xx. Carries the last response so
    the outer handler can render the original error_message."""

    def __init__(self, status: int | None, body: str | None, error: str | None):
        self.status = status
        self.body = body
        self.error = error


# --- Base ---------------------------------------------------------------


class Adapter(abc.ABC):
    kind: str

    @abc.abstractmethod
    async def send(
        self, event: NotificationEvent, channel: ChannelContext
    ) -> AdapterResult: ...


# --- Email --------------------------------------------------------------


class EmailAdapter(Adapter):
    kind = "email"

    async def send(self, event, channel) -> AdapterResult:
        cfg = channel.config or {}
        host = cfg.get("smtp_host", "localhost")
        port = int(cfg.get("smtp_port", 25))
        use_tls = bool(cfg.get("use_tls", False))
        start_tls = bool(cfg.get("start_tls", False))
        sender = cfg.get("from_address") or "argus@localhost"
        recipients = cfg.get("recipients") or []
        username = cfg.get("username")
        password = channel.secret  # Always decrypted by router

        if not recipients:
            return AdapterResult(
                success=False,
                error_message="No recipients configured",
            )

        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = f"[Argus][{event.severity.upper()}] {event.title}"
        msg.set_content(_email_body(event))
        msg.add_alternative(_email_html(event), subtype="html")

        started = time.perf_counter()
        try:
            await aiosmtplib.send(
                msg,
                hostname=host,
                port=port,
                username=username,
                password=password if username else None,
                use_tls=use_tls,
                start_tls=start_tls,
                timeout=15,
            )
            return AdapterResult(
                success=True,
                response_status=250,
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        except Exception as e:  # noqa: BLE001
            return AdapterResult(
                success=False,
                error_message=str(e)[:500],
                latency_ms=int((time.perf_counter() - started) * 1000),
            )


def _email_body(e: NotificationEvent) -> str:
    lines = [
        f"Severity : {e.severity.upper()}",
        f"Kind     : {e.kind}",
        f"Title    : {e.title}",
        "",
        e.summary,
    ]
    if e.tags:
        lines.append("")
        lines.append("Tags: " + ", ".join(e.tags))
    if e.extra:
        lines.append("")
        lines.append("Details:")
        lines.append(json.dumps(e.extra, indent=2, default=str))
    return "\n".join(lines)


def _email_html(e: NotificationEvent) -> str:
    color = {"critical": "#B71D18", "high": "#FF5630", "medium": "#FFAB00", "low": "#22C55E", "info": "#637381"}.get(
        e.severity, "#637381"
    )
    return (
        f'<div style="font-family:Inter,Arial,sans-serif">'
        f'<h2 style="margin:0 0 8px;color:{color}">[{e.severity.upper()}] {e.title}</h2>'
        f'<p style="color:#454F5B;white-space:pre-wrap">{e.summary}</p>'
        f'<p style="color:#919EAB;font-size:12px">kind: {e.kind} · org: {e.organization_id}</p>'
        f'</div>'
    )


# --- Slack --------------------------------------------------------------


class SlackAdapter(Adapter):
    kind = "slack"

    async def send(self, event, channel) -> AdapterResult:
        url = channel.secret or channel.config.get("webhook_url")
        if not url:
            return AdapterResult(success=False, error_message="webhook_url missing")
        body = {
            "text": f"*[{event.severity.upper()}]* {event.title}",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": event.title[:150]},
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": event.summary[:2900]},
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"*severity:* `{event.severity}`"},
                        {"type": "mrkdwn", "text": f"*kind:* `{event.kind}`"},
                        {"type": "mrkdwn", "text": f"*org:* `{event.organization_id}`"},
                    ],
                },
            ],
        }
        return await _post_json(url, body)


# --- Teams --------------------------------------------------------------


class TeamsAdapter(Adapter):
    kind = "teams"

    async def send(self, event, channel) -> AdapterResult:
        url = channel.secret or channel.config.get("webhook_url")
        if not url:
            return AdapterResult(success=False, error_message="webhook_url missing")
        # Office365 connector "MessageCard" schema (works with both
        # legacy connectors and Power Automate webhooks).
        color = {
            "critical": "B71D18",
            "high": "FF5630",
            "medium": "FFAB00",
            "low": "22C55E",
            "info": "637381",
        }.get(event.severity, "637381")
        body = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": event.title,
            "themeColor": color,
            "title": f"[{event.severity.upper()}] {event.title}",
            "text": event.summary,
            "sections": [
                {
                    "facts": [
                        {"name": "Kind", "value": event.kind},
                        {"name": "Severity", "value": event.severity},
                        {"name": "Organization", "value": event.organization_id},
                    ]
                }
            ],
        }
        return await _post_json(url, body)


# --- Generic webhook with optional HMAC --------------------------------


class WebhookAdapter(Adapter):
    kind = "webhook"

    async def send(self, event, channel) -> AdapterResult:
        url = channel.config.get("url")
        if not url:
            return AdapterResult(success=False, error_message="url missing")

        body = {
            "kind": event.kind,
            "severity": event.severity,
            "title": event.title,
            "summary": event.summary,
            "organization_id": event.organization_id,
            "dedup_key": event.dedup_key,
            "tags": list(event.tags),
            "extra": event.extra,
        }
        headers: dict[str, str] = {"Content-Type": "application/json"}
        # Optional: HMAC sign with channel secret.
        if channel.secret:
            payload_bytes = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
            sig = hmac.new(channel.secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
            headers["X-Argus-Signature"] = f"sha256={sig}"
            headers["X-Argus-Timestamp"] = str(int(time.time()))
        # Custom headers passthrough
        for k, v in (channel.config.get("headers") or {}).items():
            if isinstance(v, str):
                headers[k] = v
        return await _post_json(url, body, headers=headers)


# --- PagerDuty Events API v2 -------------------------------------------


class PagerDutyAdapter(Adapter):
    kind = "pagerduty"
    _EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    async def send(self, event, channel) -> AdapterResult:
        routing_key = channel.secret or channel.config.get("routing_key")
        if not routing_key:
            return AdapterResult(success=False, error_message="routing_key missing")
        url = channel.config.get("events_url") or self._EVENTS_URL
        sev_map = {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "warning",
            "info": "info",
        }
        body = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": event.dedup_key,
            "payload": {
                "summary": f"[{event.severity.upper()}] {event.title}",
                "severity": sev_map.get(event.severity, "warning"),
                "source": f"argus/{event.organization_id}",
                "custom_details": {
                    "kind": event.kind,
                    "summary": event.summary,
                    "tags": list(event.tags),
                    **event.extra,
                },
            },
        }
        return await _post_json(url, body)


# --- Opsgenie Alerts API ------------------------------------------------


class OpsgenieAdapter(Adapter):
    kind = "opsgenie"
    _ALERTS_URL = "https://api.opsgenie.com/v2/alerts"

    async def send(self, event, channel) -> AdapterResult:
        api_key = channel.secret or channel.config.get("api_key")
        if not api_key:
            return AdapterResult(success=False, error_message="api_key missing")
        url = channel.config.get("alerts_url") or self._ALERTS_URL
        prio_map = {
            "critical": "P1",
            "high": "P2",
            "medium": "P3",
            "low": "P4",
            "info": "P5",
        }
        body = {
            "message": event.title[:130],
            "alias": event.dedup_key,
            "description": event.summary[:15000],
            "priority": prio_map.get(event.severity, "P3"),
            "tags": list(event.tags),
            "details": {
                "kind": event.kind,
                "organization_id": event.organization_id,
                **{k: str(v) for k, v in event.extra.items()},
            },
            "source": f"argus/{event.organization_id}",
        }
        if responders := channel.config.get("responders"):
            body["responders"] = responders
        headers = {"Authorization": f"GenieKey {api_key}"}
        return await _post_json(url, body, headers=headers)


# --- Jasmin SMS Gateway -------------------------------------------------


class JasminSmsAdapter(Adapter):
    """Sends SMS via a self-hosted Jasmin SMS Gateway HTTP API.

    Config:
        endpoint    base URL, e.g. http://jasmin:1401
        username    Jasmin user
        recipients  list of E.164 phone numbers
        coding      0 (default) for GSM 7-bit; 8 for binary
    Secret:
        password    Jasmin user password

    Each recipient produces an independent HTTP call. Result aggregates
    into a single AdapterResult (success only if ALL succeeded).
    """

    kind = "jasmin_sms"

    async def send(self, event, channel) -> AdapterResult:
        cfg = channel.config or {}
        endpoint = (cfg.get("endpoint") or "").rstrip("/")
        username = cfg.get("username")
        password = channel.secret
        recipients = cfg.get("recipients") or []
        coding = int(cfg.get("coding", 0))

        if not endpoint or not username or password is None or not recipients:
            return AdapterResult(
                success=False,
                error_message="jasmin_sms requires endpoint, username, password, recipients",
            )

        # SMS body — short, severity + title only (160-char limit awareness).
        body_text = f"[Argus][{event.severity.upper()}] {event.title}"[:160]

        started = time.perf_counter()
        results: list[tuple[int, str]] = []

        async with aiohttp.ClientSession(timeout=_HTTP_TIMEOUT) as sess:
            for to in recipients:
                params = {
                    "username": username,
                    "password": password,
                    "to": to,
                    "content": body_text,
                    "coding": coding,
                    "dlr": "no",
                }
                try:
                    async with sess.get(f"{endpoint}/send", params=params) as resp:
                        text = await resp.text()
                        results.append((resp.status, text))
                except Exception as e:  # noqa: BLE001
                    results.append((0, str(e)[:200]))

        latency = int((time.perf_counter() - started) * 1000)
        # Jasmin returns "Success ..." on accepted send.
        all_ok = all(
            200 <= status < 300 and text.lower().startswith("success")
            for status, text in results
        )
        last_status = results[-1][0] if results else None
        last_text = "; ".join(f"{s}:{t[:80]}" for s, t in results)
        return AdapterResult(
            success=all_ok,
            response_status=last_status,
            response_body=_truncate(last_text),
            latency_ms=latency,
            error_message=None if all_ok else "One or more recipients failed",
        )


# --- Registry -----------------------------------------------------------


class AppriseAdapter(Adapter):
    """OSS-default fan-out via the Apprise library.

    One channel kind that talks to 90+ services (Slack, Mattermost,
    Rocket.Chat, ntfy, Telegram, Discord, Teams, PagerDuty, Opsgenie,
    SMTP, Twilio, etc.) by URL scheme. Operators set
    ``config.urls = ["mattermost://...","ntfy://...","slack://..."]``
    and Apprise routes each event accordingly. Replaces the need to
    individually configure five adapters when one self-hostable OSS
    fan-out covers them all."""

    kind = "apprise"

    async def send(self, event, channel) -> AdapterResult:
        cfg = channel.config or {}
        urls = cfg.get("urls") or []
        if isinstance(urls, str):
            urls = [u.strip() for u in urls.split(",") if u.strip()]
        if not urls:
            return AdapterResult(
                success=False,
                error_message="No Apprise URLs configured (config.urls = [...])",
            )
        try:
            import apprise  # type: ignore
        except Exception as e:  # noqa: BLE001
            return AdapterResult(
                success=False,
                error_message=f"apprise lib not installed: {e}",
            )
        ap = apprise.Apprise()
        for u in urls:
            ap.add(str(u))
        title = f"[Argus][{(event.severity or 'info').upper()}] {event.title}"
        body = event.body or event.title
        try:
            ok = ap.notify(title=title, body=body)
        except Exception as e:  # noqa: BLE001
            return AdapterResult(success=False, error_message=str(e))
        if ok:
            return AdapterResult(
                success=True,
                response_status=200,
                response_body=f"delivered to {len(urls)} url(s)",
            )
        return AdapterResult(
            success=False,
            error_message=(
                f"Apprise reported failure across {len(urls)} URL(s); "
                "check service-side webhooks / ports / credentials"
            ),
        )


_REGISTRY: dict[str, Adapter] = {
    "email": EmailAdapter(),
    "slack": SlackAdapter(),
    "teams": TeamsAdapter(),
    "webhook": WebhookAdapter(),
    "pagerduty": PagerDutyAdapter(),
    "opsgenie": OpsgenieAdapter(),
    "jasmin_sms": JasminSmsAdapter(),
    "apprise": AppriseAdapter(),
}


def get_adapter(kind: str) -> Adapter:
    if kind not in _REGISTRY:
        raise ValueError(f"Unknown notification adapter kind: {kind!r}")
    return _REGISTRY[kind]


def supported_kinds() -> list[str]:
    return sorted(_REGISTRY.keys())


__all__ = [
    "Adapter",
    "AdapterResult",
    "ChannelContext",
    "NotificationEvent",
    "EmailAdapter",
    "SlackAdapter",
    "TeamsAdapter",
    "WebhookAdapter",
    "PagerDutyAdapter",
    "OpsgenieAdapter",
    "JasminSmsAdapter",
    "get_adapter",
    "supported_kinds",
]
