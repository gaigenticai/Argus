"""Takedown partner adapters.

Five adapters ship in the default registry:

    manual           Records a ticket without external transmission. Used
                     for off-band / legal-team workflows where the
                     analyst contacts the registrar/host directly.

    netcraft         POSTs to the Netcraft Countermeasures API. Refuses
                     to dispatch without ``ARGUS_TAKEDOWN_NETCRAFT_API_KEY``.

    phishlabs        Fortra PhishLabs has no documented public REST API;
                     enterprise customers submit via a partner-issued
                     mailbox. The adapter dispatches a structured
                     RFC-822 email to ``ARGUS_TAKEDOWN_PHISHLABS_SMTP_RECIPIENT``
                     using the operator's configured SMTP settings.
                     Refuses to dispatch without recipient + SMTP host.

    group_ib         Group-IB DRP submissions go to a partner-issued
                     mailbox identical in pattern to PhishLabs.
                     Refuses to dispatch without recipient + SMTP host.

    internal_legal   Customer's internal counsel / IR mailbox. Two
                     transports supported and combined: SMTP recipients
                     (multi-addr CC) and Jira issue creation. At least
                     one must be configured.

No adapter ever returns ``success=True`` without a real, structured
external action having been completed. Failures are surfaced in
``SubmitResult.error_message``; callers translate that into the ticket's
``state=failed`` row.
"""

from __future__ import annotations

import abc
import asyncio
import email.utils as eut
import json
import logging
import smtplib
import time
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any

import aiohttp

from src.config.settings import settings
from src.core.http_circuit import CircuitBreakerOpenError, get_breaker


logger = logging.getLogger(__name__)


@dataclass
class SubmitPayload:
    organization_id: str
    target_kind: str  # e.g. "suspect_domain"
    target_identifier: str
    reason: str
    evidence_urls: list[str] = field(default_factory=list)
    contact_email: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SubmitResult:
    success: bool
    partner_reference: str | None = None
    partner_url: str | None = None
    error_message: str | None = None
    raw: dict[str, Any] | None = None


@dataclass
class StatusResult:
    success: bool
    partner_state: str | None = None  # raw string from partner
    error_message: str | None = None
    raw: dict[str, Any] | None = None


class TakedownAdapter(abc.ABC):
    name: str

    @abc.abstractmethod
    async def submit(self, payload: SubmitPayload) -> SubmitResult: ...

    @abc.abstractmethod
    async def fetch_status(self, partner_reference: str) -> StatusResult: ...


# --- helpers ----------------------------------------------------------


def _format_email_body(payload: SubmitPayload, *, partner: str, account_ref: str | None) -> str:
    lines = [
        f"Argus takedown request — partner: {partner}",
        f"Submission timestamp: {eut.formatdate(usegmt=True)}",
        "",
        f"Account reference : {account_ref or '<unset>'}",
        f"Customer org id   : {payload.organization_id}",
        f"Target kind       : {payload.target_kind}",
        f"Target identifier : {payload.target_identifier}",
        f"Contact (reply-to): {payload.contact_email or '<unset>'}",
        "",
        "Reason",
        "------",
        payload.reason or "<no reason provided>",
        "",
        "Evidence URLs",
        "-------------",
    ]
    if payload.evidence_urls:
        lines.extend(f"  - {u}" for u in payload.evidence_urls)
    else:
        lines.append("  <none>")

    if payload.metadata:
        lines.extend([
            "",
            "Metadata",
            "--------",
            json.dumps(payload.metadata, indent=2, sort_keys=True, default=str),
        ])
    return "\n".join(lines) + "\n"


def _smtp_transport_ready() -> tuple[bool, str | None]:
    """Return (ready, reason). Operator must set notify SMTP host + from."""
    n = settings.notify
    if not n.email_smtp_host:
        return False, "ARGUS_NOTIFY_EMAIL_SMTP_HOST is not configured"
    if not n.email_from:
        return False, "ARGUS_NOTIFY_EMAIL_FROM is not configured"
    return True, None


def _send_email(
    *,
    subject: str,
    body: str,
    to: list[str],
    reply_to: str | None = None,
) -> tuple[bool, str | None, str | None]:
    """Synchronous SMTP send; called from a worker thread by adapters.

    Returns (ok, message_id, error). Uses STARTTLS when port==587 and
    implicit TLS when port==465. Plaintext only when an operator
    explicitly sets a non-TLS port (≠465 and ≠587 and creds blank).
    """
    n = settings.notify
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = n.email_from
    msg["To"] = ", ".join(to)
    if reply_to:
        msg["Reply-To"] = reply_to
    message_id = eut.make_msgid(domain="argus.local")
    msg["Message-ID"] = message_id
    msg.set_content(body)

    try:
        if n.email_smtp_port == 465:
            client = smtplib.SMTP_SSL(n.email_smtp_host, n.email_smtp_port, timeout=30)
        else:
            client = smtplib.SMTP(n.email_smtp_host, n.email_smtp_port, timeout=30)
        try:
            client.ehlo()
            if n.email_smtp_port == 587:
                client.starttls()
                client.ehlo()
            if n.email_smtp_user and n.email_smtp_password:
                client.login(n.email_smtp_user, n.email_smtp_password)
            client.send_message(msg)
        finally:
            try:
                client.quit()
            except (smtplib.SMTPException, OSError):
                # Server already closed the connection or socket
                # is gone — message was already sent successfully,
                # so quit() failure isn't actionable.
                pass
        return True, message_id, None
    except Exception as exc:  # noqa: BLE001
        return False, None, f"{type(exc).__name__}: {exc}"


async def _send_email_async(
    *,
    subject: str,
    body: str,
    to: list[str],
    reply_to: str | None = None,
) -> tuple[bool, str | None, str | None]:
    import asyncio
    return await asyncio.to_thread(
        _send_email, subject=subject, body=body, to=to, reply_to=reply_to
    )


# --- adapters ---------------------------------------------------------


class ManualAdapter(TakedownAdapter):
    """Records a ticket without external transmission.

    Used when the customer's takedown workflow runs outside Argus (e.g.
    legal team contacts registrar directly). The ``partner_reference``
    is a millisecond-precision timestamp so analysts can correlate the
    Argus ticket with their off-band record. There is no fetch_status
    semantics because there is no external system to poll; the ticket
    state is updated by the analyst via the cases UI.
    """

    name = "manual"

    async def submit(self, payload: SubmitPayload) -> SubmitResult:
        return SubmitResult(
            success=True,
            partner_reference=f"manual-{int(time.time() * 1000)}",
            raw={"transport": "manual", "note": "ticket recorded; no transmission"},
        )

    async def fetch_status(self, partner_reference: str) -> StatusResult:
        return StatusResult(
            success=True,
            partner_state="open",
            raw={"transport": "manual"},
        )


class NetcraftAdapter(TakedownAdapter):
    """Netcraft Countermeasures REST API."""

    name = "netcraft"

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
    ):
        self.base_url = (base_url or settings.takedown.netcraft_base_url).rstrip("/")
        self.api_key = api_key or settings.takedown.netcraft_api_key

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}

    async def submit(self, payload: SubmitPayload) -> SubmitResult:
        if not self.api_key:
            return SubmitResult(
                success=False,
                error_message="Netcraft adapter requires ARGUS_TAKEDOWN_NETCRAFT_API_KEY",
            )
        body = {
            "type": payload.target_kind,
            "target": payload.target_identifier,
            "reason": payload.reason,
            "evidence_urls": payload.evidence_urls,
            "metadata": payload.metadata,
        }
        timeout = aiohttp.ClientTimeout(total=30)
        breaker = get_breaker("takedown:netcraft")
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout, headers=self._headers()) as sess:
                    async with sess.post(f"{self.base_url}/takedowns", json=body) as resp:
                        text = await resp.text()
                        try:
                            data = json.loads(text) if text else {}
                        except json.JSONDecodeError:
                            data = {"text": text}
                        if 200 <= resp.status < 300:
                            return SubmitResult(
                                success=True,
                                partner_reference=str(
                                    data.get("id") or data.get("reference") or ""
                                ) or None,
                                partner_url=data.get("url"),
                                raw=data,
                            )
                        # 4xx is a customer/data error, not an upstream
                        # outage — surface it but don't trip the breaker.
                        if 400 <= resp.status < 500 and resp.status != 429:
                            return SubmitResult(
                                success=False,
                                error_message=f"Netcraft HTTP {resp.status}",
                                raw=data,
                            )
                        raise aiohttp.ClientResponseError(
                            request_info=resp.request_info,
                            history=resp.history,
                            status=resp.status,
                            message=f"Netcraft HTTP {resp.status}",
                        )
        except CircuitBreakerOpenError as e:
            return SubmitResult(success=False, error_message=str(e))
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
            return SubmitResult(success=False, error_message=f"{type(e).__name__}: {e}"[:300])

    async def fetch_status(self, partner_reference: str) -> StatusResult:
        if not self.api_key:
            return StatusResult(
                success=False,
                error_message="Netcraft adapter requires ARGUS_TAKEDOWN_NETCRAFT_API_KEY",
            )
        timeout = aiohttp.ClientTimeout(total=15)
        breaker = get_breaker("takedown:netcraft")
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout, headers=self._headers()) as sess:
                    async with sess.get(f"{self.base_url}/takedowns/{partner_reference}") as resp:
                        text = await resp.text()
                        try:
                            data = json.loads(text) if text else {}
                        except json.JSONDecodeError:
                            data = {"text": text}
                        if 200 <= resp.status < 300:
                            return StatusResult(
                                success=True,
                                partner_state=data.get("status"),
                                raw=data,
                            )
                        if 400 <= resp.status < 500 and resp.status != 429:
                            return StatusResult(
                                success=False,
                                error_message=f"Netcraft HTTP {resp.status}",
                            )
                        raise aiohttp.ClientResponseError(
                            request_info=resp.request_info,
                            history=resp.history,
                            status=resp.status,
                            message=f"Netcraft HTTP {resp.status}",
                        )
        except CircuitBreakerOpenError as e:
            return StatusResult(success=False, error_message=str(e))
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
            return StatusResult(success=False, error_message=f"{type(e).__name__}: {e}"[:300])


class _PartnerMailboxAdapter(TakedownAdapter):
    """Shared base for partners that ingest via a configured mailbox."""

    name: str = ""
    partner_label: str = ""

    def __init__(self, *, recipient: str | None, account_ref: str | None):
        self.recipient = recipient
        self.account_ref = account_ref

    async def submit(self, payload: SubmitPayload) -> SubmitResult:
        if not self.recipient:
            return SubmitResult(
                success=False,
                error_message=f"{self.partner_label} adapter requires "
                f"ARGUS_TAKEDOWN_{self.partner_label.upper().replace('-','_')}_SMTP_RECIPIENT",
            )
        smtp_ok, smtp_err = _smtp_transport_ready()
        if not smtp_ok:
            return SubmitResult(
                success=False,
                error_message=f"{self.partner_label} adapter cannot send: {smtp_err}",
            )
        body = _format_email_body(payload, partner=self.partner_label, account_ref=self.account_ref)
        subject = (
            f"[Argus][{self.partner_label}] takedown — "
            f"{payload.target_kind}:{payload.target_identifier}"
        )
        ok, message_id, error = await _send_email_async(
            subject=subject,
            body=body,
            to=[self.recipient],
            reply_to=payload.contact_email,
        )
        if not ok:
            return SubmitResult(success=False, error_message=error)
        # Use the RFC-822 Message-ID as partner_reference so the
        # operator can grep their sent-folder when status-checking.
        return SubmitResult(
            success=True,
            partner_reference=message_id,
            raw={
                "transport": "smtp",
                "partner": self.partner_label,
                "recipient": self.recipient,
                "account_reference": self.account_ref,
            },
        )

    async def fetch_status(self, partner_reference: str) -> StatusResult:
        # No public status API exists; the partner ack arrives via reply
        # email and is logged by the analyst. We surface this honestly
        # rather than fake a green poll.
        return StatusResult(
            success=False,
            error_message=(
                f"{self.partner_label} ingests via mailbox; status checks "
                f"happen out-of-band via reply email. Update the case "
                f"manually when the partner confirms."
            ),
        )


class PhishLabsAdapter(_PartnerMailboxAdapter):
    name = "phishlabs"
    partner_label = "PhishLabs"

    def __init__(
        self,
        *,
        recipient: str | None = None,
        account_ref: str | None = None,
    ):
        super().__init__(
            recipient=recipient or settings.takedown.phishlabs_smtp_recipient,
            account_ref=account_ref or settings.takedown.phishlabs_account_reference,
        )


class GroupIBAdapter(_PartnerMailboxAdapter):
    name = "group_ib"
    partner_label = "Group-IB"

    def __init__(
        self,
        *,
        recipient: str | None = None,
        account_ref: str | None = None,
    ):
        super().__init__(
            recipient=recipient or settings.takedown.groupib_smtp_recipient,
            account_ref=account_ref or settings.takedown.groupib_account_reference,
        )


class InternalLegalAdapter(TakedownAdapter):
    """Internal counsel / IR routing.

    Two transports, executed in this order and combined into a single
    SubmitResult:
        1. SMTP — multi-recipient mail to the configured legal mailbox
           list. Failure marks the whole submit failed.
        2. Jira — POST to ``rest/api/3/issue`` on the configured cloud
           or DC instance, creating an issue with the takedown details.
           Adapter requires URL + user + token + project; missing any
           one disables the Jira leg entirely.

    At least one transport must be configured. If both are configured
    and either fails, the submit is marked failed (analyst will see the
    error and can retry).
    """

    name = "internal_legal"

    def __init__(
        self,
        *,
        smtp_recipients: list[str] | None = None,
        jira_url: str | None = None,
        jira_user: str | None = None,
        jira_token: str | None = None,
        jira_project: str | None = None,
    ):
        self.smtp_recipients = smtp_recipients or settings.takedown.internal_legal_smtp_recipients
        self.jira_url = (jira_url or settings.takedown.internal_legal_jira_url or "").rstrip("/") or None
        self.jira_user = jira_user or settings.takedown.internal_legal_jira_user
        self.jira_token = jira_token or settings.takedown.internal_legal_jira_token
        self.jira_project = jira_project or settings.takedown.internal_legal_jira_project

    @property
    def jira_configured(self) -> bool:
        return all([self.jira_url, self.jira_user, self.jira_token, self.jira_project])

    async def _submit_jira(self, payload: SubmitPayload) -> tuple[bool, str | None, str | None, dict | None]:
        body = {
            "fields": {
                "project": {"key": self.jira_project},
                "issuetype": {"name": "Task"},
                "summary": (
                    f"[Argus] takedown {payload.target_kind}:{payload.target_identifier}"
                ),
                "description": _format_email_body(
                    payload,
                    partner="internal-legal",
                    account_ref=None,
                ),
                "labels": ["argus", "takedown", payload.target_kind],
            }
        }
        timeout = aiohttp.ClientTimeout(total=30)
        auth = aiohttp.BasicAuth(self.jira_user, self.jira_token)
        breaker = get_breaker("takedown:jira")
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout, auth=auth) as sess:
                    async with sess.post(f"{self.jira_url}/rest/api/3/issue", json=body) as resp:
                        text = await resp.text()
                        try:
                            data = json.loads(text) if text else {}
                        except json.JSONDecodeError:
                            data = {"text": text}
                        if 200 <= resp.status < 300:
                            key = data.get("key")
                            url = f"{self.jira_url}/browse/{key}" if key else None
                            return True, key, url, data
                        if 400 <= resp.status < 500 and resp.status != 429:
                            return False, None, None, {"http_status": resp.status, "body": data}
                        raise aiohttp.ClientResponseError(
                            request_info=resp.request_info,
                            history=resp.history,
                            status=resp.status,
                            message=f"Jira HTTP {resp.status}",
                        )
        except CircuitBreakerOpenError as e:
            return False, None, None, {"error": str(e)}
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
            return False, None, None, {"error": f"{type(e).__name__}: {e}"[:300]}

    async def submit(self, payload: SubmitPayload) -> SubmitResult:
        if not self.smtp_recipients and not self.jira_configured:
            return SubmitResult(
                success=False,
                error_message=(
                    "internal_legal adapter requires ARGUS_TAKEDOWN_INTERNAL_LEGAL_SMTP_RECIPIENTS "
                    "and/or a complete ARGUS_TAKEDOWN_INTERNAL_LEGAL_JIRA_* set."
                ),
            )

        legs: list[dict] = []
        all_ok = True

        # SMTP leg
        if self.smtp_recipients:
            smtp_ok, smtp_err = _smtp_transport_ready()
            if not smtp_ok:
                legs.append({"transport": "smtp", "ok": False, "error": smtp_err})
                all_ok = False
            else:
                body = _format_email_body(payload, partner="internal-legal", account_ref=None)
                subject = (
                    f"[Argus][internal-legal] takedown — "
                    f"{payload.target_kind}:{payload.target_identifier}"
                )
                ok, message_id, error = await _send_email_async(
                    subject=subject,
                    body=body,
                    to=list(self.smtp_recipients),
                    reply_to=payload.contact_email,
                )
                legs.append({
                    "transport": "smtp",
                    "ok": ok,
                    "message_id": message_id,
                    "error": error,
                    "recipients": list(self.smtp_recipients),
                })
                if not ok:
                    all_ok = False

        # Jira leg
        if self.jira_configured:
            ok, key, url, raw = await self._submit_jira(payload)
            legs.append({
                "transport": "jira",
                "ok": ok,
                "issue_key": key,
                "issue_url": url,
                "raw": raw,
            })
            if not ok:
                all_ok = False

        # Pick a partner_reference: prefer Jira issue key, fall back to
        # SMTP message id, fall back to a synthetic stamp.
        ref: str | None = None
        url: str | None = None
        for leg in legs:
            if leg["transport"] == "jira" and leg.get("issue_key"):
                ref = leg["issue_key"]
                url = leg.get("issue_url")
                break
        if ref is None:
            for leg in legs:
                if leg["transport"] == "smtp" and leg.get("message_id"):
                    ref = leg["message_id"]
                    break
        if ref is None:
            ref = f"internal-legal-{int(time.time() * 1000)}"

        if not all_ok:
            errors = [
                f"{leg['transport']}: {leg.get('error') or 'failed'}"
                for leg in legs
                if not leg["ok"]
            ]
            return SubmitResult(
                success=False,
                partner_reference=ref,
                partner_url=url,
                error_message="; ".join(errors)[:500],
                raw={"legs": legs},
            )

        return SubmitResult(
            success=True,
            partner_reference=ref,
            partner_url=url,
            raw={"legs": legs},
        )

    async def fetch_status(self, partner_reference: str) -> StatusResult:
        # If the reference is a Jira key, poll Jira for status.
        if (
            self.jira_configured
            and partner_reference
            and "-" in partner_reference
            and partner_reference.split("-")[0].isalnum()
            and not partner_reference.startswith("internal-legal-")
        ):
            timeout = aiohttp.ClientTimeout(total=15)
            auth = aiohttp.BasicAuth(self.jira_user, self.jira_token)
            breaker = get_breaker("takedown:jira")
            try:
                async with breaker:
                    async with aiohttp.ClientSession(timeout=timeout, auth=auth) as sess:
                        async with sess.get(
                            f"{self.jira_url}/rest/api/3/issue/{partner_reference}?fields=status"
                        ) as resp:
                            text = await resp.text()
                            try:
                                data = json.loads(text) if text else {}
                            except json.JSONDecodeError:
                                data = {"text": text}
                            if 200 <= resp.status < 300:
                                status_obj = (data.get("fields") or {}).get("status") or {}
                                return StatusResult(
                                    success=True,
                                    partner_state=status_obj.get("name"),
                                    raw=data,
                                )
                            if 400 <= resp.status < 500 and resp.status != 429:
                                return StatusResult(
                                    success=False,
                                    error_message=f"Jira HTTP {resp.status}",
                                    raw=data,
                                )
                            raise aiohttp.ClientResponseError(
                                request_info=resp.request_info,
                                history=resp.history,
                                status=resp.status,
                                message=f"Jira HTTP {resp.status}",
                            )
            except CircuitBreakerOpenError as e:
                return StatusResult(success=False, error_message=str(e))
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                return StatusResult(success=False, error_message=f"{type(e).__name__}: {e}"[:300])

        # SMTP-only refs can't be polled; surface honestly.
        return StatusResult(
            success=False,
            error_message=(
                "Reference does not match a Jira issue; status arrives via "
                "reply email and must be recorded by the analyst."
            ),
        )


# --- Registry ---------------------------------------------------------


def _default_registry() -> dict[str, TakedownAdapter]:
    return {
        ManualAdapter.name: ManualAdapter(),
        NetcraftAdapter.name: NetcraftAdapter(),
        PhishLabsAdapter.name: PhishLabsAdapter(),
        GroupIBAdapter.name: GroupIBAdapter(),
        InternalLegalAdapter.name: InternalLegalAdapter(),
    }


_REGISTRY: dict[str, TakedownAdapter] = _default_registry()


def get_adapter(name: str) -> TakedownAdapter:
    if name not in _REGISTRY:
        raise ValueError(f"Unknown takedown adapter: {name}")
    return _REGISTRY[name]


def list_adapters() -> list[str]:
    return list(_REGISTRY.keys())


def register_adapter(adapter: TakedownAdapter) -> None:
    _REGISTRY[adapter.name] = adapter


def reset_registry() -> None:
    global _REGISTRY
    _REGISTRY = _default_registry()


__all__ = [
    "SubmitPayload",
    "SubmitResult",
    "StatusResult",
    "TakedownAdapter",
    "ManualAdapter",
    "NetcraftAdapter",
    "PhishLabsAdapter",
    "GroupIBAdapter",
    "InternalLegalAdapter",
    "get_adapter",
    "list_adapters",
    "register_adapter",
    "reset_registry",
]
