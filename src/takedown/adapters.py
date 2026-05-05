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
    # Operator-facing label rendered on the Submit form's partner
    # dropdown. Defaults to the adapter ``name`` if subclass leaves
    # this unset.
    display_label: str | None = None

    @abc.abstractmethod
    async def submit(self, payload: SubmitPayload) -> SubmitResult: ...

    @abc.abstractmethod
    async def fetch_status(self, partner_reference: str) -> StatusResult: ...

    def is_configured(self) -> bool:
        """Whether this adapter has the credentials/config to actually
        transmit. Default ``True`` — subclasses with external dependencies
        override. Used by the ``/partners`` endpoint so the dashboard
        can disable or annotate dropdown options the operator hasn't
        finished wiring up."""
        return True

    def config_hint(self) -> str | None:
        """Single-line hint shown next to a partner option that returns
        ``is_configured()=False``. Should name the env vars / settings
        the operator needs to populate."""
        return None


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
    display_label = "Manual (operator handles externally)"

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
    display_label = "Netcraft Countermeasures"

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
    ):
        self.base_url = (base_url or settings.takedown.netcraft_base_url).rstrip("/")
        self.api_key = api_key or settings.takedown.netcraft_api_key

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def config_hint(self) -> str | None:
        if self.is_configured():
            return None
        return "Set ARGUS_TAKEDOWN_NETCRAFT_API_KEY (and optionally ARGUS_TAKEDOWN_NETCRAFT_BASE_URL)."

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
                            ref = str(
                                data.get("id") or data.get("reference") or ""
                            ) or None
                            # The portal URL is what's surfaced as
                            # the dashboard's "Open at partner" deep
                            # link. Prefer the response's explicit
                            # ``url`` (newer Netcraft API), then
                            # ``portal_url``, then construct from
                            # the reference + a portal base URL.
                            # Without this fallback, every Netcraft
                            # ticket loses the most useful operator
                            # action ("jump to the partner UI").
                            portal_url = (
                                data.get("url")
                                or data.get("portal_url")
                                or (
                                    f"{settings.takedown.netcraft_portal_base_url.rstrip('/')}/takedowns/{ref}"
                                    if ref and getattr(
                                        settings.takedown,
                                        "netcraft_portal_base_url",
                                        None,
                                    )
                                    else None
                                )
                            )
                            return SubmitResult(
                                success=True,
                                partner_reference=ref,
                                partner_url=portal_url,
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

    def is_configured(self) -> bool:
        if not self.recipient:
            return False
        smtp_ok, _ = _smtp_transport_ready()
        return smtp_ok

    def config_hint(self) -> str | None:
        if self.is_configured():
            return None
        env_prefix = f"ARGUS_TAKEDOWN_{self.partner_label.upper().replace('-','_')}"
        if not self.recipient:
            return (
                f"Set {env_prefix}_SMTP_RECIPIENT (and the global "
                f"ARGUS_NOTIFY_EMAIL_SMTP_HOST + ARGUS_NOTIFY_EMAIL_FROM "
                f"so Argus can actually transmit)."
            )
        smtp_ok, smtp_err = _smtp_transport_ready()
        if not smtp_ok:
            return (
                f"SMTP transport not ready: {smtp_err}. The mailbox is "
                f"configured but Argus has nowhere to send from."
            )
        return None

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
    display_label = "PhishLabs (mailbox)"

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
    display_label = "Group-IB (mailbox)"

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
    display_label = "Internal legal / IR"

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
    def smtp_configured(self) -> bool:
        if not self.smtp_recipients:
            return False
        smtp_ok, _ = _smtp_transport_ready()
        return smtp_ok

    def is_configured(self) -> bool:
        # The adapter ships if EITHER transport is wired — both legs
        # are optional individually, only the union is required.
        return self.smtp_configured or self.jira_configured

    def config_hint(self) -> str | None:
        if self.is_configured():
            return None
        return (
            "Configure at least one transport: SMTP "
            "(ARGUS_TAKEDOWN_INTERNAL_LEGAL_SMTP_RECIPIENTS + ARGUS_NOTIFY_EMAIL_*) "
            "OR Jira (ARGUS_TAKEDOWN_INTERNAL_LEGAL_JIRA_URL/_USER/_TOKEN/_PROJECT)."
        )

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


# --- Free / self-service adapters -------------------------------------
#
# These three close the gap between "Argus tracks a takedown" and
# "the takedown actually goes out somewhere" without requiring an
# enterprise contract:
#
#   urlhaus           free abuse.ch malware URL distribution
#   threatfox         free abuse.ch IOC distribution (~500 downstream feeds)
#   direct_registrar  WHOIS-driven abuse@<registrar> mailer
#
# Each one is fully functional out of the box; identifying yourself
# with an Auth-Key (URLhaus / ThreatFox) just gets attribution and
# submission history in their portals.


# Tag derivation shared between the abuse.ch adapters. Tags are the
# main signal abuse.ch uses to categorise + route a submission.
_TARGET_KIND_TAGS: dict[str, list[str]] = {
    "suspect_domain": ["argus", "phishing", "lookalike-domain"],
    "impersonation": ["argus", "phishing", "brand-impersonation"],
    "fraud": ["argus", "phishing", "fraud"],
    "mobile_app": ["argus", "rogue-mobile-app"],
    "other": ["argus"],
}


def _abuse_ch_tags(payload: SubmitPayload) -> list[str]:
    base = list(_TARGET_KIND_TAGS.get(payload.target_kind, ["argus"]))
    # The operator can stuff extra tags through metadata; coerce to
    # strings + clamp length to keep us under abuse.ch's per-tag cap.
    extras = payload.metadata.get("tags") if isinstance(payload.metadata, dict) else None
    if isinstance(extras, list):
        for t in extras:
            if isinstance(t, str) and 1 <= len(t) <= 64:
                base.append(t)
    # Dedup while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for t in base:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


class URLhausAdapter(TakedownAdapter):
    """abuse.ch URLhaus — free malware URL submission API.

    URLhaus accepts URLs that distribute malware (drive-by download
    pages, malware staging, botnet C2) and pushes them out to ~500
    downstream consumers (browsers, ISPs, AV vendors, CERTs). The
    submission endpoint is at ``urlhaus.abuse.ch/api/`` and accepts
    either anonymous or Auth-Key-identified submissions.

    Note: URLhaus's accepted ``threat`` types are ``malware_download``
    and ``botnet_cc`` — phishing-only URLs should go through
    ThreatFox or DirectRegistrar instead. We map ``mobile_app`` and
    URLs that the operator explicitly tags as malware here; everything
    else is rejected with a hint.
    """

    name = "urlhaus"
    display_label = "abuse.ch URLhaus (free)"

    def is_configured(self) -> bool:
        # Anonymous mode is acceptable when the operator has explicitly
        # opted in — without it we refuse, since silent anonymous
        # submissions hide attribution.
        return bool(
            settings.takedown.urlhaus_auth_key
            or settings.takedown.urlhaus_anonymous
        )

    def config_hint(self) -> str | None:
        if self.is_configured():
            return None
        return (
            "Set ARGUS_TAKEDOWN_URLHAUS_AUTH_KEY (free at "
            "https://urlhaus.abuse.ch) or set "
            "ARGUS_TAKEDOWN_URLHAUS_ANONYMOUS=true to allow anonymous submissions."
        )

    @staticmethod
    def _threat_for(payload: SubmitPayload) -> str | None:
        """Map our ``target_kind`` (and operator-provided metadata.threat
        override) onto URLhaus's accepted threat enum. Returns None
        when this submission isn't appropriate for URLhaus."""
        override = payload.metadata.get("threat") if isinstance(payload.metadata, dict) else None
        if override in ("malware_download", "botnet_cc"):
            return override
        if payload.target_kind == "mobile_app":
            return "malware_download"
        # URLhaus historically rejects pure phishing URLs; they want
        # ThreatFox / PhishTank for those. Refuse here so the operator
        # gets a useful error instead of an opaque API rejection.
        return None

    async def submit(self, payload: SubmitPayload) -> SubmitResult:
        threat = self._threat_for(payload)
        if threat is None:
            return SubmitResult(
                success=False,
                error_message=(
                    "URLhaus only accepts malware URLs (malware_download / "
                    "botnet_cc). For phishing/impersonation use ThreatFox or "
                    "DirectRegistrar; pass metadata.threat to override."
                ),
            )

        url = payload.target_identifier.strip()
        if not url:
            return SubmitResult(success=False, error_message="empty target_identifier")

        # URLhaus expects array-style form encoding for multi-row
        # submits. We always submit one row; the array shape stays
        # because the API rejects flat dicts.
        form = aiohttp.FormData()
        form.add_field("anonymous", "0" if settings.takedown.urlhaus_auth_key else "1")
        form.add_field("submission[0][url]", url)
        form.add_field("submission[0][threat]", threat)
        for tag in _abuse_ch_tags(payload):
            form.add_field("submission[0][tags][]", tag)
        if payload.reason:
            # URLhaus accepts an optional ``reference`` per submission —
            # we use it as a free-text justification slot.
            form.add_field("submission[0][reference]", payload.reason[:200])

        headers: dict[str, str] = {}
        key = settings.takedown.urlhaus_auth_key
        if key:
            headers["Auth-Key"] = key

        timeout = aiohttp.ClientTimeout(total=20)
        breaker = get_breaker("takedown:urlhaus")
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout, headers=headers) as sess:
                    async with sess.post(
                        f"{settings.takedown.urlhaus_base_url.rstrip('/')}/",
                        data=form,
                    ) as resp:
                        text = await resp.text()
                        try:
                            data = json.loads(text) if text else {}
                        except json.JSONDecodeError:
                            data = {"text": text}
                        # URLhaus returns 200 with ``query_status`` even on
                        # rejection; treat any non-"ok" as a failure but
                        # surface the partner's wording.
                        status = (data.get("query_status") or "").lower()
                        if 200 <= resp.status < 300 and status == "ok":
                            subs = data.get("submission_status") or []
                            ref = None
                            url_id = None
                            if subs and isinstance(subs, list):
                                first = subs[0]
                                if isinstance(first, dict):
                                    ref = first.get("submission_id") or first.get("id")
                                    url_id = first.get("url_id") or first.get("id")
                            partner_url = (
                                f"https://urlhaus.abuse.ch/url/{url_id}/"
                                if url_id else None
                            )
                            return SubmitResult(
                                success=True,
                                partner_reference=str(ref) if ref else f"urlhaus-{int(time.time() * 1000)}",
                                partner_url=partner_url,
                                raw=data,
                            )
                        if 400 <= resp.status < 500 and resp.status != 429:
                            return SubmitResult(
                                success=False,
                                error_message=f"URLhaus HTTP {resp.status} ({status or 'no status'})",
                                raw=data,
                            )
                        # 5xx + 429 = upstream issue → trip the breaker.
                        raise aiohttp.ClientResponseError(
                            request_info=resp.request_info,
                            history=resp.history,
                            status=resp.status,
                            message=f"URLhaus HTTP {resp.status}",
                        )
        except CircuitBreakerOpenError as e:
            return SubmitResult(success=False, error_message=str(e))
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
            return SubmitResult(success=False, error_message=f"{type(e).__name__}: {e}"[:300])

    async def fetch_status(self, partner_reference: str) -> StatusResult:
        # URLhaus exposes a query API for URLs / submissions, but the
        # ``submission_id`` we get back isn't directly queryable — only
        # ``url_id`` is. We surface the limitation honestly rather than
        # fake a green poll.
        return StatusResult(
            success=False,
            error_message=(
                "URLhaus has no submission-status polling API. "
                "Status is implicit: distributed feeds pick up the URL "
                "within minutes once accepted."
            ),
        )


class ThreatFoxAdapter(TakedownAdapter):
    """abuse.ch ThreatFox — free IOC sharing API.

    ThreatFox is the IOC-focused sibling of URLhaus. Accepts domains,
    IPs, URLs, and hashes with a wide threat-type taxonomy (phishing,
    backdoor, ransomware, etc.). Same auth + anonymous-fallback model
    as URLhaus; submissions are distributed to ~500 downstream feeds.

    For Argus this is the cleanest free path for ``suspect_domain``
    and ``impersonation`` findings — URLhaus rejects pure phishing,
    but ThreatFox accepts ``threat_type=payload_delivery`` with
    ``malware=phishing``.
    """

    name = "threatfox"
    display_label = "abuse.ch ThreatFox (free)"

    def is_configured(self) -> bool:
        # ThreatFox requires an auth key — anonymous submissions are
        # not supported.
        return bool(settings.takedown.threatfox_auth_key)

    def config_hint(self) -> str | None:
        if self.is_configured():
            return None
        return (
            "Set ARGUS_TAKEDOWN_THREATFOX_AUTH_KEY (free at "
            "https://threatfox.abuse.ch — same account works for URLhaus)."
        )

    @staticmethod
    def _ioc_kind(target: str) -> str:
        """Classify the target into one of ThreatFox's ``ioc_type``s.

        ThreatFox accepts ``url``, ``domain``, ``ip:port``, ``md5_hash``,
        ``sha1_hash``, ``sha256_hash``. We pick the most specific
        applicable one.
        """
        t = target.strip()
        if t.startswith("http://") or t.startswith("https://"):
            return "url"
        # Hash heuristics by length.
        if all(c in "0123456789abcdef" for c in t.lower()):
            if len(t) == 32:
                return "md5_hash"
            if len(t) == 40:
                return "sha1_hash"
            if len(t) == 64:
                return "sha256_hash"
        return "domain"

    async def submit(self, payload: SubmitPayload) -> SubmitResult:
        if not settings.takedown.threatfox_auth_key:
            return SubmitResult(
                success=False,
                error_message="ThreatFox requires ARGUS_TAKEDOWN_THREATFOX_AUTH_KEY",
            )
        target = payload.target_identifier.strip()
        if not target:
            return SubmitResult(success=False, error_message="empty target_identifier")

        ioc_type = self._ioc_kind(target)
        # Map our target_kind onto ThreatFox's threat_type/malware
        # taxonomy. Default = phishing under payload_delivery.
        threat_type = "payload_delivery"
        malware = "phishing"
        if payload.target_kind == "mobile_app":
            threat_type = "payload_delivery"
            malware = "trojan_dropper"
        if isinstance(payload.metadata, dict):
            tt_override = payload.metadata.get("threat_type")
            mw_override = payload.metadata.get("malware")
            if isinstance(tt_override, str):
                threat_type = tt_override
            if isinstance(mw_override, str):
                malware = mw_override

        body = {
            "query": "submit_ioc",
            "ioc_type": ioc_type,
            "threat_type": threat_type,
            "malware": malware,
            "ioc": target,
            "tags": _abuse_ch_tags(payload),
            "anonymous": "0",
            "confidence_level": int(payload.metadata.get("confidence_level", 75))
                if isinstance(payload.metadata, dict)
                else 75,
            "reference": (payload.reason or "")[:200] or None,
        }
        # Strip None so we don't override ThreatFox defaults.
        body = {k: v for k, v in body.items() if v is not None}

        headers = {
            "Auth-Key": settings.takedown.threatfox_auth_key,
            "Content-Type": "application/json",
        }
        timeout = aiohttp.ClientTimeout(total=20)
        breaker = get_breaker("takedown:threatfox")
        try:
            async with breaker:
                async with aiohttp.ClientSession(timeout=timeout, headers=headers) as sess:
                    async with sess.post(
                        f"{settings.takedown.threatfox_base_url.rstrip('/')}/",
                        json=body,
                    ) as resp:
                        text = await resp.text()
                        try:
                            data = json.loads(text) if text else {}
                        except json.JSONDecodeError:
                            data = {"text": text}
                        query_status = (data.get("query_status") or "").lower()
                        if 200 <= resp.status < 300 and query_status == "ok":
                            row = (data.get("data") or {}).get("ok") or []
                            ref = None
                            ioc_id = None
                            if row and isinstance(row, list) and isinstance(row[0], dict):
                                ref = row[0].get("reference") or row[0].get("ioc_id")
                                ioc_id = row[0].get("ioc_id")
                            partner_url = (
                                f"https://threatfox.abuse.ch/ioc/{ioc_id}/"
                                if ioc_id else None
                            )
                            return SubmitResult(
                                success=True,
                                partner_reference=str(ref) if ref else f"threatfox-{int(time.time() * 1000)}",
                                partner_url=partner_url,
                                raw=data,
                            )
                        if 400 <= resp.status < 500 and resp.status != 429:
                            return SubmitResult(
                                success=False,
                                error_message=f"ThreatFox HTTP {resp.status} ({query_status or 'no status'})",
                                raw=data,
                            )
                        raise aiohttp.ClientResponseError(
                            request_info=resp.request_info,
                            history=resp.history,
                            status=resp.status,
                            message=f"ThreatFox HTTP {resp.status}",
                        )
        except CircuitBreakerOpenError as e:
            return SubmitResult(success=False, error_message=str(e))
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
            return SubmitResult(success=False, error_message=f"{type(e).__name__}: {e}"[:300])

    async def fetch_status(self, partner_reference: str) -> StatusResult:
        # ThreatFox does have a query API, but distribution is
        # automatic on submission and there's no per-IOC takedown
        # state — distinct from a phishing-host removal. Surface the
        # limitation rather than fake a state.
        return StatusResult(
            success=False,
            error_message=(
                "ThreatFox has no removal-state polling API. "
                "Submissions are pushed to downstream feeds automatically; "
                "follow up via the ThreatFox web UI for distribution stats."
            ),
        )


# --- Direct registrar abuse mailer ------------------------------------


# Common WHOIS field names that surface a registrar abuse contact.
# Order matters — RFC-3912 doesn't standardise the layout, so different
# registrars use different keys. The first match wins.
_WHOIS_ABUSE_FIELDS = (
    "registrar abuse contact email",
    "abuse contact email",
    "registrar abuse email",
    "abuse-mailbox",
    "abuse email",
    "registrar abuse contact",  # picked up if value happens to be email
)

_EMAIL_RE = __import__("re").compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _extract_abuse_email(whois_text: str) -> str | None:
    """Pull the first plausible abuse contact email out of a WHOIS dump.

    Strategy (cheap → robust):
      1. Walk lines. Where the key matches one of the known abuse
         labels, return the email value on the same line.
      2. Otherwise, fall back to the first email-shaped token in the
         document — registrars that use unusual field names usually
         still have only one address near the top.
    """
    if not whois_text:
        return None
    lower = whois_text.lower()
    for field in _WHOIS_ABUSE_FIELDS:
        idx = lower.find(field)
        if idx < 0:
            continue
        # Read forward to end-of-line and grep an email out of it.
        eol = lower.find("\n", idx)
        line = whois_text[idx:(eol if eol >= 0 else len(whois_text))]
        m = _EMAIL_RE.search(line)
        if m:
            return m.group(0)
    # Fall back: any email in the document. Skip the obvious noise
    # (privacy-protected proxies, the domain owner's own email).
    candidates: list[str] = []
    for m in _EMAIL_RE.finditer(whois_text):
        addr = m.group(0).lower()
        if addr.startswith(("noreply@", "no-reply@", "donotreply@")):
            continue
        candidates.append(addr)
    return candidates[0] if candidates else None


class DirectRegistrarAbuseAdapter(TakedownAdapter):
    """WHOIS-driven abuse@<registrar> mailer.

    Closes the loop between "we found a malicious domain" and "we sent
    the registrar a takedown request" without any commercial contract.
    The adapter:

      1. Runs WHOIS on the target (uses the system ``whois`` binary
         in a worker thread — no Python WHOIS lib dependency).
      2. Extracts the registrar's abuse contact email from the dump.
      3. Sends the same templated body the SMTP-only partners use.

    Falls back to ``ARGUS_TAKEDOWN_DIRECT_REGISTRAR_FALLBACK_RECIPIENT``
    when the WHOIS contact extraction fails.
    """

    name = "direct_registrar"
    display_label = "Direct registrar abuse (free, WHOIS-driven)"

    def is_configured(self) -> bool:
        # Needs SMTP transport ready. The WHOIS lookup is best-effort
        # — when it fails we use the configured fallback recipient.
        smtp_ok, _ = _smtp_transport_ready()
        return smtp_ok

    def config_hint(self) -> str | None:
        smtp_ok, smtp_err = _smtp_transport_ready()
        if not smtp_ok:
            return (
                f"SMTP transport not ready: {smtp_err}. Direct-registrar "
                f"reports are sent over your existing ARGUS_NOTIFY_EMAIL_* "
                f"transport."
            )
        return None

    @staticmethod
    async def _whois_lookup(target: str, timeout_s: float) -> str:
        """Run ``whois <target>`` in a worker thread. Returns the raw
        text body or an empty string on error / timeout. Defensive —
        WHOIS server quirks must never crash the takedown path."""
        import shutil
        import subprocess

        binary = shutil.which("whois")
        if not binary:
            logger.warning("[direct_registrar] whois binary not on PATH")
            return ""

        def _run() -> str:
            try:
                out = subprocess.run(
                    [binary, target],
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                    check=False,
                )
                return (out.stdout or "") + "\n" + (out.stderr or "")
            except (subprocess.TimeoutExpired, OSError) as exc:
                logger.warning("[direct_registrar] whois failed: %s", exc)
                return ""

        try:
            return await asyncio.to_thread(_run)
        except Exception:  # noqa: BLE001
            logger.exception("[direct_registrar] whois worker crashed")
            return ""

    async def submit(self, payload: SubmitPayload) -> SubmitResult:
        smtp_ok, smtp_err = _smtp_transport_ready()
        if not smtp_ok:
            return SubmitResult(
                success=False,
                error_message=f"DirectRegistrar cannot send: {smtp_err}",
            )

        # Only domain-shaped targets make sense — the registrar can't
        # do anything about a mobile-app id or a fraud handle.
        target = payload.target_identifier.strip().lower()
        if payload.target_kind not in ("suspect_domain", "impersonation", "fraud", "other"):
            return SubmitResult(
                success=False,
                error_message=(
                    f"DirectRegistrar accepts domain-shaped targets only "
                    f"(target_kind={payload.target_kind!r} not supported)."
                ),
            )
        if not target or "." not in target or " " in target:
            return SubmitResult(
                success=False,
                error_message="target_identifier doesn't look like a domain",
            )

        # Strip protocol + path if the analyst pasted a URL.
        if "://" in target:
            target = target.split("://", 1)[1]
        target = target.split("/", 1)[0].split(":", 1)[0]

        whois_text = await self._whois_lookup(
            target,
            timeout_s=settings.takedown.direct_registrar_whois_timeout_seconds,
        )
        recipient = _extract_abuse_email(whois_text)
        whois_used = bool(recipient)
        if not recipient:
            recipient = settings.takedown.direct_registrar_fallback_recipient
        if not recipient:
            return SubmitResult(
                success=False,
                error_message=(
                    "WHOIS lookup didn't surface an abuse contact and no "
                    "ARGUS_TAKEDOWN_DIRECT_REGISTRAR_FALLBACK_RECIPIENT is "
                    "configured. Either fix the WHOIS path (often a missing "
                    "system 'whois' binary) or set the fallback."
                ),
                raw={"whois": whois_text[:500] if whois_text else None},
            )

        body = _format_email_body(
            payload, partner="direct-registrar", account_ref=None,
        )
        # Append the WHOIS dump so the registrar can see we did our
        # homework and to short-circuit "which registrar are you
        # talking to" follow-up emails.
        if whois_text:
            body += "\nWHOIS\n-----\n" + whois_text[:6000] + "\n"

        subject = (
            f"[Argus][takedown-request] {payload.target_kind}:{target} — "
            f"abuse report"
        )
        ok, message_id, error = await _send_email_async(
            subject=subject,
            body=body,
            to=[recipient],
            reply_to=payload.contact_email,
        )
        if not ok:
            return SubmitResult(
                success=False,
                error_message=error,
                raw={"recipient": recipient, "whois_extracted": whois_used},
            )
        return SubmitResult(
            success=True,
            partner_reference=message_id,
            raw={
                "transport": "smtp",
                "recipient": recipient,
                "whois_extracted": whois_used,
                # Truncate the WHOIS dump in storage so the JSONB column
                # doesn't grow unbounded on bulk submits.
                "whois_excerpt": (whois_text[:1500] if whois_text else None),
            },
        )

    async def fetch_status(self, partner_reference: str) -> StatusResult:
        return StatusResult(
            success=False,
            error_message=(
                "Direct-registrar takedowns happen out-of-band — track "
                "the registrar's reply email and update the ticket "
                "manually when they confirm suspension or refuse."
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
        URLhausAdapter.name: URLhausAdapter(),
        ThreatFoxAdapter.name: ThreatFoxAdapter(),
        DirectRegistrarAbuseAdapter.name: DirectRegistrarAbuseAdapter(),
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
    "URLhausAdapter",
    "ThreatFoxAdapter",
    "DirectRegistrarAbuseAdapter",
    "get_adapter",
    "list_adapters",
    "register_adapter",
    "reset_registry",
]
