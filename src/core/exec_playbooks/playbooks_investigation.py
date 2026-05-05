"""V1 catalogued *investigation* playbooks for Case Copilot.

Whereas :mod:`.playbooks` ships org-level response actions (takedowns,
DMARC, VIPs, typosquats), this module ships per-case investigation
probes the Case Copilot can queue against an open case:

* :py:obj:`whois_lookup` — RDAP/WHOIS for one domain.
* :py:obj:`live_probe_capture` — fetch the live page, hash + verdict.
* :py:obj:`cert_transparency_pivot` — crt.sh sibling hostnames.
* :py:obj:`submit_takedown_for_suspect` — single-domain takedown
  (partner-dispatched, **requires admin approval**).
* :py:obj:`siem_pivot` — Wazuh / SIEM lookup for traffic to/from an
  indicator. Only applicable if a SIEM connector is configured.

Every investigation playbook reads ``params["_case_id"]`` (set by the
orchestrator when the run is created from a case) and posts its
output as a ``CaseComment`` so the analyst can scroll the timeline
and see "WHOIS pulled at 14:02 → registrar X, created 2019-04-02".
The persistent state side-effect (LiveProbe row, TakedownTicket row)
also lands so other dashboards pick it up.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import aiohttp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.auth import User
from src.models.brand import SuspectDomain, SuspectDomainState
from src.models.cases import CaseComment
from src.models.live_probe import LiveProbe, LiveProbeVerdict
from src.models.takedown import (
    TakedownPartner,
    TakedownState,
    TakedownTargetKind,
    TakedownTicket,
)
from src.models.threat import Organization

from .framework import (
    AffectedItem,
    Playbook,
    PlaybookStep,
    StepPreview,
    StepResult,
    register,
)

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------------


def _resolve_case_id(params: dict[str, Any]) -> uuid.UUID | None:
    """Read the system-injected ``_case_id`` from params.

    Underscore-prefixed keys are reserved for the orchestrator;
    operator-supplied params never start with one.
    """
    raw = params.get("_case_id")
    if not raw:
        return None
    if isinstance(raw, uuid.UUID):
        return raw
    try:
        return uuid.UUID(str(raw))
    except (ValueError, TypeError):
        return None


async def _post_case_comment(
    db: AsyncSession,
    *,
    case_id: uuid.UUID | None,
    user: User,
    body: str,
) -> bool:
    """Append a markdown comment to a case timeline.

    Returns True when the comment was actually written; False when the
    playbook ran outside a case (e.g. operator manually fired it from
    /playbooks). Either way the playbook's own state result captures
    the substance.
    """
    if case_id is None:
        return False
    db.add(CaseComment(
        case_id=case_id,
        author_user_id=user.id,
        body=body,
    ))
    await db.flush()
    return True


# ======================================================================
# 1. whois_lookup
# ======================================================================


_WHOIS_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "domain": {"type": "string", "minLength": 3, "maxLength": 253},
    },
    "required": ["domain"],
}


def _format_whois(data: dict[str, Any], domain: str) -> str:
    """Render a python-whois result block as case-comment markdown."""
    def _flat(v: Any) -> str:
        if isinstance(v, list) and v:
            return str(v[0])
        if v is None:
            return "—"
        return str(v)

    nameservers = data.get("name_servers") or []
    ns_list = (
        ", ".join(sorted({(ns or "").lower() for ns in nameservers}))
        or "—"
    )
    lines = [
        f"**WHOIS / RDAP — `{domain}`**",
        "",
        f"- Registrar: `{_flat(data.get('registrar'))}`",
        f"- Created: `{_flat(data.get('creation_date'))}`",
        f"- Expires: `{_flat(data.get('expiration_date'))}`",
        f"- Name servers: `{ns_list}`",
        f"- Status: `{_flat(data.get('status'))}`",
    ]
    return "\n".join(lines)


async def _whois_preview(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
) -> StepPreview:
    domain = (params.get("domain") or "").strip().lower()
    if not domain:
        return StepPreview(
            summary="No target domain supplied.",
            can_execute=False,
            blocker_reason="Enter a domain (or run from a suspect-domain case so it pre-fills).",
        )
    return StepPreview(
        summary=f"Will look up WHOIS / RDAP for {domain}.",
        affected_items=[AffectedItem(id=domain, label=domain)],
    )


async def _whois_execute(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
    user: User,
) -> StepResult:
    domain = (params.get("domain") or "").strip().lower()
    if not domain:
        return StepResult(ok=False, summary="No domain", error="missing domain")

    try:
        import whois  # type: ignore
    except ImportError:
        return StepResult(
            ok=False,
            summary="python-whois not installed; cannot resolve.",
            error="python-whois unavailable",
        )

    try:
        data = await asyncio.to_thread(whois.whois, domain)
    except Exception as exc:  # noqa: BLE001
        return StepResult(
            ok=False, summary=f"WHOIS lookup failed for {domain}.",
            error=str(exc)[:300],
        )

    payload = dict(data) if hasattr(data, "items") else {}
    body = _format_whois(payload, domain)
    case_id = _resolve_case_id(params)
    posted = await _post_case_comment(db, case_id=case_id, user=user, body=body)
    return StepResult(
        ok=True,
        summary=(
            f"WHOIS captured for {domain}; registrar="
            f"{(payload.get('registrar') or 'unknown')}."
        ),
        items=[{
            "domain": domain,
            "registrar": payload.get("registrar"),
            "creation_date": str(payload.get("creation_date") or ""),
            "case_comment_posted": posted,
        }],
    )


whois_lookup = register(Playbook(
    id="whois_lookup",
    title="Pull WHOIS / RDAP for a domain",
    category="investigation",
    description=(
        "Queries the registrar (python-whois → RDAP fallback) for "
        "ownership, creation date, expiration, name servers and status. "
        "Result lands as a comment on the originating case."
    ),
    cta_label="Pull WHOIS →",
    requires_approval=False,
    requires_input=True,
    permission="analyst",
    input_schema=_WHOIS_INPUT_SCHEMA,
    scope="investigation",
    applicable_when=lambda snap: True,
    steps=(
        PlaybookStep(
            step_id="run_whois",
            title="Run WHOIS",
            description="Fetch and parse the registry record.",
            preview=_whois_preview,
            execute=_whois_execute,
        ),
    ),
))


# ======================================================================
# 2. live_probe_capture
# ======================================================================


_LIVE_PROBE_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "minLength": 4, "maxLength": 1024},
    },
    "required": ["url"],
}


def _normalise_url(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    if not s.startswith(("http://", "https://")):
        s = "http://" + s
    return s


async def _live_probe_preview(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
) -> StepPreview:
    url = _normalise_url(params.get("url") or "")
    if not url:
        return StepPreview(
            summary="No target URL supplied.",
            can_execute=False,
            blocker_reason="Provide a URL — typically the suspect domain root.",
        )
    return StepPreview(
        summary=f"Will fetch {url}, hash content, and persist a LiveProbe row.",
        affected_items=[AffectedItem(id=url, label=url)],
        warnings=[
            "The fetch is direct (not Tor-tunnelled). For known-malicious "
            "URLs, prefer running from a sandboxed analyst workstation.",
        ],
    )


async def _live_probe_execute(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
    user: User,
) -> StepResult:
    url = _normalise_url(params.get("url") or "")
    if not url:
        return StepResult(ok=False, summary="No URL", error="missing url")

    started = datetime.now(timezone.utc)
    http_status: int | None = None
    final_url: str | None = None
    title: str | None = None
    error: str | None = None
    content_sha256: str | None = None

    try:
        async with aiohttp.ClientSession() as http:
            async with http.get(
                url,
                timeout=aiohttp.ClientTimeout(total=15),
                allow_redirects=True,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (compatible; ArgusBot/1.0; +https://marsad.local)"
                    ),
                },
            ) as resp:
                http_status = resp.status
                final_url = str(resp.url)
                raw = await resp.read()
                import hashlib
                content_sha256 = hashlib.sha256(raw).hexdigest()
                # Extract <title> if present — useful for "Bank Login"
                # squat detection in the analyst view.
                try:
                    text = raw[:65536].decode("utf-8", errors="replace")
                    import re as _re
                    m = _re.search(
                        r"<title[^>]*>(.*?)</title>",
                        text,
                        _re.IGNORECASE | _re.DOTALL,
                    )
                    if m:
                        title = m.group(1).strip()[:500]
                except Exception:  # noqa: BLE001
                    pass
    except aiohttp.ClientError as exc:
        error = f"network: {exc}"
    except asyncio.TimeoutError:
        error = "timeout after 15s"
    except Exception as exc:  # noqa: BLE001
        error = f"unexpected: {exc}"

    # Verdict mapping against the real LiveProbeVerdict enum:
    #   - error path → UNREACHABLE
    #   - 2xx with content → UNKNOWN (we don't have a real classifier
    #     here; "live page exists, no verdict" is the honest read)
    #   - other status → UNKNOWN as well
    if error:
        verdict = LiveProbeVerdict.UNREACHABLE.value
    else:
        verdict = LiveProbeVerdict.UNKNOWN.value

    domain = url.split("://", 1)[-1].split("/", 1)[0]
    suspect_id_param = params.get("suspect_domain_id")
    suspect_uuid: uuid.UUID | None = None
    if suspect_id_param:
        try:
            suspect_uuid = uuid.UUID(str(suspect_id_param))
        except (ValueError, TypeError):
            suspect_uuid = None

    probe = LiveProbe(
        organization_id=org.id,
        domain=domain,
        url=url,
        suspect_domain_id=suspect_uuid,
        fetched_at=started,
        http_status=http_status,
        final_url=final_url,
        title=title,
        html_evidence_sha256=content_sha256,
        screenshot_evidence_sha256=None,
        verdict=verdict,
        classifier_name="playbook_live_probe_capture",
        confidence=0.5,
        signals=[],
        matched_brand_terms=[],
        rationale=(
            "Operator-triggered capture via Case Copilot playbook. "
            "No automated classifier verdict; analyst should review."
        ),
        error_message=error,
    )
    db.add(probe)
    await db.flush()

    body_md = (
        f"**Live probe — `{url}`**\n\n"
        f"- Verdict: `{verdict}`\n"
        f"- HTTP status: `{http_status if http_status is not None else 'n/a'}`\n"
        f"- Final URL: `{final_url or url}`\n"
        f"- Title: `{title or '—'}`\n"
        f"- SHA-256: `{content_sha256 or '—'}`\n"
        f"- Error: {error or '_none_'}"
    )
    case_id = _resolve_case_id(params)
    posted = await _post_case_comment(db, case_id=case_id, user=user, body=body_md)

    return StepResult(
        ok=error is None,
        summary=f"Probed {url} → {verdict} ({http_status or 'n/a'}).",
        error=error,
        items=[{
            "url": url,
            "verdict": verdict,
            "http_status": http_status,
            "content_sha256": content_sha256,
            "live_probe_id": str(probe.id),
            "case_comment_posted": posted,
        }],
    )


live_probe_capture = register(Playbook(
    id="live_probe_capture",
    title="Probe a URL and capture content fingerprint",
    category="investigation",
    description=(
        "Fetches the live URL, hashes the body, and stores a LiveProbe "
        "row tagged to the originating case + suspect domain. Verdict "
        "(live / unreachable / inconclusive) goes into the case timeline."
    ),
    cta_label="Probe URL →",
    requires_approval=False,
    requires_input=True,
    permission="analyst",
    input_schema=_LIVE_PROBE_INPUT_SCHEMA,
    scope="investigation",
    applicable_when=lambda snap: True,
    steps=(
        PlaybookStep(
            step_id="capture",
            title="Fetch and fingerprint",
            description="HTTP GET, hash, persist LiveProbe row.",
            preview=_live_probe_preview,
            execute=_live_probe_execute,
        ),
    ),
))


# ======================================================================
# 3. cert_transparency_pivot
# ======================================================================


CERT_SHEETS_URL = "https://crt.sh/?q={domain}&output=json"
CERT_SHEETS_LIMIT = 200


_CERT_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "domain": {"type": "string", "minLength": 3, "maxLength": 253},
    },
    "required": ["domain"],
}


async def _cert_pivot_preview(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
) -> StepPreview:
    domain = (params.get("domain") or "").strip().lower()
    if not domain:
        return StepPreview(
            summary="No target domain supplied.",
            can_execute=False,
            blocker_reason="Enter the suspect domain.",
        )
    return StepPreview(
        summary=(
            f"Will query crt.sh certificate-transparency logs for {domain} "
            f"and surface every sibling hostname (mail., login., webmail., etc.) "
            f"the attacker may have provisioned under the same registration."
        ),
        affected_items=[AffectedItem(id=domain, label=domain)],
    )


async def _cert_pivot_execute(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
    user: User,
) -> StepResult:
    domain = (params.get("domain") or "").strip().lower()
    if not domain:
        return StepResult(ok=False, summary="No domain", error="missing domain")

    url = CERT_SHEETS_URL.format(domain=f"%25.{domain}")
    siblings: set[str] = set()
    error: str | None = None
    try:
        async with aiohttp.ClientSession() as http:
            async with http.get(
                url,
                timeout=aiohttp.ClientTimeout(total=20),
                headers={"User-Agent": "ArgusBot/1.0"},
            ) as resp:
                if resp.status != 200:
                    error = f"crt.sh HTTP {resp.status}"
                else:
                    payload = await resp.json(content_type=None)
                    if isinstance(payload, list):
                        for entry in payload[:CERT_SHEETS_LIMIT * 5]:
                            if not isinstance(entry, dict):
                                continue
                            for raw in str(entry.get("name_value") or "").splitlines():
                                name = raw.strip().lower().lstrip("*.")
                                if name and name.endswith(domain):
                                    siblings.add(name)
                            if len(siblings) >= CERT_SHEETS_LIMIT:
                                break
    except aiohttp.ClientError as exc:
        error = f"network: {exc}"
    except asyncio.TimeoutError:
        error = "timeout"
    except Exception as exc:  # noqa: BLE001
        error = f"unexpected: {exc}"

    siblings.discard(domain)
    sibling_list = sorted(siblings)

    body_lines = [f"**Cert-transparency pivot — `{domain}`**", ""]
    if error:
        body_lines.append(f"- Error: `{error}`")
    elif not sibling_list:
        body_lines.append("- No sibling hostnames found in crt.sh.")
    else:
        body_lines.append(
            f"- Found `{len(sibling_list)}` sibling hostname(s):"
        )
        body_lines.extend(f"  - `{n}`" for n in sibling_list[:50])
        if len(sibling_list) > 50:
            body_lines.append(f"  - … {len(sibling_list) - 50} more truncated")

    case_id = _resolve_case_id(params)
    posted = await _post_case_comment(
        db, case_id=case_id, user=user, body="\n".join(body_lines),
    )

    return StepResult(
        ok=error is None,
        summary=(
            f"Cert-transparency: {len(sibling_list)} sibling hostname(s) found "
            f"for {domain}."
        ),
        error=error,
        items=[{
            "domain": domain,
            "sibling_count": len(sibling_list),
            "siblings_sample": sibling_list[:20],
            "case_comment_posted": posted,
        }],
    )


cert_transparency_pivot = register(Playbook(
    id="cert_transparency_pivot",
    title="Cert-transparency pivot for sibling hostnames",
    category="investigation",
    description=(
        "Queries crt.sh for every TLS certificate ever issued under the "
        "domain and surfaces sibling hostnames (mail., login., webmail., "
        "api., etc.) — typically the auxiliary infra an attacker stages "
        "alongside the phishing landing page."
    ),
    cta_label="Pivot via crt.sh →",
    requires_approval=False,
    requires_input=True,
    permission="analyst",
    input_schema=_CERT_INPUT_SCHEMA,
    scope="investigation",
    applicable_when=lambda snap: True,
    steps=(
        PlaybookStep(
            step_id="query_crt_sh",
            title="Query certificate-transparency logs",
            description="Hit crt.sh, dedupe, list siblings.",
            preview=_cert_pivot_preview,
            execute=_cert_pivot_execute,
        ),
    ),
))


# ======================================================================
# 4. submit_takedown_for_suspect
# ======================================================================


_SUSPECT_TAKEDOWN_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "suspect_domain_id": {"type": "string", "format": "uuid"},
    },
    "required": ["suspect_domain_id"],
}


async def _suspect_takedown_preview(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
) -> StepPreview:
    raw = params.get("suspect_domain_id")
    try:
        suspect_id = uuid.UUID(str(raw))
    except (ValueError, TypeError):
        return StepPreview(
            summary="No suspect domain selected.",
            can_execute=False,
            blocker_reason="Open this from a SuspectDomain finding so the id pre-fills.",
        )

    suspect = await db.get(SuspectDomain, suspect_id)
    if suspect is None or suspect.organization_id != org.id:
        return StepPreview(
            summary="Suspect domain not found in this org.",
            can_execute=False,
            blocker_reason="Stale suspect_domain_id — refresh the case.",
        )
    if suspect.state in (
        SuspectDomainState.DISMISSED.value,
        SuspectDomainState.CLEARED.value,
    ):
        return StepPreview(
            summary=f"{suspect.domain} was already adjudicated as {suspect.state}.",
            can_execute=False,
            blocker_reason=(
                "Don't file takedowns on dismissed/cleared suspects — "
                "either re-open the suspect first or pick a different one."
            ),
        )
    return StepPreview(
        summary=(
            f"Will file ONE takedown ticket against `{suspect.domain}` via "
            f"the Manual partner adapter."
        ),
        affected_items=[AffectedItem(
            id=str(suspect.id),
            label=suspect.domain,
            sub_label=(
                f"matched {suspect.matched_term_value!r} · "
                f"similarity {suspect.similarity:.2f} · {suspect.source}"
            ),
        )],
        warnings=[
            "Once submitted, the takedown is dispatched to the partner "
            "and cannot be auto-recalled. Make sure the suspect is "
            "confirmed phishing or you have strong indicators.",
        ],
    )


async def _suspect_takedown_execute(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
    user: User,
) -> StepResult:
    from src.takedown.adapters import SubmitPayload, get_adapter

    raw = params.get("suspect_domain_id")
    try:
        suspect_id = uuid.UUID(str(raw))
    except (ValueError, TypeError):
        return StepResult(
            ok=False, summary="Invalid suspect_domain_id.", error="bad_uuid",
        )

    suspect = await db.get(SuspectDomain, suspect_id)
    if suspect is None or suspect.organization_id != org.id:
        return StepResult(
            ok=False, summary="Suspect not in org.", error="not_found",
        )

    # Idempotent against the existing unique constraint.
    target = suspect.domain
    existing = (
        await db.execute(
            select(TakedownTicket).where(
                TakedownTicket.organization_id == org.id,
                TakedownTicket.target_kind == TakedownTargetKind.SUSPECT_DOMAIN.value,
                TakedownTicket.target_identifier == target,
                TakedownTicket.partner == TakedownPartner.MANUAL.value,
            ).limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return StepResult(
            ok=True,
            summary=(
                f"Takedown already on file for {target} "
                f"(ticket {existing.id})."
            ),
            items=[{
                "suspect_domain_id": str(suspect.id),
                "ticket_id": str(existing.id),
                "skipped": "duplicate",
            }],
        )

    # Route through the adapter so partner_reference / partner_url are
    # populated. Manual adapter generates a timestamp reference; real
    # partners (Netcraft / PhishLabs / Group-IB / Internal-Legal)
    # actually transmit. Required for the dashboard's Sync button to
    # operate later (/sync requires partner_reference != NULL).
    adapter = get_adapter(TakedownPartner.MANUAL.value)
    submit_result = await adapter.submit(
        SubmitPayload(
            organization_id=str(org.id),
            target_kind=TakedownTargetKind.SUSPECT_DOMAIN.value,
            target_identifier=target,
            reason=(
                f"Suspect domain {target} flagged as a likely phishing/"
                f"impersonation target — single-domain takedown via "
                f"Case Copilot playbook submit_takedown_for_suspect."
            ),
            evidence_urls=[],
            metadata={
                "suspect_domain_id": str(suspect.id),
                "matched_term_value": suspect.matched_term_value,
                "similarity": suspect.similarity,
                "source": suspect.source,
            },
        )
    )

    now = datetime.now(timezone.utc)
    ticket = TakedownTicket(
        organization_id=org.id,
        partner=TakedownPartner.MANUAL.value,
        state=(
            TakedownState.SUBMITTED.value
            if submit_result.success
            else TakedownState.FAILED.value
        ),
        target_kind=TakedownTargetKind.SUSPECT_DOMAIN.value,
        target_identifier=target,
        source_finding_id=suspect.id,
        partner_reference=submit_result.partner_reference,
        partner_url=submit_result.partner_url,
        submitted_by_user_id=user.id,
        submitted_at=now,
        failed_at=now if not submit_result.success else None,
        notes=(
            submit_result.error_message
            or "Single-domain takedown via playbook submit_takedown_for_suspect"
        ),
        raw=submit_result.raw,
    )
    db.add(ticket)

    if submit_result.success:
        suspect.state = SuspectDomainState.TAKEDOWN_REQUESTED.value
        suspect.state_changed_at = now
        suspect.state_changed_by_user_id = user.id
        suspect.state_reason = f"takedown filed via playbook (ticket {ticket.id})"
    await db.flush()

    body_md = (
        f"**Takedown filed — `{target}`**\n\n"
        f"- Ticket: `{ticket.id}`\n"
        f"- Partner: `manual`\n"
        f"- Partner reference: `{submit_result.partner_reference or '—'}`\n"
        f"- State: `{ticket.state}`\n"
    )
    if not submit_result.success:
        body_md += f"- Error: `{submit_result.error_message}`\n"
    else:
        body_md += "- Suspect state moved to `takedown_requested`.\n"

    case_id = _resolve_case_id(params)
    posted = await _post_case_comment(db, case_id=case_id, user=user, body=body_md)

    return StepResult(
        ok=submit_result.success,
        summary=(
            f"Filed takedown for {target} (ticket {ticket.id})."
            if submit_result.success
            else f"Takedown submit failed for {target}: {submit_result.error_message}"
        ),
        error=None if submit_result.success else submit_result.error_message,
        items=[{
            "suspect_domain_id": str(suspect.id),
            "ticket_id": str(ticket.id),
            "partner_reference": submit_result.partner_reference,
            "partner_url": submit_result.partner_url,
            "case_comment_posted": posted,
        }],
    )


submit_takedown_for_suspect = register(Playbook(
    id="submit_takedown_for_suspect",
    title="File takedown for one suspect domain",
    category="investigation",
    description=(
        "Files a single takedown ticket for the case's suspect domain via "
        "the configured partner. Marks the suspect as takedown_requested "
        "and posts a confirmation comment to the case."
    ),
    cta_label="File takedown →",
    requires_approval=True,
    requires_input=True,
    permission="analyst",
    input_schema=_SUSPECT_TAKEDOWN_INPUT_SCHEMA,
    scope="investigation",
    applicable_when=lambda snap: True,
    steps=(
        PlaybookStep(
            step_id="submit_takedown",
            title="Submit takedown",
            description="Create one TakedownTicket; flip suspect state.",
            preview=_suspect_takedown_preview,
            execute=_suspect_takedown_execute,
        ),
    ),
))


# ======================================================================
# 5. siem_pivot — Wazuh search (only when configured)
# ======================================================================


_SIEM_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "indicator": {"type": "string", "minLength": 3, "maxLength": 1024},
    },
    "required": ["indicator"],
}


def _wazuh_configured() -> bool:
    """Cheap env probe — full client init happens inside execute.

    The integration reads ``ARGUS_WAZUH_URL`` (manager URL) +
    ``ARGUS_WAZUH_API_KEY`` (``user:password`` format) — see
    ``src.core.service_inventory`` for the canonical contract. We
    don't import the client here to avoid module-load cost.
    """
    return bool(os.environ.get("ARGUS_WAZUH_URL")) and bool(
        os.environ.get("ARGUS_WAZUH_API_KEY")
    )


async def _siem_preview(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
) -> StepPreview:
    indicator = (params.get("indicator") or "").strip()
    if not indicator:
        return StepPreview(
            summary="No indicator supplied.",
            can_execute=False,
            blocker_reason="Provide a domain, URL or IP to pivot on.",
        )
    if not _wazuh_configured():
        return StepPreview(
            summary="No SIEM connector configured for this deployment.",
            can_execute=False,
            blocker_reason=(
                "Set ARGUS_WAZUH_URL + ARGUS_WAZUH_USERNAME / _PASSWORD "
                "in Settings → Services → SIEM connector first."
            ),
        )
    return StepPreview(
        summary=f"Will query Wazuh for events referencing `{indicator}`.",
        affected_items=[AffectedItem(id=indicator, label=indicator)],
    )


async def _siem_execute(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
    user: User,
) -> StepResult:
    indicator = (params.get("indicator") or "").strip()
    if not indicator:
        return StepResult(
            ok=False, summary="No indicator", error="missing indicator",
        )
    if not _wazuh_configured():
        return StepResult(
            ok=False,
            summary="No SIEM connector configured.",
            error="wazuh_unconfigured",
        )

    # Lazy import — keeps the playbook module lean and lets the rest
    # of the catalog load even if the integrations package has its
    # own import-time issues (e.g. partial install).
    try:
        from src.integrations.wazuh.client import WazuhClient
    except Exception as exc:  # noqa: BLE001
        return StepResult(
            ok=False,
            summary="Wazuh client failed to import.",
            error=str(exc)[:300],
        )

    api_url = os.environ["ARGUS_WAZUH_URL"]
    api_key = os.environ["ARGUS_WAZUH_API_KEY"]

    # The shipped client exposes ``get_alerts(limit, offset)`` only —
    # there's no per-indicator search method on the manager today, so
    # we pull a recent batch and filter client-side. For v1 against an
    # OSS Wazuh deployment (typical default 90-day rolling alerts) this
    # is enough to surface activity; if the operator needs deeper
    # retention they can increase the limit cap.
    try:
        async with WazuhClient(api_url=api_url, api_key=api_key) as client:
            response = await client.get_alerts(limit=500, offset=0)
    except Exception as exc:  # noqa: BLE001
        return StepResult(
            ok=False,
            summary=f"Wazuh search failed: {type(exc).__name__}",
            error=str(exc)[:300],
        )

    raw_items = WazuhClient._extract_items(response)
    needle = indicator.lower()
    hits: list[dict[str, Any]] = []
    import json as _json
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        try:
            blob = _json.dumps(item, default=str).lower()
        except (TypeError, ValueError):
            continue
        if needle in blob:
            hits.append(item)

    body_lines = [f"**SIEM pivot (Wazuh) — `{indicator}`**", ""]
    if not hits:
        body_lines.append(
            "- No matching events in the most recent 500 Wazuh alerts. "
            "If this indicator is brand new the absence is expected; "
            "for deeper retention, raise the alert pull limit."
        )
    else:
        body_lines.append(f"- `{len(hits)}` event(s) match this indicator:")
        for h in hits[:10]:
            ts = h.get("timestamp") or h.get("@timestamp") or "—"
            rule = (
                h.get("rule", {}).get("description")
                if isinstance(h.get("rule"), dict)
                else None
            ) or "—"
            host = (
                h.get("agent", {}).get("name")
                if isinstance(h.get("agent"), dict)
                else None
            ) or "—"
            body_lines.append(f"  - `{ts}` · host `{host}` · {rule}")
        if len(hits) > 10:
            body_lines.append(f"  - … {len(hits) - 10} more in Wazuh")

    case_id = _resolve_case_id(params)
    posted = await _post_case_comment(
        db, case_id=case_id, user=user, body="\n".join(body_lines),
    )

    return StepResult(
        ok=True,
        summary=f"SIEM pivot complete: {len(hits)} hit(s) for {indicator}.",
        items=[{
            "indicator": indicator,
            "hit_count": len(hits),
            "case_comment_posted": posted,
        }],
    )


siem_pivot = register(Playbook(
    id="siem_pivot",
    title="SIEM pivot for indicator activity",
    category="investigation",
    description=(
        "Searches the configured SIEM (Wazuh in v1) for any host that "
        "talked to or from the indicator. Result lands as a comment on "
        "the originating case so the operator sees \"5 events from "
        "endpoint-12 hit this domain at 14:01\"."
    ),
    cta_label="Pivot through SIEM →",
    requires_approval=False,
    requires_input=True,
    permission="analyst",
    input_schema=_SIEM_INPUT_SCHEMA,
    scope="investigation",
    applicable_when=lambda snap: _wazuh_configured(),
    steps=(
        PlaybookStep(
            step_id="search",
            title="Search SIEM",
            description="Run Wazuh search and persist hits.",
            preview=_siem_preview,
            execute=_siem_execute,
        ),
    ),
))


# Module-load assertion — every investigation playbook must
# explicitly declare scope="investigation" so a typo doesn't quietly
# leak it into the briefing surface.
_INVESTIGATION_V1 = (
    whois_lookup,
    live_probe_capture,
    cert_transparency_pivot,
    submit_takedown_for_suspect,
    siem_pivot,
)
for _pb in _INVESTIGATION_V1:
    assert _pb.scope == "investigation", _pb.id
del _INVESTIGATION_V1, _pb


__all__ = [
    "whois_lookup",
    "live_probe_capture",
    "cert_transparency_pivot",
    "submit_takedown_for_suspect",
    "siem_pivot",
]
