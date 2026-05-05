"""V1 catalogued playbooks for the AI Executive Briefing.

Six playbooks covering the most common CIO-grade response actions:

* :py:obj:`bulk_takedown_rogue_apps` — submit takedowns for every
  detected rogue mobile app. Single-step, **requires admin approval**
  (irreversible external tickets).
* :py:obj:`triage_brand_suspects` — promote the top-N highest-similarity
  open suspect domains into Brand Defender investigation. Single-step,
  no approval needed.
* :py:obj:`enable_dmarc_reporting` — multi-step: publish DMARC ``p=none``
  reporting record, then verify reports are arriving.
* :py:obj:`set_dmarc_reject_policy` — multi-step: verify quarantine
  baseline, then publish ``p=reject`` records. **Requires admin approval**
  on the publish step (DNS change).
* :py:obj:`add_vip_roster` — operator inputs VIP names/emails; creates
  ``VIPTarget`` rows. Single-step, no approval, ``requires_input=True``.
* :py:obj:`run_typosquat_scan` — fire the brand scanner on the org's
  brand terms. Single-step, no approval needed.

Importing this module registers every playbook; the
:py:func:`__init__.validate_catalog` invariant check then runs at
package import time so any drift fails the import instead of leaking
into a 500.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.dmarc.wizard import generate_records as dmarc_generate_records
from src.models.auth import User
from src.models.brand import SuspectDomain, SuspectDomainState
from src.models.dmarc import DmarcReport
from src.models.social import MobileAppFinding, MobileAppFindingState
from src.models.takedown import (
    TakedownPartner,
    TakedownState,
    TakedownTargetKind,
    TakedownTicket,
)
from src.models.threat import Organization, VIPTarget

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
# Helpers shared across playbooks
# ----------------------------------------------------------------------


def _truthy_count(value: int | None) -> int:
    return int(value or 0)


# ======================================================================
# 1. bulk_takedown_rogue_apps  (single-step, requires_approval=True)
# ======================================================================


async def _rogue_apps_preview(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
) -> StepPreview:
    rows = (
        await db.execute(
            select(MobileAppFinding)
            .where(MobileAppFinding.organization_id == org.id)
            .where(
                MobileAppFinding.state.in_(
                    (
                        MobileAppFindingState.OPEN.value,
                        # We rely on the OPEN bucket for "detected, not
                        # yet adjudicated"; future state values will be
                        # added here as they're introduced.
                    )
                )
            )
            .order_by(MobileAppFinding.created_at.desc())
            .limit(200)
        )
    ).scalars().all()

    # ``r.store`` is the underlying enum *string* (e.g. "apple",
    # "google_play") on the SQLAlchemy attribute, but a few rows may
    # carry the ``MobileAppStore`` enum member instead depending on how
    # they were inserted. Force a clean string either way so the
    # operator sees ``apple`` and not ``MobileAppStore.APPLE``.
    def _store_str(s: Any) -> str:
        return getattr(s, "value", s) or "?"
    items = [
        AffectedItem(
            id=str(r.id),
            label=f"{r.title} ({r.publisher or 'unknown publisher'})",
            sub_label=f"{_store_str(r.store)} · {r.app_id} · matched {r.matched_term!r}",
            metadata={
                "store": _store_str(r.store),
                "app_id": r.app_id,
                "url": r.url,
            },
        )
        for r in rows
    ]
    if not items:
        return StepPreview(
            summary="No detected rogue apps to act on.",
            can_execute=False,
            blocker_reason=(
                "Every rogue app has already been triaged. "
                "Run a fresh mobile-app scan to surface new findings."
            ),
        )
    return StepPreview(
        summary=(
            f"Will create {len(items)} takedown ticket"
            f"{'s' if len(items) != 1 else ''} via the Manual partner adapter."
        ),
        affected_items=items,
        warnings=[
            "Each ticket is irreversible once dispatched to the partner.",
            "Tickets default to the Manual adapter when no integration is configured.",
        ],
    )


async def _rogue_apps_execute(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
    user: User,
) -> StepResult:
    from src.takedown.adapters import SubmitPayload, get_adapter

    rows = (
        await db.execute(
            select(MobileAppFinding)
            .where(MobileAppFinding.organization_id == org.id)
            .where(
                MobileAppFinding.state == MobileAppFindingState.OPEN.value
            )
        )
    ).scalars().all()
    if not rows:
        return StepResult(
            ok=True, summary="No rogue apps in OPEN state — nothing to submit.",
        )

    # Pre-fetch existing manual takedown rows for this org+kind so we can
    # skip rows that already have a ticket. The unique constraint on
    # ``takedown_tickets`` is (org, target_kind, target_identifier,
    # partner) — we mirror it here. Doing a per-row try/flush + rollback
    # on IntegrityError invalidates the async session for subsequent
    # ORM access, which is the actual MissingGreenlet symptom.
    existing_rows = (
        await db.execute(
            select(TakedownTicket.target_identifier).where(
                TakedownTicket.organization_id == org.id,
                TakedownTicket.target_kind == TakedownTargetKind.MOBILE_APP.value,
                TakedownTicket.partner == TakedownPartner.MANUAL.value,
            )
        )
    ).scalars().all()
    existing_targets: set[str] = set(existing_rows)

    def _store_str(s: Any) -> str:
        return getattr(s, "value", s) or "?"

    # Resolve the partner adapter once — Manual today; future versions
    # of this playbook can take ``partner`` as input and dispatch to
    # Netcraft / PhishLabs / etc. via the same call.
    adapter = get_adapter(TakedownPartner.MANUAL.value)

    now = datetime.now(timezone.utc)
    submitted: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    for r in rows:
        target = f"{_store_str(r.store)}:{r.app_id}"
        if target in existing_targets:
            skipped.append({
                "item_id": str(r.id),
                "label": r.title,
                "reason": "duplicate ticket already exists",
            })
            continue

        # Route through the adapter so partner_reference / partner_url
        # are populated from a real call (or the Manual adapter's
        # timestamp ref). Without this the Sync button on the
        # /takedowns page can't operate on these tickets at all
        # because /sync requires partner_reference != NULL.
        submit_result = await adapter.submit(
            SubmitPayload(
                organization_id=str(org.id),
                target_kind=TakedownTargetKind.MOBILE_APP.value,
                target_identifier=target,
                reason="Rogue mobile app impersonating brand — bulk takedown via playbook bulk_takedown_rogue_apps.",
                evidence_urls=[r.url] if r.url else [],
                metadata={
                    "store": _store_str(r.store),
                    "app_id": r.app_id,
                    "publisher": r.publisher,
                },
            )
        )

        ticket = TakedownTicket(
            organization_id=org.id,
            partner=TakedownPartner.MANUAL.value,
            state=(
                TakedownState.SUBMITTED.value
                if submit_result.success
                else TakedownState.FAILED.value
            ),
            target_kind=TakedownTargetKind.MOBILE_APP.value,
            target_identifier=target,
            source_finding_id=r.id,
            partner_reference=submit_result.partner_reference,
            partner_url=submit_result.partner_url,
            submitted_by_user_id=user.id,
            submitted_at=now,
            failed_at=now if not submit_result.success else None,
            notes=(
                submit_result.error_message
                or "Bulk takedown via playbook bulk_takedown_rogue_apps"
            ),
            raw=submit_result.raw,
        )
        db.add(ticket)
        existing_targets.add(target)

        # Track action in state_reason — there's no TAKEDOWN_REQUESTED
        # enum on MobileAppFindingState so we don't transition state.
        r.state_changed_at = now
        r.state_changed_by_user_id = user.id
        r.state_reason = "takedown submitted by playbook"

        bucket = submitted if submit_result.success else failed
        bucket.append({
            "item_id": str(r.id),
            "label": r.title,
            "target_identifier": target,
            "partner_reference": submit_result.partner_reference,
            "partner_url": submit_result.partner_url,
            **({"error": submit_result.error_message} if not submit_result.success else {}),
        })

    # Single flush at the end. If anything still trips the unique
    # constraint at this point it's a genuine race we can't paper over,
    # so let it bubble.
    await db.flush()

    summary = (
        f"{len(submitted)} ticket{'s' if len(submitted) != 1 else ''} submitted, "
        f"{len(failed)} failed, "
        f"{len(skipped)} skipped (duplicate)."
    )
    return StepResult(
        ok=len(submitted) > 0 or (not failed and not skipped),
        summary=summary,
        items=[*submitted, *failed, *skipped],
    )


bulk_takedown_rogue_apps = register(
    Playbook(
        id="bulk_takedown_rogue_apps",
        title="Submit takedowns for all rogue mobile apps",
        category="brand",
        description=(
            "Files a takedown ticket against every detected rogue mobile app "
            "via the configured partner. Each ticket is independent — partial "
            "failures don't block the rest."
        ),
        cta_label="Review takedowns →",
        requires_approval=True,
        permission="analyst",
        applicable_when=lambda snap: _truthy_count(
            getattr(snap, "rogue_app_count", 0)
        ) > 0,
        steps=(
            PlaybookStep(
                step_id="submit_takedowns",
                title="Submit takedowns",
                description="Create one takedown ticket per detected app.",
                preview=_rogue_apps_preview,
                execute=_rogue_apps_execute,
            ),
        ),
    )
)


# ======================================================================
# 2. triage_brand_suspects  (single-step, no approval)
# ======================================================================


_TRIAGE_BATCH_SIZE = 50


async def _triage_suspects_preview(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
) -> StepPreview:
    rows = (
        await db.execute(
            select(SuspectDomain)
            .where(SuspectDomain.organization_id == org.id)
            .where(SuspectDomain.state == SuspectDomainState.OPEN.value)
            .order_by(SuspectDomain.similarity.desc())
            .limit(_TRIAGE_BATCH_SIZE)
        )
    ).scalars().all()
    items = [
        AffectedItem(
            id=str(r.id),
            label=r.domain,
            sub_label=(
                f"matched {r.matched_term_value!r} · "
                f"similarity {r.similarity:.2f} · {r.source}"
            ),
            metadata={
                "similarity": r.similarity,
                "source": r.source,
            },
        )
        for r in rows
    ]
    if not items:
        return StepPreview(
            summary="No open suspect domains to triage.",
            can_execute=False,
            blocker_reason=(
                "Every suspect is either confirmed, dismissed, or already in takedown."
            ),
        )
    return StepPreview(
        summary=(
            f"Will queue Brand Defender investigation on the top "
            f"{len(items)} open suspect"
            f"{'s' if len(items) != 1 else ''} (highest similarity first)."
        ),
        affected_items=items,
    )


async def _triage_suspects_execute(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
    user: User,
) -> StepResult:
    from src.agents.brand_defender_agent import maybe_queue_brand_defence

    rows = (
        await db.execute(
            select(SuspectDomain)
            .where(SuspectDomain.organization_id == org.id)
            .where(SuspectDomain.state == SuspectDomainState.OPEN.value)
            .order_by(SuspectDomain.similarity.desc())
            .limit(_TRIAGE_BATCH_SIZE)
        )
    ).scalars().all()

    queued: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for r in rows:
        action_id = await maybe_queue_brand_defence(db, r)
        if action_id is None:
            skipped.append({
                "item_id": str(r.id),
                "label": r.domain,
                "reason": "below similarity threshold or already queued",
            })
        else:
            queued.append({
                "item_id": str(r.id),
                "label": r.domain,
                "brand_action_id": str(action_id),
            })

    summary = (
        f"{len(queued)} suspect{'s' if len(queued) != 1 else ''} queued for "
        f"Brand Defender investigation, {len(skipped)} skipped."
    )
    return StepResult(
        ok=True,
        summary=summary,
        items=[*queued, *skipped],
    )


triage_brand_suspects = register(
    Playbook(
        id="triage_brand_suspects",
        title="Queue top suspects for Brand Defender investigation",
        category="brand",
        description=(
            "Dispatches the Brand Defender agent against the highest-similarity "
            "open suspect domains. The agent decides per-domain whether to "
            "promote to confirmed-phishing or dismiss."
        ),
        cta_label="Queue for triage →",
        requires_approval=False,
        permission="analyst",
        applicable_when=lambda snap: _truthy_count(
            getattr(snap, "suspect_count", 0)
        ) > 0,
        steps=(
            PlaybookStep(
                step_id="queue_for_brand_defender",
                title="Queue for Brand Defender",
                description=(
                    "Top 50 open suspects by similarity get an agent verdict."
                ),
                preview=_triage_suspects_preview,
                execute=_triage_suspects_execute,
            ),
        ),
    )
)


# ======================================================================
# 3. enable_dmarc_reporting  (multi-step, no approval)
# ======================================================================


async def _dmarc_publish_preview(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
) -> StepPreview:
    domains = list(org.domains or [])
    if not domains:
        return StepPreview(
            summary="No domains registered on the organization.",
            can_execute=False,
            blocker_reason=(
                "Add at least one domain on Settings → Organization "
                "before enabling DMARC reporting."
            ),
        )

    instructions: list[str] = []
    items: list[AffectedItem] = []
    for d in domains:
        try:
            out = dmarc_generate_records(d)
        except ValueError:
            continue
        items.append(
            AffectedItem(
                id=d,
                label=d,
                sub_label=f"rua={out.rua_endpoint}",
                metadata={"records": out.dmarc_records_progression},
            )
        )
        # Use the first progression entry, which is p=none.
        first = out.dmarc_records_progression[0] if out.dmarc_records_progression else None
        if first:
            instructions.append(
                f"{first.get('name', f'_dmarc.{d}')}  TXT  {first.get('value', '')}"
            )

    return StepPreview(
        summary=(
            f"Will publish a DMARC p=none reporting record on {len(items)} "
            f"domain{'s' if len(items) != 1 else ''}. Reports start arriving "
            f"within ~24 hours."
        ),
        affected_items=items,
        instructions=instructions,
        warnings=[
            "Argus does not modify your DNS — copy each record into your DNS "
            "provider after clicking Mark as published.",
        ],
    )


async def _dmarc_publish_execute(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
    user: User,
) -> StepResult:
    # The actual DNS write happens operator-side. This step just records
    # operator confirmation that the records are now live, so the verify
    # step has a sane "started waiting" timestamp.
    domains = list(org.domains or [])
    return StepResult(
        ok=True,
        summary=(
            f"Marked DMARC reporting as published for {len(domains)} domain"
            f"{'s' if len(domains) != 1 else ''}. "
            f"Continue once reports start arriving."
        ),
        items=[{"item_id": d, "label": d, "marked_at": datetime.now(timezone.utc).isoformat()} for d in domains],
    )


async def _dmarc_verify_preview(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
) -> StepPreview:
    cutoff = datetime.now(timezone.utc) - timedelta(days=14)
    count = (
        await db.execute(
            select(func.count())
            .select_from(DmarcReport)
            .where(DmarcReport.organization_id == org.id)
            .where(DmarcReport.created_at >= cutoff)
        )
    ).scalar_one() or 0

    if count == 0:
        return StepPreview(
            summary="No DMARC aggregate reports received in the last 14 days yet.",
            warnings=[
                "Reports arrive within ~24h after the record is live. "
                "If it has been longer, double-check the rua= endpoint resolves "
                "and that mailbox providers can deliver to it.",
            ],
            can_execute=False,
            blocker_reason="Waiting on first aggregate report.",
        )
    return StepPreview(
        summary=f"{count} DMARC report(s) ingested in the last 14 days. Ready to confirm reporting is healthy.",
    )


async def _dmarc_verify_execute(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
    user: User,
) -> StepResult:
    cutoff = datetime.now(timezone.utc) - timedelta(days=14)
    count = (
        await db.execute(
            select(func.count())
            .select_from(DmarcReport)
            .where(DmarcReport.organization_id == org.id)
            .where(DmarcReport.created_at >= cutoff)
        )
    ).scalar_one() or 0
    return StepResult(
        ok=count > 0,
        summary=f"Confirmed {count} report(s) ingested. DMARC reporting is healthy.",
        items=[],
        error=None if count else "No reports ingested yet.",
    )


enable_dmarc_reporting = register(
    Playbook(
        id="enable_dmarc_reporting",
        title="Enable DMARC reporting on all brand domains",
        category="email",
        description=(
            "Generates the DMARC p=none reporting record for every brand "
            "domain and waits until aggregate reports start arriving. Step 1 "
            "shows the DNS records to publish; step 2 verifies reports are "
            "flowing."
        ),
        cta_label="Set up DMARC →",
        requires_approval=False,
        permission="analyst",
        applicable_when=lambda snap: (
            getattr(snap, "dmarc_pass_rate", None) is None
        ),
        steps=(
            PlaybookStep(
                step_id="publish_reporting_record",
                title="Publish DMARC reporting record",
                description=(
                    "Copy each generated TXT record into your DNS provider, "
                    "then mark as published."
                ),
                preview=_dmarc_publish_preview,
                execute=_dmarc_publish_execute,
            ),
            PlaybookStep(
                step_id="verify_reports_arriving",
                title="Verify reports arriving",
                description=(
                    "Check that aggregate reports have been ingested in the "
                    "last 14 days."
                ),
                preview=_dmarc_verify_preview,
                execute=_dmarc_verify_execute,
            ),
        ),
    )
)


# ======================================================================
# 4. set_dmarc_reject_policy  (multi-step, requires_approval on publish)
# ======================================================================


async def _dmarc_baseline_preview(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
) -> StepPreview:
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    rows = (
        await db.execute(
            select(DmarcReport)
            .where(DmarcReport.organization_id == org.id)
            .where(DmarcReport.created_at >= cutoff)
        )
    ).scalars().all()
    if not rows:
        return StepPreview(
            summary="No DMARC reports in the last 30 days.",
            can_execute=False,
            blocker_reason=(
                "Run enable_dmarc_reporting first and wait for reports "
                "to accumulate before tightening policy."
            ),
        )
    total = sum(r.total_messages or 0 for r in rows)
    passes = sum(r.pass_count or 0 for r in rows)
    rate = (passes / total) if total else 0.0
    if rate < 0.95:
        return StepPreview(
            summary=(
                f"DMARC pass-rate is {rate:.1%} over 30d ({passes:,}/{total:,}) — "
                f"too low to safely move to p=reject."
            ),
            warnings=[
                "Pass-rate below 95% means legitimate mail will be rejected.",
                "Investigate failing source IPs in /dmarc before continuing.",
            ],
            can_execute=False,
            blocker_reason="Pass-rate below 95% baseline.",
        )
    return StepPreview(
        summary=(
            f"DMARC pass-rate is {rate:.1%} over 30d ({passes:,}/{total:,}). "
            f"Safe to escalate to p=reject."
        ),
    )


async def _dmarc_baseline_execute(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
    user: User,
) -> StepResult:
    return StepResult(
        ok=True,
        summary="Baseline confirmed. Proceed to publish p=reject record.",
    )


async def _dmarc_reject_preview(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
) -> StepPreview:
    domains = list(org.domains or [])
    items: list[AffectedItem] = []
    instructions: list[str] = []
    for d in domains:
        try:
            out = dmarc_generate_records(d)
        except ValueError:
            continue
        # Find p=reject in the progression.
        reject = next(
            (r for r in out.dmarc_records_progression if "p=reject" in r.get("value", "")),
            None,
        )
        if not reject:
            continue
        items.append(
            AffectedItem(
                id=d,
                label=d,
                sub_label=reject.get("value", ""),
                metadata={"record": reject},
            )
        )
        instructions.append(
            f"{reject.get('name', f'_dmarc.{d}')}  TXT  {reject.get('value', '')}"
        )
    return StepPreview(
        summary=(
            f"Will instruct DNS update on {len(items)} domain"
            f"{'s' if len(items) != 1 else ''} to p=reject."
        ),
        affected_items=items,
        instructions=instructions,
        warnings=[
            "Once p=reject is live, mailbox providers will reject any "
            "unaligned mail. Confirm SPF/DKIM coverage for every legitimate "
            "sender first.",
        ],
    )


async def _dmarc_reject_execute(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
    user: User,
) -> StepResult:
    domains = list(org.domains or [])
    return StepResult(
        ok=True,
        summary=(
            f"Recorded p=reject publication on {len(domains)} domain"
            f"{'s' if len(domains) != 1 else ''}. "
            f"Monitor /dmarc for a week to confirm no legitimate mail is "
            f"being rejected."
        ),
        items=[{"item_id": d, "label": d} for d in domains],
    )


set_dmarc_reject_policy = register(
    Playbook(
        id="set_dmarc_reject_policy",
        title="Escalate DMARC policy to p=reject",
        category="email",
        description=(
            "Verifies a 30-day baseline of ≥95% DMARC pass rate, then "
            "instructs the DNS update to p=reject. Reject means mailbox "
            "providers will block any spoofed mail outright."
        ),
        cta_label="Escalate to reject →",
        requires_approval=True,
        permission="admin",
        applicable_when=lambda snap: (
            (rate := getattr(snap, "dmarc_pass_rate", None)) is not None
            and rate >= 0.95
        ),
        steps=(
            PlaybookStep(
                step_id="verify_baseline",
                title="Verify quarantine baseline",
                description="Confirm DMARC pass-rate is healthy enough to tighten.",
                preview=_dmarc_baseline_preview,
                execute=_dmarc_baseline_execute,
            ),
            PlaybookStep(
                step_id="publish_reject_record",
                title="Publish p=reject record",
                description="Update DNS to the strict reject policy.",
                preview=_dmarc_reject_preview,
                execute=_dmarc_reject_execute,
            ),
        ),
    )
)


# ======================================================================
# 5. add_vip_roster  (single-step, requires_input=True, no approval)
# ======================================================================


_VIP_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "vips": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name":     {"type": "string", "minLength": 1},
                    "title":    {"type": "string"},
                    "emails":   {"type": "array", "items": {"type": "string"}},
                    "usernames":{"type": "array", "items": {"type": "string"}},
                },
                "required": ["name"],
            },
            "minItems": 1,
            "maxItems": 50,
        }
    },
    "required": ["vips"],
}


async def _vip_preview(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
) -> StepPreview:
    vips = params.get("vips") or []
    if not vips:
        return StepPreview(
            summary="No VIPs in the input form.",
            can_execute=False,
            blocker_reason="Add at least one VIP before continuing.",
        )
    items = [
        AffectedItem(
            id=str(i),
            label=v.get("name", "(unnamed)"),
            sub_label=v.get("title") or None,
            metadata={
                "emails": v.get("emails") or [],
                "usernames": v.get("usernames") or [],
            },
        )
        for i, v in enumerate(vips)
    ]
    return StepPreview(
        summary=f"Will create {len(items)} VIP target row(s).",
        affected_items=items,
    )


async def _vip_execute(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
    user: User,
) -> StepResult:
    vips = params.get("vips") or []
    created: list[dict[str, Any]] = []
    for v in vips:
        target = VIPTarget(
            organization_id=org.id,
            name=v.get("name", "").strip() or "Unnamed VIP",
            title=(v.get("title") or "").strip() or None,
            emails=list(v.get("emails") or []),
            usernames=list(v.get("usernames") or []),
            phone_numbers=list(v.get("phone_numbers") or []),
        )
        db.add(target)
        await db.flush()
        created.append({
            "item_id": str(target.id),
            "label": target.name,
        })
    return StepResult(
        ok=True,
        summary=f"Created {len(created)} VIP target row(s).",
        items=created,
    )


add_vip_roster = register(
    Playbook(
        id="add_vip_roster",
        title="Add VIP executive protection roster",
        category="asset",
        description=(
            "Creates VIP target rows so the impersonation, fraud and "
            "social-monitoring pipelines start matching against executive "
            "names, emails and handles."
        ),
        cta_label="Add VIPs →",
        requires_approval=False,
        requires_input=True,
        permission="analyst",
        input_schema=_VIP_INPUT_SCHEMA,
        applicable_when=lambda snap: _truthy_count(
            getattr(snap, "vip_count", 0)
        ) == 0,
        steps=(
            PlaybookStep(
                step_id="create_vips",
                title="Create VIP rows",
                description="Persist each VIP target.",
                preview=_vip_preview,
                execute=_vip_execute,
            ),
        ),
    )
)


# ======================================================================
# 6. run_typosquat_scan  (single-step, no approval)
# ======================================================================


async def _typosquat_preview(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
) -> StepPreview:
    from src.models.brand import BrandTerm

    terms = (
        await db.execute(
            select(BrandTerm)
            .where(BrandTerm.organization_id == org.id)
            .where(BrandTerm.is_active == True)  # noqa: E712
        )
    ).scalars().all()
    if not terms:
        return StepPreview(
            summary="No active brand terms — nothing to scan.",
            can_execute=False,
            blocker_reason=(
                "Add brand terms on /brand first; the scanner permutes those "
                "into typosquat candidates."
            ),
        )
    items = [
        AffectedItem(
            id=str(t.id),
            label=t.value,
            sub_label=f"kind={t.kind}",
        )
        for t in terms
    ]
    return StepPreview(
        summary=f"Will permute {len(items)} brand term(s) and resolve every candidate.",
        affected_items=items,
        warnings=[
            "Scan runs synchronously; large brand-term sets can take a minute or two.",
        ],
    )


async def _typosquat_execute(
    db: AsyncSession,
    org: Organization,
    params: dict,
    prior: list[StepResult],
    user: User,
) -> StepResult:
    from src.brand.scanner import scan_organization

    try:
        report = await scan_organization(db, org.id)
    except Exception as exc:  # noqa: BLE001
        logger.exception("typosquat scan failed for org %s", org.id)
        return StepResult(
            ok=False,
            summary="Scan failed; see error.",
            error=str(exc),
        )
    return StepResult(
        ok=True,
        summary=(
            f"Scanned {report.terms_scanned} term(s) → "
            f"{report.permutations_generated} permutation(s) → "
            f"{report.suspects_created} new suspect(s) created, "
            f"{report.suspects_seen_again} already known."
        ),
        items=[],
    )


run_typosquat_scan = register(
    Playbook(
        id="run_typosquat_scan",
        title="Run a fresh typosquat scan",
        category="brand",
        description=(
            "Permutes the org's active brand terms and resolves every "
            "candidate domain. New SuspectDomain rows are auto-queued for "
            "Brand Defender investigation."
        ),
        cta_label="Run scan →",
        requires_approval=False,
        permission="analyst",
        applicable_when=lambda snap: True,  # always offer-able
        steps=(
            PlaybookStep(
                step_id="run_scan",
                title="Run scanner",
                description="Permute brand terms and resolve candidates.",
                preview=_typosquat_preview,
                execute=_typosquat_execute,
            ),
        ),
    )
)


# Module-load self-check — every playbook in V1 must have applicable_when
# and at least one step. The Playbook __post_init__ already enforces
# this, but a defensive sanity check at import time means a refactor
# that bypasses the dataclass constructor still gets caught.
_V1 = (
    bulk_takedown_rogue_apps,
    triage_brand_suspects,
    enable_dmarc_reporting,
    set_dmarc_reject_policy,
    add_vip_roster,
    run_typosquat_scan,
)
for _pb in _V1:
    assert _pb.applicable_when is not None, _pb.id
    assert _pb.steps, _pb.id
del _V1, _pb


__all__ = [
    "bulk_takedown_rogue_apps",
    "triage_brand_suspects",
    "enable_dmarc_reporting",
    "set_dmarc_reject_policy",
    "add_vip_roster",
    "run_typosquat_scan",
]
