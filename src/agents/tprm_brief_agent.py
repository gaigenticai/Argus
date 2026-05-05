"""Vendor risk brief + mitigation playbook generator + quarterly health-check.

Three operations:

  1. ``generate_brief(vendor)`` — synthesises the latest scorecard, posture
     signals, sanctions, snapshots and questionnaire answers into a 1-page
     narrative brief suitable for a procurement / risk-committee deck.
     Always produces a deterministic baseline; the LLM polishes if the
     provider is configured.

  2. ``generate_playbook(vendor, failing_pillar)`` — emits a structured
     mitigation playbook for the given pillar (questionnaire / security /
     breach / operational) — concrete steps, ownership hints,
     evidence we'd want before changing the score.

  3. ``run_quarterly_health_check(org)`` — recomputes every vendor scorecard
     in the org, snapshots history, detects >20-point drops, returns a
     summary dict the cron hook persists into a CaseEvent and an email
     digest. (Email send hand-off lives in ``src/notifications`` — outside
     this module.)
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.llm.providers import LLMNotConfigured, get_provider
from src.models.threat import Asset
from src.models.tprm import (
    VendorPostureSignal,
    VendorScorecard,
)
from src.tprm.scoring import compute_vendor_score, persist_vendor_scorecard
from src.tprm.snapshots import detect_score_drop, list_snapshots

_logger = logging.getLogger(__name__)


async def _latest_scorecard(
    db: AsyncSession, vendor_asset_id: uuid.UUID
) -> VendorScorecard | None:
    return (
        await db.execute(
            select(VendorScorecard)
            .where(VendorScorecard.vendor_asset_id == vendor_asset_id)
            .where(VendorScorecard.is_current.is_(True))
            .limit(1)
        )
    ).scalar_one_or_none()


async def _posture_signals(
    db: AsyncSession, vendor_asset_id: uuid.UUID
) -> list[VendorPostureSignal]:
    return list(
        (
            await db.execute(
                select(VendorPostureSignal).where(
                    VendorPostureSignal.vendor_asset_id == vendor_asset_id
                )
            )
        ).scalars()
    )


def _baseline_brief(
    vendor: Asset, card: VendorScorecard | None, signals: list[VendorPostureSignal]
) -> str:
    lines: list[str] = []
    lines.append(f"Vendor: {vendor.value}")
    lines.append(f"Criticality: {vendor.criticality}")
    if card is None:
        lines.append("Scorecard: not yet computed")
    else:
        lines.append(
            f"Scorecard: {card.score:.1f}/100 ({card.grade}) "
            f"computed {card.computed_at.isoformat()}"
        )
        for k, v in (card.pillar_scores or {}).items():
            lines.append(f"  · {k}: {v}")
    if signals:
        lines.append("Posture signals:")
        for s in signals:
            lines.append(
                f"  · {s.kind}: score={s.score} severity={s.severity} — {s.summary or ''}"
            )
    return "\n".join(lines)


async def generate_brief(
    db: AsyncSession,
    *,
    vendor_asset_id: uuid.UUID,
    use_llm: bool = True,
) -> dict[str, Any]:
    vendor = await db.get(Asset, vendor_asset_id)
    if vendor is None:
        raise LookupError("vendor asset not found")
    card = await _latest_scorecard(db, vendor_asset_id)
    signals = await _posture_signals(db, vendor_asset_id)
    snapshots = await list_snapshots(
        db,
        organization_id=vendor.organization_id,
        vendor_asset_id=vendor_asset_id,
        days=180,
    )
    drop = detect_score_drop(snapshots) if snapshots else None
    baseline = _baseline_brief(vendor, card, signals)

    narrative = baseline
    used_llm = False
    if use_llm:
        try:
            provider = get_provider(settings.llm)
            sys = (
                "You write a one-paragraph risk brief for a procurement committee. "
                "Output 4-6 sentences, plain text, no markdown, no headings. Lead "
                "with the headline grade and the largest risk; close with the "
                "single highest-priority next action."
            )
            user = (
                f"BASELINE:\n{baseline}\n\n"
                f"recent_drop_alert: {drop or 'none'}\n"
                "Avoid hedging language. Be specific."
            )
            out = (await provider.call(sys, user) or "").strip()
            if out and len(out) <= 1500:
                narrative = out
                used_llm = True
        except LLMNotConfigured:
            pass
        except Exception as e:  # noqa: BLE001
            _logger.warning("brief LLM failed: %s", e)
    return {
        "vendor_value": vendor.value,
        "vendor_id": str(vendor.id),
        "current_score": card.score if card else None,
        "current_grade": card.grade if card else None,
        "drop_alert": drop,
        "narrative": narrative,
        "llm_used": used_llm,
        "baseline": baseline,
    }


_PILLAR_PLAYBOOKS: dict[str, list[str]] = {
    "questionnaire": [
        "Re-send the latest questionnaire instance with a 14-day SLA.",
        "Schedule a 30-minute clarification call with the vendor's CISO if any required answer is still missing.",
        "Request a copy of their most recent SOC 2 / ISO 27001 report and parse it into the evidence vault.",
    ],
    "security": [
        "Run a fresh Argus EASM sweep against the vendor's primary domain (subfinder → httpx → nuclei).",
        "Open a Case for any nuclei finding above HIGH severity and assign it to the procurement lead.",
        "Send the vendor a short security-posture report with our top 3 findings and a 30-day remediation deadline.",
    ],
    "breach": [
        "If HIBP shows hits on common-localpart vendor mailboxes, ask the vendor to rotate those credentials and confirm MFA enforcement.",
        "If sanctions lists hit, escalate to legal/compliance before any further engagement.",
        "If internal leakage findings are open, mark them for legal-hold and re-run the breach pillar.",
    ],
    "operational": [
        "Verify the contract dates in the vendor record and request a renewal if expiring in <90 days.",
        "Tighten the data_access_level if the vendor's actual scope is narrower than recorded.",
        "Push DMARC/SPF to enforce — at minimum p=quarantine — at the vendor before next questionnaire cycle.",
    ],
}


async def generate_playbook(
    db: AsyncSession,
    *,
    vendor_asset_id: uuid.UUID,
    failing_pillar: str,
    use_llm: bool = True,
) -> dict[str, Any]:
    vendor = await db.get(Asset, vendor_asset_id)
    if vendor is None:
        raise LookupError("vendor asset not found")
    card = await _latest_scorecard(db, vendor_asset_id)
    base_actions = _PILLAR_PLAYBOOKS.get(
        failing_pillar.lower(),
        ["No structured playbook for this pillar — escalate to the risk lead."],
    )
    actions = list(base_actions)
    used_llm = False
    if use_llm:
        try:
            provider = get_provider(settings.llm)
            sys = (
                "You expand a 3-step mitigation checklist for a vendor risk pillar. "
                "Return STRICT JSON: {\"actions\": [string,...], \"owner\": string, "
                "\"due_days\": int}. Each action <=180 chars, imperative voice. No prose."
            )
            user = (
                f"vendor: {vendor.value}\n"
                f"pillar: {failing_pillar}\n"
                f"current_score: {card.score if card else 'unknown'}\n"
                f"baseline_actions: {base_actions}\n"
            )
            out = (await provider.call(sys, user) or "").strip()
            if out.startswith("```"):
                import re as _re

                out = _re.sub(r"^```[a-z]*\s*|\s*```$", "", out, flags=_re.MULTILINE).strip()
            import json as _json

            obj = _json.loads(out)
            if isinstance(obj, dict) and isinstance(obj.get("actions"), list):
                actions = [str(a)[:300] for a in obj["actions"][:8]]
                used_llm = True
        except LLMNotConfigured:
            pass
        except Exception as e:  # noqa: BLE001
            _logger.warning("playbook LLM failed: %s", e)
    return {
        "vendor_value": vendor.value,
        "pillar": failing_pillar,
        "actions": actions,
        "current_score": card.score if card else None,
        "llm_used": used_llm,
    }


async def run_quarterly_health_check(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    drop_threshold: float = 20.0,
) -> dict[str, Any]:
    vendors = (
        await db.execute(
            select(Asset).where(
                Asset.organization_id == organization_id,
                Asset.asset_type == "vendor",
            )
        )
    ).scalars().all()
    summary: dict[str, Any] = {
        "vendors_total": len(vendors),
        "computed": 0,
        "drops_detected": [],
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    for v in vendors:
        try:
            result = await compute_vendor_score(db, organization_id, v.id)
            await persist_vendor_scorecard(db, organization_id, v.id, result)
            await db.commit()
            summary["computed"] += 1
            snaps = await list_snapshots(
                db,
                organization_id=organization_id,
                vendor_asset_id=v.id,
                days=180,
            )
            drop = detect_score_drop(snaps, threshold=drop_threshold)
            if drop:
                summary["drops_detected"].append(
                    {"vendor": v.value, "vendor_id": str(v.id), **drop}
                )
        except Exception as e:  # noqa: BLE001
            _logger.warning("quarterly check failed for %s: %s", v.value, e)
            await db.rollback()
    summary["finished_at"] = datetime.now(timezone.utc).isoformat()
    return summary


__all__ = ["generate_brief", "generate_playbook", "run_quarterly_health_check"]
