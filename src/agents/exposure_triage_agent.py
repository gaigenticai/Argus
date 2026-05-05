"""AI exposure triage + false-positive suppression agent.

Two operations both surfaced through ``POST /easm/exposures/triage``:

1. **Risk-rank** every open exposure by a composite score (0–100):

       EPSS exploit probability × 40
       CVSS base score / 10     × 25
       CISA KEV catalog flag    +20 boost
       Linked asset criticality +10 (critical) / +5 (high)
       Open age                 +5 (>180 days)

   The deterministic score is always written; an LLM-generated rationale
   is appended when the platform's configured provider can dispatch.
   When the LLM is unavailable the rationale falls back to a structured
   template so analysts always see *why* a score was assigned.

2. **False-positive suppression**: if an open exposure matches a
   ``(rule_id, target_host)`` pair the analyst already dismissed as
   ``false_positive`` in the same org within the past 90 days, the
   agent sets ``ai_suggest_dismiss=True`` with an explanation. The
   analyst still drives the actual dismissal — the agent only flags.

Both pass over the same set of rows; the function commits once per
batch.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.intel.exposure_enrichment import enrich_findings
from src.llm.providers import LLMNotConfigured, LLMTransportError, get_provider
from src.models.exposures import ExposureFinding, ExposureState
from src.models.threat import Asset

_logger = logging.getLogger(__name__)


_FP_LOOKBACK_DAYS = 90
_LLM_RATIONALE_TIMEOUT_S = 20  # bound; if LLM is slow we fall back


@dataclass
class TriageResult:
    exposure_id: uuid.UUID
    ai_priority: float
    ai_rationale: str
    ai_suggest_dismiss: bool = False
    ai_dismiss_reason: str | None = None


@dataclass
class TriageReport:
    org_id: uuid.UUID
    triaged_count: int = 0
    suppressed_count: int = 0
    llm_used: bool = False
    llm_failures: int = 0
    results: list[TriageResult] = field(default_factory=list)


# --- Helpers --------------------------------------------------------


def _norm_host(s: str) -> str:
    if not s:
        return ""
    s = s.strip().lower()
    for prefix in ("https://", "http://"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    s = s.split("/", 1)[0]
    s = s.split(":", 1)[0]
    return s


def _criticality_boost(asset: Asset | None) -> tuple[float, str]:
    if asset is None:
        return 0.0, ""
    crit = (asset.criticality or "").lower()
    if crit == "critical":
        return 10.0, "critical asset"
    if crit == "high":
        return 5.0, "high-criticality asset"
    return 0.0, ""


def _age_boost(matched_at: datetime | None, now: datetime) -> tuple[float, str]:
    if matched_at is None:
        return 0.0, ""
    delta = now - matched_at
    if delta.days >= 180:
        return 5.0, f"open {delta.days}d (well past SLA)"
    return 0.0, ""


def _score_finding(
    f: ExposureFinding,
    *,
    asset: Asset | None,
    now: datetime,
) -> tuple[float, list[str]]:
    """Deterministic composite score + ordered list of rationale clauses
    used to render a sentence for analysts."""
    components: list[str] = []
    score = 0.0

    if f.epss_score is not None:
        epss_pts = float(f.epss_score) * 40.0
        score += epss_pts
        components.append(
            f"EPSS {float(f.epss_score) * 100:.1f}% (+{epss_pts:.1f})"
        )

    if f.cvss_score is not None:
        cvss_pts = (float(f.cvss_score) / 10.0) * 25.0
        score += cvss_pts
        components.append(
            f"CVSS {float(f.cvss_score):.1f} (+{cvss_pts:.1f})"
        )

    if f.is_kev:
        score += 20.0
        components.append("on CISA KEV catalog (+20)")

    crit_pts, crit_label = _criticality_boost(asset)
    if crit_pts:
        score += crit_pts
        components.append(f"{crit_label} (+{crit_pts:.0f})")

    age_pts, age_label = _age_boost(f.matched_at, now)
    if age_pts:
        score += age_pts
        components.append(f"{age_label} (+{age_pts:.0f})")

    score = max(0.0, min(score, 100.0))
    return score, components


def _template_rationale(
    f: ExposureFinding, components: list[str], score: float
) -> str:
    """Used when the LLM provider isn't available or fails."""
    bits = ", ".join(components) if components else "no enrichment signals"
    severity = (f.severity or "unknown").upper()
    headline = f.title or f.rule_id
    return (
        f"AI priority {score:.0f}/100 — {severity} severity {headline}. "
        f"Score components: {bits}."
    )


async def _llm_rationale(
    provider, f: ExposureFinding, components: list[str], score: float
) -> str | None:
    """Best-effort LLM narrative; returns None on any failure so the
    caller can fall back to the deterministic template."""
    try:
        sysmsg = (
            "You are a SOC analyst summarising one exposure for an analyst's "
            "ranked queue. Output ONE sentence, max 35 words, plain text "
            "(no markdown, no bullet points, no preamble). Lead with the "
            "actionable risk; mention KEV / EPSS / age only if material."
        )
        components_str = ", ".join(components) if components else "no enrichment data"
        user = (
            f"Exposure: {f.title or f.rule_id}\n"
            f"Severity: {f.severity}\n"
            f"CVE: {', '.join(f.cve_ids or []) or 'none'}\n"
            f"Target: {f.target}\n"
            f"Score components: {components_str}\n"
            f"Composite priority: {score:.0f}/100\n"
        )
        text = await provider.call(sysmsg, user)
        text = (text or "").strip()
        if not text or len(text) > 800:
            return None
        return text
    except (LLMNotConfigured, LLMTransportError, Exception) as e:  # noqa: BLE001
        _logger.warning("triage LLM rationale failed: %s", e)
        return None


# --- FP suppression -------------------------------------------------


async def _learn_fp_patterns(
    db: AsyncSession, org_id: uuid.UUID
) -> dict[tuple[str, str], tuple[datetime, str | None]]:
    """Return ``{(rule_id, normalised_host): (decided_at, reason)}`` for
    every false-positive transition in this org over the lookback window."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=_FP_LOOKBACK_DAYS)
    rows = (
        await db.execute(
            select(
                ExposureFinding.rule_id,
                ExposureFinding.target,
                ExposureFinding.state_changed_at,
                ExposureFinding.state_reason,
            )
            .where(ExposureFinding.organization_id == org_id)
            .where(ExposureFinding.state == ExposureState.FALSE_POSITIVE.value)
            .where(ExposureFinding.state_changed_at >= cutoff)
        )
    ).all()
    out: dict[tuple[str, str], tuple[datetime, str | None]] = {}
    for r in rows:
        host = _norm_host(r.target or "")
        if not r.rule_id or not host:
            continue
        key = (r.rule_id, host)
        existing = out.get(key)
        ts = r.state_changed_at or datetime.min.replace(tzinfo=timezone.utc)
        if existing is None or existing[0] < ts:
            out[key] = (ts, r.state_reason)
    return out


def _maybe_suppress(
    f: ExposureFinding,
    fp_patterns: dict[tuple[str, str], tuple[datetime, str | None]],
) -> tuple[bool, str | None]:
    if f.state != ExposureState.OPEN.value and f.state != ExposureState.REOPENED.value:
        return False, None
    host = _norm_host(f.target or "")
    if not f.rule_id or not host:
        return False, None
    hit = fp_patterns.get((f.rule_id, host))
    if hit is None:
        return False, None
    decided_at, reason = hit
    iso = decided_at.date().isoformat()
    if reason:
        msg = f"Same rule + host marked false-positive on {iso}: {reason}"
    else:
        msg = f"Same rule + host marked false-positive on {iso} by an analyst."
    return True, msg


# --- Public entrypoint ---------------------------------------------


async def triage_exposures(
    db: AsyncSession,
    org_id: uuid.UUID,
    *,
    exposure_ids: list[uuid.UUID] | None = None,
    use_llm: bool = True,
) -> TriageReport:
    """Score and (optionally) narrate every open exposure for ``org_id``.

    ``exposure_ids`` lets callers triage a subset; ``None`` triages
    everything currently in OPEN/REOPENED state.

    Mutates the rows in place and commits once.
    """
    report = TriageReport(org_id=org_id)

    qs = select(ExposureFinding).where(
        ExposureFinding.organization_id == org_id,
        ExposureFinding.state.in_(
            [ExposureState.OPEN.value, ExposureState.REOPENED.value]
        ),
    )
    if exposure_ids:
        qs = qs.where(ExposureFinding.id.in_(exposure_ids))
    findings = list((await db.execute(qs)).scalars().all())
    if not findings:
        return report

    # Make sure we have NVD/EPSS/KEV enrichment baked in before scoring.
    await enrich_findings(db, findings)

    # Collect linked assets for the criticality boost in one round-trip.
    asset_ids = {f.asset_id for f in findings if f.asset_id}
    asset_map: dict[uuid.UUID, Asset] = {}
    if asset_ids:
        rows = (
            await db.execute(select(Asset).where(Asset.id.in_(asset_ids)))
        ).scalars().all()
        asset_map = {r.id: r for r in rows}

    fp_patterns = await _learn_fp_patterns(db, org_id)

    # Try to wire up an LLM provider. If unconfigured we fall back to the
    # deterministic template — agents must never block on a missing LLM.
    provider = None
    if use_llm:
        try:
            provider = get_provider(settings.llm)
        except LLMNotConfigured:
            provider = None
        except Exception as e:  # noqa: BLE001
            _logger.warning("triage: get_provider failed: %s", e)
            provider = None

    now = datetime.now(timezone.utc)
    for f in findings:
        asset = asset_map.get(f.asset_id) if f.asset_id else None
        score, components = _score_finding(f, asset=asset, now=now)

        rationale: str | None = None
        if provider is not None:
            rationale = await _llm_rationale(provider, f, components, score)
            if rationale is None:
                report.llm_failures += 1
        if rationale is None:
            rationale = _template_rationale(f, components, score)
        else:
            report.llm_used = True

        f.ai_priority = float(score)
        f.ai_rationale = rationale
        f.ai_triaged_at = now

        suggest, dismiss_reason = _maybe_suppress(f, fp_patterns)
        f.ai_suggest_dismiss = suggest
        f.ai_dismiss_reason = dismiss_reason
        if suggest:
            report.suppressed_count += 1

        report.triaged_count += 1
        report.results.append(
            TriageResult(
                exposure_id=f.id,
                ai_priority=score,
                ai_rationale=rationale,
                ai_suggest_dismiss=suggest,
                ai_dismiss_reason=dismiss_reason,
            )
        )

    await db.commit()
    return report


__all__ = ["TriageReport", "TriageResult", "triage_exposures"]
