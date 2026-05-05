"""Leakage agentic handlers — Bridge-LLM driven.

Five handlers, all registered via ``src.llm.agent_queue.register_handler``:

  * ``leakage_classify``         Severity classifier (PII / financial / etc.).
  * ``leakage_takedown_draft``   DMCA / abuse takedown drafter.
  * ``leakage_correlate_cross_org``
                                Cross-org correlator — surfaces supply-chain
                                breaches when the same PAN/email appears in
                                multiple customers' findings.
  * ``leakage_exec_briefing``    Daily exec briefing (Markdown) per org.
  * ``leakage_policy_tune``      False-positive sweep against a benign
                                corpus; suggests tighter regex when FP > 20%.

All Bridge prompts request strict JSON (when applicable) and parse leniently
via :func:`_parse_json`. Every handler must return a ``dict`` so the
dispatcher can persist it as ``AgentTask.result``.
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.llm.agent_queue import call_bridge, register_handler
from src.models.agent_task import AgentTask
from src.models.leakage import (
    CardLeakageFinding,
    DlpFinding,
    DlpPolicy,
    LeakageState,
)
from src.models.notification_inbox import NotificationInboxItem
from src.models.threat import (
    Alert,
    AlertStatus,
    ThreatCategory,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------- helpers


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# DLP excerpts ship with their matched secrets replaced by a fingerprint
# placeholder of the form ``<redacted len=N sha256=DEADBEEF12345678>``
# (see ``src/leakage/dlp.py:_redact_excerpt``). The cross-org correlator
# uses these fingerprints — never the cleartext — to find findings in
# other tenants that share the same secret. This keeps PII out of the
# correlator while still catching repeated leaks.
_REDACTION_FP_RE = re.compile(r"<redacted\s+len=\d+\s+sha256=([0-9a-f]{8,64})>")


def _parse_json(text: str) -> dict[str, Any] | None:
    """Lenient JSON parse.

    Handles four flaky shapes Bridge models produce in practice:
      1. Plain JSON.
      2. Markdown-fenced: ``` ```json … ``` ```.
      3. Prose-wrapped JSON inside arbitrary text.
      4. Lazy JSON with bare-word enum values (``"impact_level": critical``).
         We rewrite those to quoted strings before re-parsing.
    """
    if not text:
        return None
    s = text.strip()
    for candidate in _json_candidates(s):
        for variant in (candidate, _quote_bare_words(candidate)):
            try:
                obj = json.loads(variant)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                return obj
    return None


def _json_candidates(s: str) -> list[str]:
    out = [s]
    # Strip markdown fence.
    cleaned = re.sub(r"^```(?:json)?\s*", "", s)
    cleaned = re.sub(r"\s*```$", "", cleaned.strip())
    if cleaned != s:
        out.append(cleaned)
    # Brace-bounded slice.
    first = s.find("{")
    last = s.rfind("}")
    if first != -1 and last > first:
        out.append(s[first : last + 1])
    return out


_BARE_VALUE_RE = re.compile(
    r'("\w[\w_\-]*"\s*:\s*)([A-Za-z_][A-Za-z0-9_\-]*)(\s*[,}])'
)


def _quote_bare_words(s: str) -> str:
    """Wrap bare-word values in quotes when they sit between a JSON
    key colon and a comma/brace. Preserves ``true``, ``false``, ``null``
    and numbers (those are valid JSON literals already)."""
    keep = {"true", "false", "null"}

    def _sub(m: re.Match) -> str:
        prefix, value, tail = m.group(1), m.group(2), m.group(3)
        if value in keep:
            return m.group(0)
        return f'{prefix}"{value}"{tail}'

    return _BARE_VALUE_RE.sub(_sub, s)


def _excerpt_text(finding: DlpFinding | CardLeakageFinding) -> str:
    if isinstance(finding, DlpFinding):
        return "\n".join((finding.matched_excerpts or [])[:5])[:2000]
    return (finding.excerpt or "")[:2000]


def _emails_from_finding(finding: DlpFinding | CardLeakageFinding) -> list[str]:
    """Extract cleartext emails. Returns ``[]`` for DLP findings whose
    excerpts are already redaction-fingerprinted."""
    seen: set[str] = set()
    out: list[str] = []
    for email in _EMAIL_RE.findall(_excerpt_text(finding)):
        e = email.lower()
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out


def _secret_fingerprints(finding: DlpFinding | CardLeakageFinding) -> list[str]:
    """Extract redaction-fingerprint hashes from the finding's excerpts.

    DLP findings persist excerpts with their matched secret replaced by
    ``<redacted len=N sha256=H>``; that ``H`` is the SHA-256 hash of the
    matched bytes and is stable across tenants. We use it as the
    cross-org matching key so we never have to compare cleartext.
    """
    text = _excerpt_text(finding)
    return list({m.group(1) for m in _REDACTION_FP_RE.finditer(text)})


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _maybe_bump_severity(finding: DlpFinding | CardLeakageFinding, impact: str) -> str | None:
    """Return the new severity if it's HIGHER than current; else None.

    CardLeakageFinding has no ``severity`` column today — it's modelled
    instead via state-machine + auto-link to Cases. We return ``None``
    for those rows so the caller doesn't try to assign a non-existent
    column. The classifier still persists the impact level inside
    ``classification['impact_level']`` for downstream consumers.
    """
    if not impact:
        return None
    if not hasattr(finding, "severity"):
        return None
    impact = impact.strip().lower()
    if impact not in _SEVERITY_RANK:
        return None
    cur = (getattr(finding, "severity", None) or "medium").lower()
    if _SEVERITY_RANK.get(impact, 0) > _SEVERITY_RANK.get(cur, 0):
        return impact
    return None


async def _load_finding(
    db: AsyncSession, finding_id: uuid.UUID, kind: str
) -> DlpFinding | CardLeakageFinding | None:
    if kind == "dlp":
        return await db.get(DlpFinding, finding_id)
    if kind in ("card", "cards"):
        return await db.get(CardLeakageFinding, finding_id)
    return None


# ---------------------------------------------------------------- 1. classify


_CLASSIFY_SYS = (
    "You are an enterprise data-leakage triage analyst. Given a leaked "
    "excerpt and policy metadata, classify the leak. Reply with STRICT "
    "JSON only — no prose, no fences. Required keys: "
    "category (one of: pii, financial, trade_secret, source_code, credential), "
    "impact_level (one of: critical, high, medium, low), "
    "compliance (array, any of: gdpr, hipaa, pci, sox, ccpa), "
    "confidence (number between 0 and 1), "
    "rationale (string, 1-2 sentences)."
)


def _build_classify_user(finding: DlpFinding | CardLeakageFinding, kind: str) -> str:
    if kind == "dlp":
        meta = (
            f"Policy: {finding.policy_name}\n"
            f"Current severity: {finding.severity}\n"
            f"Source: {finding.source_url or finding.source_kind or 'unknown'}\n"
        )
    else:
        meta = (
            f"Card scheme: {finding.scheme}\n"
            f"Issuer: {finding.issuer or 'unknown'}\n"
            f"BIN: {finding.pan_first6} / last4 {finding.pan_last4}\n"
            f"Source: {finding.source_url or finding.source_kind or 'unknown'}\n"
        )
    return f"{meta}\nExcerpt:\n---\n{_excerpt_text(finding)}\n---"


async def _h_classify(db: AsyncSession, task: AgentTask) -> dict[str, Any]:
    payload = task.payload or {}
    finding_id = uuid.UUID(payload["finding_id"])
    kind = payload.get("kind", "dlp")
    finding = await _load_finding(db, finding_id, kind)
    if finding is None:
        return {"skipped": True, "reason": "finding not found"}

    user = _build_classify_user(finding, kind)
    text, model_id = await call_bridge(_CLASSIFY_SYS, user)
    task.model_id = model_id
    parsed = _parse_json(text) or {}

    classification = {
        "category": str(parsed.get("category", "")).strip().lower() or "pii",
        "impact_level": str(parsed.get("impact_level", "")).strip().lower() or "medium",
        "compliance": [
            str(c).strip().lower() for c in (parsed.get("compliance") or []) if str(c).strip()
        ][:6],
        "confidence": float(parsed.get("confidence") or 0.0),
        "rationale": str(parsed.get("rationale", ""))[:1000],
        "model_id": model_id,
        "raw": text[:2000] if not parsed else None,
        "classified_at": datetime.now(timezone.utc).isoformat(),
    }

    finding.classification = classification
    bumped = _maybe_bump_severity(finding, classification["impact_level"])
    if bumped and hasattr(finding, "severity"):
        finding.severity = bumped
    await db.commit()
    return {
        "finding_id": str(finding.id),
        "kind": kind,
        "classification": classification,
        "severity_bumped_to": bumped,
    }


register_handler("leakage_classify", _h_classify)


# ---------------------------------------------------------------- 2. takedown


_TAKEDOWN_SYS = (
    "You draft formal takedown / abuse notices on behalf of the affected "
    "organisation. Output Markdown only — start with a top-level heading, "
    "then sections for: Notice, Identification of the Material, Statement "
    "of Good Faith, Statement of Accuracy, Signature block. Cite DMCA "
    "17 U.S.C. § 512(c) and trade-secret protections under the DTSA "
    "(18 U.S.C. § 1836) where applicable. Do NOT include the leaked "
    "secret verbatim — refer to it by hash / fingerprint only."
)


def _site_from_url(url: str | None) -> str:
    if not url:
        return "the hosting provider"
    m = re.match(r"https?://([^/]+)", url)
    return m.group(1) if m else url


def _build_takedown_user(finding: DlpFinding | CardLeakageFinding, kind: str) -> str:
    site = _site_from_url(finding.source_url)
    if kind == "dlp":
        sev = getattr(finding, "severity", "medium")
        what = f"DLP policy '{finding.policy_name}' (severity {sev})"
    else:
        what = (
            f"a leaked payment-card record (BIN {finding.pan_first6}, "
            f"scheme {finding.scheme}, issuer {finding.issuer or 'unknown'})"
        )
    return (
        f"Draft a takedown notice addressed to {site}.\n"
        f"Material concerned: {what}\n"
        f"Source URL: {finding.source_url or 'unknown'}\n"
        f"Detected: {finding.detected_at.isoformat() if finding.detected_at else 'recently'}\n"
        f"Excerpt fingerprint (do NOT reproduce contents):\n"
        f"---\n{_excerpt_text(finding)[:400]}\n---\n"
    )


async def _h_takedown(db: AsyncSession, task: AgentTask) -> dict[str, Any]:
    payload = task.payload or {}
    finding_id = uuid.UUID(payload["finding_id"])
    kind = payload.get("kind", "dlp")
    finding = await _load_finding(db, finding_id, kind)
    if finding is None:
        return {"skipped": True, "reason": "finding not found"}

    user = _build_takedown_user(finding, kind)
    text, model_id = await call_bridge(_TAKEDOWN_SYS, user)
    task.model_id = model_id
    draft = (text or "").strip()
    finding.takedown_draft = draft[:32000]
    await db.commit()
    return {
        "finding_id": str(finding.id),
        "kind": kind,
        "draft_chars": len(draft),
        "model_id": model_id,
    }


register_handler("leakage_takedown_draft", _h_takedown)


# ---------------------------------------------------------------- 3. cross-org


_CORRELATE_SYS = (
    "You are a threat-intel analyst spotting supply-chain breaches across "
    "tenants of a managed cyber platform. Given that the same secret "
    "(PAN hash / email hash) appears in N customers' findings across M "
    "organisations, infer the probable common breach source or threat "
    "actor. Reply with STRICT JSON only. Required keys: "
    "probable_source (string), confidence (0..1), recommended_action "
    "(string), supply_chain_likelihood (one of: high, medium, low)."
)


async def _h_correlate(db: AsyncSession, task: AgentTask) -> dict[str, Any]:
    payload = task.payload or {}
    finding_id = uuid.UUID(payload["finding_id"])
    kind = payload.get("kind", "dlp")
    finding = await _load_finding(db, finding_id, kind)
    if finding is None:
        return {"skipped": True, "reason": "finding not found"}

    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    matched_findings: list[dict] = []
    distinct_orgs: set[uuid.UUID] = {finding.organization_id}

    if kind in ("card", "cards"):
        rows = (
            await db.execute(
                select(CardLeakageFinding).where(
                    and_(
                        CardLeakageFinding.pan_sha256 == finding.pan_sha256,
                        CardLeakageFinding.id != finding.id,
                        CardLeakageFinding.detected_at >= cutoff,
                    )
                )
            )
        ).scalars().all()
        for r in rows:
            distinct_orgs.add(r.organization_id)
            matched_findings.append(
                {
                    "id": str(r.id),
                    "kind": "card",
                    "organization_id": str(r.organization_id),
                    "source_url": r.source_url,
                    "detected_at": r.detected_at.isoformat() if r.detected_at else None,
                }
            )
        match_key = f"pan:{finding.pan_sha256[:12]}"
    else:
        # DLP excerpts ship with their matched values redacted to a
        # SHA-256 fingerprint. We use those fingerprints (not cleartext)
        # as the cross-tenant join key. Raw email matches still work
        # for findings that were written before redaction was added.
        fingerprints = _secret_fingerprints(finding)
        emails = _emails_from_finding(finding)
        if not fingerprints and not emails:
            finding.correlated_findings = {
                "matches": [],
                "distinct_orgs": 1,
                "skipped": "no_signal_extracted",
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }
            await db.commit()
            return {
                "finding_id": str(finding.id),
                "matches": 0,
                "reason": "no fingerprints or emails",
            }
        recent = (
            await db.execute(
                select(DlpFinding).where(
                    and_(
                        DlpFinding.id != finding.id,
                        DlpFinding.detected_at >= cutoff,
                    )
                )
            )
        ).scalars().all()
        fp_set = set(fingerprints)
        email_set = set(emails)
        for r in recent:
            r_fps = set(_secret_fingerprints(r))
            r_emails = set(_emails_from_finding(r))
            shared_fps = fp_set & r_fps
            shared_emails = email_set & r_emails
            if not (shared_fps or shared_emails):
                continue
            distinct_orgs.add(r.organization_id)
            matched_findings.append(
                {
                    "id": str(r.id),
                    "kind": "dlp",
                    "organization_id": str(r.organization_id),
                    "source_url": r.source_url,
                    "detected_at": r.detected_at.isoformat() if r.detected_at else None,
                    "shared_fingerprints": sorted(list(shared_fps))[:3],
                    "shared_emails": sorted(list(shared_emails))[:3],
                }
            )
        if fingerprints:
            match_key = f"fp:{sorted(fingerprints)[0][:16]}"
        else:
            match_key = f"emails:{','.join(sorted(emails)[:3])}"

    correlated: dict[str, Any] = {
        "match_key": match_key,
        "matches": matched_findings[:25],
        "distinct_orgs": len(distinct_orgs),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    actor_inference: dict[str, Any] | None = None
    if len(distinct_orgs) >= 2:
        user = (
            f"We see the same {('PAN' if kind in ('card','cards') else 'email')} fingerprint "
            f"in {len(matched_findings) + 1} customer findings across {len(distinct_orgs)} "
            f"distinct organisations within the last 30 days. Match key: {match_key}.\n"
            f"Sources observed: {sorted({m.get('source_url') or '?' for m in matched_findings})[:5]}.\n"
            f"Suggest the probable breach source or threat actor."
        )
        text, model_id = await call_bridge(_CORRELATE_SYS, user)
        task.model_id = model_id
        parsed = _parse_json(text) or {}
        actor_inference = {
            "probable_source": str(parsed.get("probable_source", ""))[:500],
            "confidence": float(parsed.get("confidence") or 0.0),
            "recommended_action": str(parsed.get("recommended_action", ""))[:500],
            "supply_chain_likelihood": str(
                parsed.get("supply_chain_likelihood", "medium")
            ).lower(),
            "model_id": model_id,
        }
        correlated["actor_inference"] = actor_inference

        # Create a cross-org Alert. One per match_key per origin org so we
        # don't spam — dedup via title prefix.
        title = f"Cross-org leak correlation: {match_key} ({len(distinct_orgs)} orgs)"
        existing_alert = (
            await db.execute(
                select(Alert).where(
                    and_(
                        Alert.organization_id == finding.organization_id,
                        Alert.title == title,
                    )
                )
            )
        ).scalar_one_or_none()
        if existing_alert is None:
            db.add(
                Alert(
                    organization_id=finding.organization_id,
                    category=ThreatCategory.DATA_BREACH.value,
                    severity=("high" if len(distinct_orgs) >= 3 else "medium"),
                    status=AlertStatus.NEW.value,
                    title=title,
                    summary=(
                        f"The same leaked artefact appears in findings across "
                        f"{len(distinct_orgs)} organisations. Likely common breach "
                        f"source: {actor_inference['probable_source'][:200] or 'unknown'}."
                    ),
                    details={
                        "match_key": match_key,
                        "tags": ["cross_org_leak"],
                        "matches": matched_findings[:25],
                        "actor_inference": actor_inference,
                        "origin_finding_id": str(finding.id),
                        "origin_finding_kind": kind,
                    },
                    confidence=actor_inference["confidence"],
                    agent_reasoning=actor_inference["probable_source"],
                    recommended_actions=[actor_inference["recommended_action"]]
                    if actor_inference["recommended_action"]
                    else None,
                )
            )

    finding.correlated_findings = correlated
    await db.commit()
    return {
        "finding_id": str(finding.id),
        "kind": kind,
        "matches": len(matched_findings),
        "distinct_orgs": len(distinct_orgs),
        "alerted": actor_inference is not None,
    }


register_handler("leakage_correlate_cross_org", _h_correlate)


# ---------------------------------------------------------------- 4. exec briefing


_BRIEFING_SYS = (
    "You are writing a daily DLP briefing for a CISO. Output Markdown "
    "only. Required sections, in order: ## Headline, ## Volume Trend, "
    "## Top Categories, ## Top 3 Urgent Findings (with bracketed "
    "finding IDs), ## Recommended Actions. Keep under 400 words. Be "
    "direct; CISOs skim."
)


async def _h_briefing(db: AsyncSession, task: AgentTask) -> dict[str, Any]:
    payload = task.payload or {}
    org_id = uuid.UUID(payload["org_id"])
    window_hours = int(payload.get("window_hours") or 24)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)

    dlp_rows = (
        await db.execute(
            select(DlpFinding).where(
                and_(
                    DlpFinding.organization_id == org_id,
                    DlpFinding.detected_at >= cutoff,
                )
            ).order_by(DlpFinding.detected_at.desc()).limit(200)
        )
    ).scalars().all()
    card_rows = (
        await db.execute(
            select(CardLeakageFinding).where(
                and_(
                    CardLeakageFinding.organization_id == org_id,
                    CardLeakageFinding.detected_at >= cutoff,
                )
            ).order_by(CardLeakageFinding.detected_at.desc()).limit(200)
        )
    ).scalars().all()

    if not dlp_rows and not card_rows:
        return {"org_id": str(org_id), "skipped": "no_findings"}

    severity_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    urgent: list[tuple[str, str, str, str]] = []  # (id, kind, severity, summary)
    for r in dlp_rows:
        sev = (r.severity or "medium").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        cat = ((r.classification or {}).get("category") or "uncategorised")
        category_counts[cat] = category_counts.get(cat, 0) + 1
        if sev in ("critical", "high"):
            urgent.append(
                (str(r.id), "dlp", sev, f"{r.policy_name} @ {r.source_url or r.source_kind or '—'}")
            )
    for r in card_rows:
        # CardLeakageFinding has no ``severity`` column. Derive an
        # impact level from the agent classification when available;
        # otherwise treat every card hit as ``high`` per the auto-link
        # contract in src/leakage/cards.py.
        cls = (r.classification or {}).get("impact_level") if r.classification else None
        sev = (cls or "high").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        category_counts["financial"] = category_counts.get("financial", 0) + 1
        if sev in ("critical", "high"):
            urgent.append(
                (str(r.id), "card", sev, f"BIN {r.pan_first6} ({r.scheme}) @ {r.source_url or '—'}")
            )

    summary_input = {
        "window_hours": window_hours,
        "total_findings": len(dlp_rows) + len(card_rows),
        "dlp_count": len(dlp_rows),
        "card_count": len(card_rows),
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "urgent": urgent[:10],
    }
    user = (
        "Aggregated counts (JSON):\n"
        f"{json.dumps(summary_input, default=str)}\n\n"
        "Write the briefing now."
    )
    text, model_id = await call_bridge(_BRIEFING_SYS, user)
    task.model_id = model_id
    markdown = (text or "").strip()

    db.add(
        NotificationInboxItem(
            organization_id=org_id,
            event_kind="leakage_daily_briefing",
            severity="info",
            title=f"Daily DLP briefing — {len(dlp_rows) + len(card_rows)} findings",
            summary=markdown[:8000],
            link_path="/leakage",
            payload={
                "kind": "leakage_daily_briefing",
                "window_hours": window_hours,
                "totals": summary_input,
                "model_id": model_id,
            },
        )
    )
    await db.commit()
    return {
        "org_id": str(org_id),
        "total_findings": summary_input["total_findings"],
        "model_id": model_id,
        "briefing_chars": len(markdown),
    }


register_handler("leakage_exec_briefing", _h_briefing)


# ---------------------------------------------------------------- 5. policy tune


_BENIGN_CORPUS_PATH = Path(__file__).resolve().parents[2] / "leakage" / "_benign_corpus.txt"


def _load_benign_corpus() -> str:
    try:
        return _BENIGN_CORPUS_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


_TUNE_SYS = (
    "You are a regex hygiene reviewer. The given pattern matched "
    "benign Wikipedia-style prose at a high false-positive rate. "
    "Suggest a tighter regex that targets the policy's stated intent. "
    "Reply STRICT JSON only. Required keys: "
    "suggested_pattern (string, valid Python re), "
    "rationale (string, 1-2 sentences), "
    "expected_fp_reduction (one of: large, moderate, small)."
)


async def _h_policy_tune(db: AsyncSession, task: AgentTask) -> dict[str, Any]:
    payload = task.payload or {}
    org_id_raw = payload.get("organization_id")
    org_filter = uuid.UUID(org_id_raw) if org_id_raw else None

    corpus = _load_benign_corpus()
    if not corpus:
        return {"skipped": True, "reason": "benign corpus missing"}

    q = select(DlpPolicy).where(DlpPolicy.enabled == True)  # noqa: E712
    if org_filter:
        q = q.where(DlpPolicy.organization_id == org_filter)
    policies = (await db.execute(q)).scalars().all()
    if not policies:
        return {"reviewed": 0, "tuned": 0}

    # Rough FP rate = lines that match / total lines.
    lines = [ln for ln in corpus.splitlines() if ln.strip()]
    total_lines = max(1, len(lines))

    # Lazy import to avoid pulling the regex engine into module load.
    from src.leakage.dlp import evaluate_policy

    reviewed = 0
    tuned = 0
    suggestions: list[dict] = []
    for policy in policies:
        reviewed += 1
        # evaluate per-line so an early match doesn't mask spread
        match_lines = 0
        sample_match: str | None = None
        for ln in lines:
            ex = evaluate_policy(policy, ln)
            if ex:
                match_lines += 1
                if sample_match is None:
                    sample_match = ex[0]
        fp_rate = match_lines / total_lines
        if fp_rate < 0.20:
            continue

        user = (
            f"Policy name: {policy.name}\n"
            f"Policy kind: {policy.kind}\n"
            f"Policy description: {policy.description or '(none)'}\n"
            f"Current pattern: {policy.pattern}\n"
            f"False-positive rate against benign corpus: {fp_rate:.0%}\n"
            f"Sample match: {sample_match or '(unavailable)'}\n"
        )
        text, model_id = await call_bridge(_TUNE_SYS, user)
        parsed = _parse_json(text) or {}
        suggested = str(parsed.get("suggested_pattern", "")).strip()
        rationale = str(parsed.get("rationale", "")).strip()
        if not suggested:
            continue

        suggestion = {
            "policy_id": str(policy.id),
            "policy_name": policy.name,
            "current_pattern": policy.pattern,
            "fp_rate": round(fp_rate, 3),
            "suggested_pattern": suggested[:1000],
            "rationale": rationale[:500],
            "expected_fp_reduction": str(parsed.get("expected_fp_reduction", "")).lower(),
            "model_id": model_id,
        }
        suggestions.append(suggestion)
        tuned += 1

        # Surface the suggestion in the operator's inbox — non-destructive.
        db.add(
            NotificationInboxItem(
                organization_id=policy.organization_id,
                event_kind="leakage_policy_tune_suggestion",
                severity="warning",
                title=f"DLP policy '{policy.name}' has FP rate {fp_rate:.0%}",
                summary=(
                    f"Suggested replacement pattern:\n\n```\n{suggested[:500]}\n```\n\n"
                    f"Rationale: {rationale[:400]}"
                ),
                link_path="/leakage#policies",
                payload=suggestion,
            )
        )
    await db.commit()
    return {"reviewed": reviewed, "tuned": tuned, "suggestions": suggestions}


register_handler("leakage_policy_tune", _h_policy_tune)


__all__: list[str] = []
