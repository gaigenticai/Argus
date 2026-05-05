"""DMARC360 Bridge-LLM agent handlers.

Four agents fan out from the RUA / RUF ingest pipelines:

    1. ``dmarc_alignment_rca``        — root-cause one misaligned RUA record.
    2. ``dmarc_policy_rollout_plan``  — author the next progression step.
    3. ``dmarc_spoof_campaign_detect``— classify a spike of RUF events.
    4. ``dmarc_lookalike_detect``     — flag spoof Return-Path domains.

Each registers via ``register_handler``; the worker dispatcher picks
them up through ``src.agents.governance_handlers``.

Bridge prompts always demand strict JSON — we parse leniently and
fall back to ``{}`` if the LLM returns prose.
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.dmarc.lookalike import generate as gen_lookalikes
from src.dmarc.lookalike import is_lookalike
from src.llm.agent_queue import call_bridge, register_handler
from src.models.agent_task import AgentTask
from src.models.dmarc import DmarcReport, DmarcReportRecord
from src.models.dmarc_forensic import DmarcForensicReport
from src.models.notification_inbox import NotificationInboxItem
from src.models.threat import Alert

_logger = logging.getLogger(__name__)


# ----------------------------------------------------------- helpers


def _coerce_json(text: str | None) -> dict[str, Any]:
    """Best-effort JSON extraction from a Bridge response.

    Bridge sometimes wraps JSON in code-fences or adds preamble; we
    take the longest substring that parses cleanly.
    """
    if not text:
        return {}
    text = text.strip()
    # 1. Whole text
    try:
        v = json.loads(text)
        if isinstance(v, dict):
            return v
    except Exception:  # noqa: BLE001
        pass
    # 2. Strip code fences
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, flags=re.S | re.I)
    if fenced:
        try:
            v = json.loads(fenced.group(1).strip())
            if isinstance(v, dict):
                return v
        except Exception:  # noqa: BLE001
            pass
    # 3. First {...} block
    m = re.search(r"\{.*\}", text, flags=re.S)
    if m:
        try:
            v = json.loads(m.group(0))
            if isinstance(v, dict):
                return v
        except Exception:  # noqa: BLE001
            pass
    return {}


def _short_uuid(s: str | uuid.UUID) -> str:
    s = str(s)
    return s[:8] if len(s) >= 8 else s


# ----------------------------------------------------------- 1. RCA


async def _handle_alignment_rca(db: AsyncSession, task: AgentTask) -> dict[str, Any]:
    p = task.payload or {}
    report_id = p.get("report_id")
    src_ip = p.get("source_ip") or "?"
    header_from = p.get("header_from") or "?"
    spf_res = p.get("spf_result") or "n/a"
    dkim_res = p.get("dkim_result") or "n/a"

    system = (
        "You are a DMARC SME. Diagnose the root cause of an alignment "
        "failure observed in an aggregate DMARC report. Respond with a "
        "single JSON object only (no prose, no fences). Schema:\n"
        '{"cause": "forwarding|saas_misconfig|spoof|selector_drift|other",'
        ' "recommendation": "<<one short paragraph>>",'
        ' "references": ["<<rfc/url/...>>"]}'
    )
    user = (
        f"Source IP {src_ip} sent mail purporting to be from {header_from}. "
        f"SPF result: {spf_res}; DKIM result: {dkim_res}. "
        f"SPF aligned: {p.get('spf_aligned')}; DKIM aligned: {p.get('dkim_aligned')}. "
        "Cross-reference whether this is a forwarding hop, a SaaS provider "
        "(Zendesk/SendGrid/Mailchimp/Salesforce/Atlassian/etc.), or a spoofer. "
        "Recommend a concrete remediation: add SPF include, fix DKIM selector, "
        "block source, or no-op."
    )
    text, model_id = await call_bridge(system, user)
    payload_out = _coerce_json(text)
    if not payload_out:
        payload_out = {
            "cause": "other",
            "recommendation": (text or "Bridge returned no parseable JSON").strip()[:600],
            "references": [],
        }

    # Persist into DmarcReport.rca (keyed by source_ip).
    if report_id:
        try:
            report = await db.get(DmarcReport, uuid.UUID(report_id))
            if report is not None:
                rca = dict(report.rca or {})
                rca[str(src_ip)] = {
                    **payload_out,
                    "header_from": header_from,
                    "model_id": model_id,
                    "at": datetime.now(timezone.utc).isoformat(),
                }
                report.rca = rca
                await db.flush()
        except Exception:  # noqa: BLE001
            _logger.exception("dmarc_alignment_rca: persist failed")

    if model_id and not task.model_id:
        task.model_id = model_id
    return payload_out


register_handler("dmarc_alignment_rca", _handle_alignment_rca)


# ----------------------------------------------------------- 2. Rollout planner


async def _handle_policy_rollout_plan(db: AsyncSession, task: AgentTask) -> dict[str, Any]:
    """Drafts the next-stage rollout plan in Markdown."""
    p = task.payload or {}
    domain = (p.get("domain") or "").lower()
    org_id_raw = p.get("organization_id")
    if not domain or not org_id_raw:
        return {"error": "missing domain or organization_id"}
    organization_id = uuid.UUID(org_id_raw)

    # Latest report
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    latest_q = (
        select(DmarcReport)
        .where(
            and_(
                DmarcReport.organization_id == organization_id,
                DmarcReport.domain == domain,
            )
        )
        .order_by(DmarcReport.date_begin.desc())
        .limit(1)
    )
    latest = (await db.execute(latest_q)).scalar_one_or_none()
    current_policy = latest.policy_p if latest else "none"

    # 30-d alignment %
    agg_q = select(
        func.coalesce(func.sum(DmarcReportRecord.count), 0),
        func.coalesce(
            func.sum(
                case(
                    (
                        (DmarcReportRecord.spf_aligned.is_(True))
                        | (DmarcReportRecord.dkim_aligned.is_(True)),
                        DmarcReportRecord.count,
                    ),
                    else_=0,
                )
            ),
            0,
        ),
    ).where(
        and_(
            DmarcReportRecord.organization_id == organization_id,
            DmarcReportRecord.domain == domain,
            DmarcReportRecord.created_at >= cutoff,
        )
    )
    try:
        total, passed = (await db.execute(agg_q)).one()
    except Exception:  # noqa: BLE001
        total, passed = 0, 0
    pct = round(100.0 * float(passed) / float(total), 2) if total else 0.0

    # RUF count last 30d
    ruf_count = (
        await db.execute(
            select(func.count(DmarcForensicReport.id)).where(
                and_(
                    DmarcForensicReport.organization_id == organization_id,
                    DmarcForensicReport.domain == domain,
                    DmarcForensicReport.received_at >= cutoff,
                )
            )
        )
    ).scalar_one() or 0

    system = (
        "You are a deliverability engineer authoring a DMARC rollout plan "
        "aligned with M3AAWG Sender BCP. Output GitHub-flavoured Markdown "
        "only — no JSON, no preamble. Sections required: 'Current state', "
        "'Recommended next stage', 'Predicted impact', 'Timeline', "
        "'Rollback plan', 'Validation checks'."
    )
    user = (
        f"Domain: {domain}\n"
        f"Current policy: p={current_policy}\n"
        f"30-day alignment pass rate: {pct}%\n"
        f"30-day RUF (forensic) count: {ruf_count}\n"
        f"30-day total messages observed: {total}\n"
        "Draft the next-stage rollout plan."
    )
    text, model_id = await call_bridge(system, user)
    md = (text or "").strip()
    if not md:
        md = (
            f"## Rollout plan for {domain}\n\nBridge returned no content; "
            "manually review."
        )

    if latest is not None:
        summary = dict(latest.agent_summary or {})
        summary["rollout_plan"] = {
            "markdown": md,
            "model_id": model_id,
            "at": datetime.now(timezone.utc).isoformat(),
            "alignment_pct": pct,
            "ruf_count": int(ruf_count),
        }
        latest.agent_summary = summary
        await db.flush()

    if model_id and not task.model_id:
        task.model_id = model_id
    return {
        "markdown": md,
        "alignment_pct": pct,
        "current_policy": current_policy,
        "ruf_count": int(ruf_count),
    }


register_handler("dmarc_policy_rollout_plan", _handle_policy_rollout_plan)


# ----------------------------------------------------------- 3. Spoof campaign detector


async def _handle_spoof_campaign_detect(db: AsyncSession, task: AgentTask) -> dict[str, Any]:
    p = task.payload or {}
    org_id_raw = p.get("organization_id")
    source_ip = p.get("source_ip")
    domain = p.get("domain")
    sample_count = int(p.get("count") or 0)
    if not org_id_raw or not source_ip:
        return {"error": "missing inputs"}
    organization_id = uuid.UUID(org_id_raw)

    system = (
        "You are an email-threat analyst. A burst of DMARC forensic "
        "reports was just observed. Classify it. Respond with JSON only:\n"
        '{"verdict": "misconfig|targeted_attack|botnet|noise",'
        ' "confidence": 0..1,'
        ' "attribution_hints": ["..."],'
        ' "recommended_actions": ["..."]}'
    )
    user = (
        f"Organisation: {organization_id}\n"
        f"Brand domain: {domain}\n"
        f"Source IP responsible for the spike: {source_ip}\n"
        f"Failed-message count in the last hour: {sample_count}\n"
        "Distinguish misconfiguration (one SaaS forgot DKIM) vs a "
        "targeted attack (low-volume against many recipients) vs botnet "
        "(many IPs, high volume, scattered)."
    )
    text, model_id = await call_bridge(system, user)
    out = _coerce_json(text)
    verdict = (out.get("verdict") or "noise").lower()

    if verdict in {"targeted_attack", "botnet"}:
        # Create an Alert so the SOC sees it.
        alert = Alert(
            organization_id=organization_id,
            category="phishing",
            severity="high" if verdict == "botnet" else "medium",
            status="new",
            title=f"DMARC spoof campaign — {domain or source_ip}",
            summary=(
                f"Bridge classified a RUF burst from {source_ip} ({sample_count} "
                f"messages last hour) as {verdict}."
            ),
            details={
                "source_ip": source_ip,
                "domain": domain,
                "verdict": verdict,
                "confidence": out.get("confidence"),
                "attribution_hints": out.get("attribution_hints", []),
                "recommended_actions": out.get("recommended_actions", []),
            },
            confidence=float(out.get("confidence") or 0.5),
            agent_reasoning=text or "",
            recommended_actions=out.get("recommended_actions", []) or None,
        )
        db.add(alert)
        await db.flush()

    if model_id and not task.model_id:
        task.model_id = model_id
    return out or {"verdict": verdict}


register_handler("dmarc_spoof_campaign_detect", _handle_spoof_campaign_detect)


# ----------------------------------------------------------- 4. Lookalike detector


async def _handle_lookalike_detect(db: AsyncSession, task: AgentTask) -> dict[str, Any]:
    p = task.payload or {}
    forensic_id = p.get("forensic_id")
    brand_domain = (p.get("domain") or "").lower()
    spoof_candidates: list[str] = []

    # Brand may be the same as the reported domain (common). We compare
    # the spoof's Return-Path / mail-from / spf-domain against the
    # brand permutation set.
    for key in ("original_mail_from", "spf_domain", "dkim_domain"):
        v = p.get(key) or ""
        if "@" in v:
            v = v.split("@", 1)[1]
        v = v.strip().lower().lstrip(".")
        if v:
            spoof_candidates.append(v)

    matched: list[str] = []
    for cand in spoof_candidates:
        if cand and cand != brand_domain and is_lookalike(cand, brand_domain):
            matched.append(cand)

    if not matched:
        return {"matched": [], "reason": "no permutation match"}

    spoof_domain = matched[0]
    sample_perm_set = ", ".join(gen_lookalikes(brand_domain, cap=10))

    system = (
        "You are a brand-protection analyst. A spoof domain was detected "
        "as a lookalike of the brand domain. Respond with JSON only:\n"
        '{"severity":"low|medium|high|critical",'
        ' "recommendations": ["takedown_url", "bimi", "user_awareness"],'
        ' "rationale": "<<short paragraph>>"}'
    )
    user = (
        f"Brand domain: {brand_domain}\n"
        f"Detected spoof domain (matched permutation): {spoof_domain}\n"
        f"Permutation cohort sample: {sample_perm_set}\n"
        f"Other auth fields seen: {spoof_candidates}\n"
        "Recommend takedown channel, BIMI, user-awareness comms."
    )
    text, model_id = await call_bridge(system, user)
    out = _coerce_json(text) or {
        "severity": "medium",
        "recommendations": ["takedown_url", "user_awareness"],
        "rationale": (text or "")[:400],
    }

    org_id = (
        uuid.UUID(p.get("organization_id"))
        if p.get("organization_id")
        else task.organization_id
    )

    # Persist back onto the forensic row + raise an inbox notification.
    if forensic_id:
        try:
            row = await db.get(DmarcForensicReport, uuid.UUID(forensic_id))
            if row is not None:
                summary = dict(row.agent_summary or {})
                summary["lookalike"] = {
                    **out,
                    "matched": matched,
                    "model_id": model_id,
                    "at": datetime.now(timezone.utc).isoformat(),
                }
                row.agent_summary = summary
        except Exception:  # noqa: BLE001
            _logger.exception("dmarc_lookalike_detect: persist failed")

    if org_id is not None:
        try:
            inbox = NotificationInboxItem(
                organization_id=org_id,
                event_kind="dmarc_lookalike_detected",
                severity=str(out.get("severity") or "medium"),
                title=f"Lookalike spoof: {spoof_domain}",
                summary=str(out.get("rationale") or "")[:1000],
                link_path="/dmarc",
                payload={
                    "brand_domain": brand_domain,
                    "spoof_domain": spoof_domain,
                    "matched": matched,
                    "recommendations": out.get("recommendations", []),
                    "forensic_id": forensic_id,
                },
            )
            db.add(inbox)
            await db.flush()
        except Exception:  # noqa: BLE001
            _logger.exception("lookalike inbox-write failed")

    if model_id and not task.model_id:
        task.model_id = model_id
    return {**out, "matched": matched, "spoof_domain": spoof_domain}


register_handler("dmarc_lookalike_detect", _handle_lookalike_detect)


__all__ = [
    "_handle_alignment_rca",
    "_handle_policy_rollout_plan",
    "_handle_spoof_campaign_detect",
    "_handle_lookalike_detect",
]
