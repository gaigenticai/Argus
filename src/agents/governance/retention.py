"""Retention Bridge-LLM agents.

Six handlers, all registered via ``src.llm.agent_queue.register_handler``:

  * ``retention_dsar_scan``           DSAR Responder — scan phase. Walks
                                      every PII-bearing table for rows
                                      matching the subject, persists
                                      matched_tables + match_summary.

  * ``retention_dsar_respond``        DSAR Responder — letter phase. Calls
                                      Bridge with regulation-specific
                                      template; persists draft_response.

  * ``retention_policy_conflict_detect``
                                      Conflict Detector. Bridge proposes a
                                      resolution; surfaced as a
                                      notification_inbox row.

  * ``retention_regulation_translate``
                                      (Optional async path; the synchronous
                                      version is used by /translate-regulation
                                      endpoint, this handler exists so the
                                      same prompt can be re-used by other
                                      callers via the queue.)

  * ``retention_preserve_knowledge``  Pre-Purge Knowledge Preserver. Reads
                                      the about-to-be-deleted rows and
                                      writes a PII-free learnings_log row.

  * ``retention_attestation_generate``
                                      Compliance Attestation Generator.
                                      Aggregates policy + cleanup +
                                      legal-hold + DSAR stats, asks Bridge
                                      to draft a Markdown report, persists
                                      it as a learnings_log row with
                                      source_table='attestation'.

All Bridge prompts request strict JSON (when applicable) and parse leniently.
Every handler returns a ``dict`` so the dispatcher can persist it as
``AgentTask.result``.
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, or_, select, text as _text
from sqlalchemy.ext.asyncio import AsyncSession

from src.llm.agent_queue import call_bridge, register_handler
from src.models.agent_task import AgentTask
from src.models.dsar import DsarRequest
from src.models.intel import RetentionPolicy
from src.models.learnings import LearningsLog
from src.models.notification_inbox import NotificationInboxItem

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------- helpers


def _parse_json(text: str) -> dict[str, Any] | None:
    """Lenient JSON parse — handles markdown-fenced and prose-wrapped outputs."""
    if not text:
        return None
    s = text.strip()
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    cleaned = re.sub(r"^```(?:json)?\s*", "", s)
    cleaned = re.sub(r"\s*```$", "", cleaned.strip())
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    first = s.find("{")
    last = s.rfind("}")
    if first != -1 and last > first:
        try:
            return json.loads(s[first : last + 1])
        except json.JSONDecodeError:
            pass
    return None


# ----------------------------------------------------------- 1. DSAR scan


# Catalog of (table, columns_to_match_against). The match condition is
# ``column ILIKE :needle`` joined with OR. We use parameterised SQL so the
# subject identifier never gets concatenated into SQL.
#
# The shape `(table, [text_columns], [jsonb_columns])` lets us search both
# scalar columns (e.g. raw_intel.author) and JSONB blobs that may contain
# the subject indirectly (e.g. alerts.details).
_DSAR_TARGETS: list[tuple[str, list[str], list[str]]] = [
    # (table_name, text_columns, jsonb_columns)
    ("raw_intel", ["author", "source_url", "title", "content"], ["raw_data"]),
    ("alerts", ["title", "summary", "agent_reasoning", "analyst_notes"],
     ["details", "matched_entities"]),
    ("news_articles", ["title", "summary", "url", "author"], ["raw"]),
    ("dmarc_reports", ["domain", "org_name"], ["parsed"]),
    ("dlp_findings", ["source_url", "policy_name"], ["classification"]),
    ("card_leakage_findings", ["source_url", "issuer", "excerpt"], []),
    ("audit_logs",
     ["resource_type", "resource_id", "user_agent", "ip_address"],
     ["details", "before_state", "after_state"]),
    ("evidence_blobs",
     ["original_filename", "description", "capture_source"],
     ["extra"]),
]
# Tables in _DSAR_TARGETS that have NO organization_id column. We skip the
# org filter for these. (raw_intel + news_articles fall in this set.)
_DSAR_NO_ORG_TABLES: set[str] = {"raw_intel", "news_articles"}


def _build_subject_predicates(
    text_cols: list[str],
    jsonb_cols: list[str],
    *,
    email: str | None,
    name: str | None,
    phone: str | None,
    other: str | None,
) -> tuple[str, dict[str, str]]:
    """Construct an OR-joined predicate over the given text/jsonb columns.

    Returns (sql_fragment, params). All bind values are bound — no string
    concat of user input. Column identifiers are NOT bind-able in SQL so
    they're whitelisted by the caller.
    """
    needles: dict[str, str] = {}
    if email:
        needles["needle_email"] = f"%{email}%"
    if name:
        needles["needle_name"] = f"%{name}%"
    if phone:
        needles["needle_phone"] = f"%{phone}%"
    if other:
        needles["needle_other"] = f"%{other}%"

    if not needles:
        return "FALSE", {}

    fragments: list[str] = []
    for col in text_cols:
        # quote identifier literally — text_cols come from our whitelist,
        # never user input.
        for needle_param in needles.keys():
            fragments.append(f"{col} ILIKE :{needle_param}")
    for col in jsonb_cols:
        # JSONB ::text cast lets us ILIKE-search any string anywhere in
        # the document. Crude but effective — DSAR scans aren't hot path.
        for needle_param in needles.keys():
            fragments.append(f"({col})::text ILIKE :{needle_param}")
    if not fragments:
        return "FALSE", {}
    return "(" + " OR ".join(fragments) + ")", needles


async def _h_dsar_scan(db: AsyncSession, task: AgentTask) -> dict[str, Any]:
    payload = task.payload or {}
    dsar_id = uuid.UUID(payload["dsar_id"])
    req = await db.get(DsarRequest, dsar_id)
    if req is None:
        return {"skipped": True, "reason": "DSAR not found"}

    email = (req.subject_email or "").strip().lower() or None
    name = (req.subject_name or "").strip() or None
    phone = (req.subject_phone or "").strip() or None
    other = (req.subject_id_other or "").strip() or None

    matched_tables: list[str] = []
    summary: dict[str, dict] = {}
    grand_total = 0

    for table, text_cols, jsonb_cols in _DSAR_TARGETS:
        # Each table runs in its own SAVEPOINT — a missing column /
        # missing table on a partially-migrated DB must not poison the
        # outer transaction (which holds the row-locked DsarRequest).
        try:
            async with db.begin_nested():
                await db.execute(_text(f"SELECT 1 FROM {table} LIMIT 1"))
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "dsar_scan: table %s unavailable (%s); skipping",
                table, type(exc).__name__,
            )
            continue

        predicate, params = _build_subject_predicates(
            text_cols, jsonb_cols,
            email=email, name=name, phone=phone, other=other,
        )
        if predicate == "FALSE":
            continue

        bind = dict(params)
        if table in _DSAR_NO_ORG_TABLES:
            org_clause = ""
        else:
            org_clause = " AND organization_id = :org_id"
            bind["org_id"] = req.organization_id

        cnt = 0
        try:
            async with db.begin_nested():
                count_sql = _text(
                    f"SELECT COUNT(*) FROM {table} "
                    f"WHERE {predicate}{org_clause}"
                )
                cnt = int((await db.execute(count_sql, bind)).scalar() or 0)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "dsar_scan: count on %s failed (%s); skipping",
                table, type(exc).__name__,
            )
            continue

        if cnt <= 0:
            continue

        sample_ids: list[str] = []
        try:
            async with db.begin_nested():
                sample_sql = _text(
                    f"SELECT id FROM {table} "
                    f"WHERE {predicate}{org_clause} "
                    f"ORDER BY 1 LIMIT 5"
                )
                sample_ids = [
                    str(r[0])
                    for r in (await db.execute(sample_sql, bind)).all()
                ]
        except Exception:  # noqa: BLE001
            pass

        matched_tables.append(table)
        summary[table] = {
            "count": cnt,
            "sample_ids": sample_ids,
            "matched_columns": text_cols + jsonb_cols,
        }
        grand_total += cnt

    req.matched_tables = matched_tables
    req.match_summary = summary
    req.matched_row_count = grand_total
    req.status = "ready_for_review"
    await db.commit()

    return {
        "dsar_id": str(req.id),
        "matched_tables": matched_tables,
        "matched_row_count": grand_total,
    }


register_handler("retention_dsar_scan", _h_dsar_scan)


# ---------------------------------------------------- 2. DSAR letter draft


_DSAR_RESPOND_SYS = (
    "You draft formal Data Subject Access Request response letters on "
    "behalf of the controller. Output Markdown only — start with a top-"
    "level heading, then sections in this order: Confirmation of Scope, "
    "What We Hold (tables and counts only — NEVER the underlying PII), "
    "Action Taken or Refused (with rationale), Regulatory Citation, "
    "Signature Block. Be precise; cite GDPR articles by number, CCPA "
    "sections by §, HIPAA by §164.x. The reply is the entire letter — "
    "no preamble, no commentary."
)


def _regulation_citation(regulation: str | None, request_type: str) -> str:
    if not regulation:
        return "GDPR Art.15 / CCPA §1798.100"
    r = regulation.lower()
    if "gdpr" in r:
        if request_type == "erasure":
            return "GDPR Art.17 (Right to Erasure)"
        if request_type == "portability":
            return "GDPR Art.20 (Right to Data Portability)"
        if request_type == "rectification":
            return "GDPR Art.16 (Right to Rectification)"
        if request_type == "restriction":
            return "GDPR Art.18 (Right to Restriction of Processing)"
        return "GDPR Art.15 (Right of Access)"
    if "ccpa" in r:
        if request_type == "erasure":
            return "CCPA §1798.105 (Right to Delete)"
        return "CCPA §1798.100 (Right to Know)"
    if "hipaa" in r:
        return "HIPAA §164.524 (Right of Access)"
    return regulation.upper()


async def _h_dsar_respond(db: AsyncSession, task: AgentTask) -> dict[str, Any]:
    payload = task.payload or {}
    dsar_id = uuid.UUID(payload["dsar_id"])
    req = await db.get(DsarRequest, dsar_id)
    if req is None:
        return {"skipped": True, "reason": "DSAR not found"}

    citation = _regulation_citation(req.regulation, req.request_type)
    holdings_block = "\n".join(
        f"- `{tbl}`: {info.get('count', 0)} record(s)"
        for tbl, info in (req.match_summary or {}).items()
    ) or "- No personal data found in our systems."

    user_prompt = (
        f"Draft a {req.regulation or 'GDPR'} response letter for a "
        f"{req.request_type} request.\n"
        f"Subject identifier (HASHED — do not echo verbatim): "
        f"email_present={bool(req.subject_email)}, "
        f"name_present={bool(req.subject_name)}, "
        f"phone_present={bool(req.subject_phone)}.\n"
        f"Holdings (counts only, NO underlying values):\n{holdings_block}\n"
        f"Total rows located: {req.matched_row_count}.\n"
        f"Statutory citation: {citation}.\n"
        f"Statutory deadline: "
        f"{req.deadline_at.isoformat() if req.deadline_at else 'N/A'}.\n"
    )

    text, model_id = await call_bridge(_DSAR_RESPOND_SYS, user_prompt)
    task.model_id = model_id
    draft = (text or "").strip()
    req.draft_response = draft[:32000]
    if req.status == "received":
        req.status = "ready_for_review"
    await db.commit()

    return {
        "dsar_id": str(req.id),
        "draft_chars": len(draft),
        "model_id": model_id,
    }


register_handler("retention_dsar_respond", _h_dsar_respond)


# -------------------------------------------------- 3. policy conflict


_CONFLICT_SYS = (
    "You are a data retention compliance reviewer. Given a single "
    "conflict between the operator's retention policy and reality, "
    "suggest a concrete resolution. Output STRICT JSON only — no prose, "
    "no fences. Required keys: recommendation (string, 1-3 sentences), "
    "suggested_policy_changes (object: {field: new_value}; valid fields "
    "are alerts_days, audit_logs_days, raw_intel_days, iocs_days, "
    "deletion_mode, compliance_mappings), severity (one of: info, "
    "warning, critical)."
)


async def _h_conflict_detect(db: AsyncSession, task: AgentTask) -> dict[str, Any]:
    payload = task.payload or {}
    kind = payload.get("kind", "unknown")
    policy_id = payload.get("policy_id")

    user_prompt = (
        f"Conflict kind: {kind}\n"
        f"Context (JSON):\n{json.dumps(payload, default=str)}\n\n"
        "Suggest a resolution."
    )
    text, model_id = await call_bridge(_CONFLICT_SYS, user_prompt)
    task.model_id = model_id
    parsed = _parse_json(text) or {}

    resolution = {
        "recommendation": str(parsed.get("recommendation", ""))[:1000],
        "suggested_policy_changes": parsed.get("suggested_policy_changes") or {},
        "severity": str(parsed.get("severity", "warning")).lower(),
        "model_id": model_id,
    }
    if resolution["severity"] not in ("info", "warning", "critical"):
        resolution["severity"] = "warning"

    # Surface to compliance officers via the inbox.
    org_id = task.organization_id
    if org_id is None:
        # Conflict-detect is org-scoped, but legal-hold scans can be on a
        # global policy with no org. Pin to the policy's org if we can.
        if policy_id:
            policy = await db.get(RetentionPolicy, uuid.UUID(policy_id))
            if policy and policy.organization_id:
                org_id = policy.organization_id
    if org_id is None:
        # No org → store under a sentinel; any null-org would fail the
        # NOT NULL constraint on notification_inbox.organization_id. Use
        # a synthetic dropdown by deferring.
        await db.commit()
        return {
            "conflict_kind": kind,
            "skipped": "no_organization",
            "resolution": resolution,
        }

    title = {
        "framework_window_too_short": "Retention window below regulatory minimum",
        "stale_legal_hold": "Stale legal-hold rows",
        "open_cases_at_risk": "Open cases would be impacted by retention cleanup",
    }.get(kind, "Retention/compliance conflict")

    summary = (
        f"**Recommendation**\n\n{resolution['recommendation']}\n\n"
        f"**Conflict context**\n\n```json\n"
        f"{json.dumps(payload, default=str, indent=2)}\n```"
    )

    db.add(
        NotificationInboxItem(
            organization_id=org_id,
            event_kind="retention_policy_conflict",
            severity=resolution["severity"],
            title=title,
            summary=summary[:8000],
            link_path="/retention",
            payload={
                "kind": kind,
                "context": payload,
                "resolution": resolution,
            },
        )
    )
    await db.commit()
    return {
        "conflict_kind": kind,
        "resolution": resolution,
        "alerted_org": str(org_id),
    }


register_handler("retention_policy_conflict_detect", _h_conflict_detect)


# ----------------------------------------- 4. regulation translator (async)


_TRANSLATE_SYS = (
    "You are a data retention compliance translator. Read the regulation "
    "text and recommend retention windows. Output STRICT JSON only — "
    "alerts_days, audit_logs_days, raw_intel_days, iocs_days, "
    "deletion_mode (hard_delete|soft_delete|anonymise), "
    "compliance_mappings (array), rationale_per_class (object)."
)


async def _h_translate(db: AsyncSession, task: AgentTask) -> dict[str, Any]:
    payload = task.payload or {}
    regulation_text = (payload.get("regulation_text") or "")[:8000]
    if not regulation_text.strip():
        return {"skipped": True, "reason": "no regulation_text"}

    text, model_id = await call_bridge(
        _TRANSLATE_SYS, f"Regulation:\n---\n{regulation_text}\n---"
    )
    task.model_id = model_id
    parsed = _parse_json(text) or {}
    return {"suggestion": parsed, "model_id": model_id, "raw": text[:4000]}


register_handler("retention_regulation_translate", _h_translate)


# --------------------------------------- 5. pre-purge knowledge preserver


_PRESERVE_SYS = (
    "You are an intelligence analyst summarising raw security data BEFORE "
    "it is purged for compliance. Drop ALL personally-identifiable "
    "information (subject names, email addresses, IP addresses, account "
    "numbers, phone numbers, postal addresses). Capture the institutional "
    "knowledge: campaigns observed, threat actor TTPs, IOCs already "
    "promoted, MITRE techniques, novel infrastructure patterns. Output "
    "STRICT JSON only — keys: summary_md (Markdown string, <=2000 chars), "
    "iocs (array of strings; hashes/domains/IPs ALREADY in our IOC table "
    "are fine but no fresh PII), actors (array of strings), techniques "
    "(array of MITRE ATT&CK technique IDs like T1566.002)."
)


async def _h_preserve(db: AsyncSession, task: AgentTask) -> dict[str, Any]:
    payload = task.payload or {}
    cutoff_raw = datetime.fromisoformat(payload["cutoff_raw_iso"])
    cutoff_alerts = datetime.fromisoformat(payload["cutoff_alerts_iso"])
    org_id = task.organization_id

    # Raw SQL — RawIntel/Alert ORM models don't declare legal_hold even
    # though alembic adds the column at the DB level. Going via _text
    # also lets us skip the column projection if a future schema drops
    # one of these tables.
    raw_sql = _text(
        "SELECT id, source_type, title, content_hash, content, created_at "
        "FROM raw_intel "
        "WHERE created_at < :cutoff AND legal_hold = false "
        "ORDER BY created_at ASC LIMIT 50"
    )
    raw_rows_db = []
    try:
        async with db.begin_nested():
            raw_rows_db = (
                await db.execute(raw_sql, {"cutoff": cutoff_raw})
            ).all()
    except Exception as exc:  # noqa: BLE001
        logger.warning("preserve: raw_intel scan failed (%s)", type(exc).__name__)

    alert_sql_str = (
        "SELECT id, category, severity, title, summary, agent_reasoning, "
        "created_at FROM alerts "
        "WHERE created_at < :cutoff AND legal_hold = false "
    )
    alert_bind: dict[str, Any] = {"cutoff": cutoff_alerts}
    if org_id is not None:
        alert_sql_str += "AND organization_id = :org_id "
        alert_bind["org_id"] = org_id
    alert_sql_str += "ORDER BY created_at ASC LIMIT 50"
    alert_rows_db = []
    try:
        async with db.begin_nested():
            alert_rows_db = (
                await db.execute(_text(alert_sql_str), alert_bind)
            ).all()
    except Exception as exc:  # noqa: BLE001
        logger.warning("preserve: alerts scan failed (%s)", type(exc).__name__)

    if not raw_rows_db and not alert_rows_db:
        return {"skipped": True, "reason": "no rows to preserve"}

    raw_dates = [r[5] for r in raw_rows_db]
    alert_dates = [r[6] for r in alert_rows_db]
    window_start = min(
        [t for t in (raw_dates + alert_dates) if t], default=None
    )
    window_end = max(
        [t for t in (raw_dates + alert_dates) if t], default=None
    )

    # Build a compact corpus the LLM can chew through.
    corpus_lines: list[str] = []
    for r in raw_rows_db[:25]:
        # r = (id, source_type, title, content_hash, content, created_at)
        corpus_lines.append(
            f"[raw] src={r[1]} title={ (r[2] or '')[:80] } "
            f"hash={(r[3] or '')[:12]} body={ (r[4] or '')[:300] }"
        )
    for a in alert_rows_db[:25]:
        # a = (id, category, severity, title, summary, agent_reasoning, created_at)
        corpus_lines.append(
            f"[alert] cat={a[1]} sev={a[2]} title={(a[3] or '')[:80]} "
            f"summary={(a[4] or '')[:300]} "
            f"reasoning={ (a[5] or '')[:200] }"
        )
    corpus = "\n".join(corpus_lines)[:12000]

    user_prompt = (
        f"Window: {window_start.isoformat() if window_start else '?'} → "
        f"{window_end.isoformat() if window_end else '?'}\n"
        f"Total rows in scope: {len(raw_rows_db) + len(alert_rows_db)} "
        f"(raw_intel={len(raw_rows_db)}, alerts={len(alert_rows_db)}).\n\n"
        f"Sample rows (PII may be present in the input — DO NOT echo back):\n"
        f"---\n{corpus}\n---\n"
        "Summarise the institutional learning, dropping all PII."
    )

    text, model_id = await call_bridge(_PRESERVE_SYS, user_prompt)
    parsed = _parse_json(text) or {}
    summary_md = str(parsed.get("summary_md", "") or text)[:8000]
    iocs = [str(x)[:200] for x in (parsed.get("iocs") or [])][:50]
    actors = [str(x)[:200] for x in (parsed.get("actors") or [])][:30]
    techniques = [str(x)[:50] for x in (parsed.get("techniques") or [])][:50]

    db.add(
        LearningsLog(
            organization_id=org_id,
            source_table="raw_intel+alerts",
            rows_summarised=len(raw_rows_db) + len(alert_rows_db),
            window_start=window_start,
            window_end=window_end,
            summary_md=summary_md,
            extracted_iocs=iocs,
            extracted_actors=actors,
            extracted_techniques=techniques,
            model_id=model_id,
        )
    )
    await db.commit()

    return {
        "rows_summarised": len(raw_rows_db) + len(alert_rows_db),
        "model_id": model_id,
        "iocs_count": len(iocs),
        "actors_count": len(actors),
        "techniques_count": len(techniques),
    }


register_handler("retention_preserve_knowledge", _h_preserve)


# -------------------------------------------- 6. attestation generator


_ATTEST_SYS = (
    "You draft a {period_days}-day data retention compliance attestation "
    "report for {framework_list}. Output Markdown only. Required sections "
    "in order: ## Executive Summary, ## Policies in Force, ## Cleanup "
    "Activity, ## Legal Holds, ## DSAR Activity, ## Findings & Risks, "
    "## Attestation Statement. Audit-grade tone — concise, factual, no "
    "marketing language. Cite the framework articles where relevant. The "
    "Attestation Statement section must say the controller has reviewed "
    "the activity for the period and either confirms continued compliance "
    "or lists exceptions."
)


async def _h_attestation(db: AsyncSession, task: AgentTask) -> dict[str, Any]:
    payload = task.payload or {}
    org_id_raw = payload.get("organization_id")
    org_id = uuid.UUID(org_id_raw) if org_id_raw else None
    period_days = int(payload.get("period_days") or 90)
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=period_days)

    # Aggregate: policies in force.
    pol_q = select(RetentionPolicy)
    if org_id is not None:
        pol_q = pol_q.where(
            or_(
                RetentionPolicy.organization_id == org_id,
                RetentionPolicy.organization_id.is_(None),
            )
        )
    policies = (await db.execute(pol_q)).scalars().all()
    policies_block = [
        {
            "id": str(p.id),
            "scope": "global" if not p.organization_id else "org",
            "raw_intel_days": p.raw_intel_days,
            "alerts_days": p.alerts_days,
            "audit_logs_days": p.audit_logs_days,
            "iocs_days": p.iocs_days,
            "deletion_mode": getattr(p, "deletion_mode", "hard_delete"),
            "compliance_mappings": list(p.compliance_mappings or []),
            "auto_cleanup_enabled": p.auto_cleanup_enabled,
            "last_cleanup_at": (
                p.last_cleanup_at.isoformat() if p.last_cleanup_at else None
            ),
        }
        for p in policies
    ]

    # Frameworks union — drives the prompt's framework_list.
    framework_set: set[str] = set()
    for p in policies:
        for fw in (p.compliance_mappings or []):
            framework_set.add(fw)
    framework_list = (
        ", ".join(sorted(framework_set)) or "GDPR + CCPA (no explicit mappings)"
    )

    # Cleanup activity within window — peek at AuditLog rows.
    try:
        cleanup_count = int(
            (
                await db.execute(
                    _text(
                        "SELECT COUNT(*) FROM audit_logs WHERE timestamp >= :s "
                        "AND action = 'retention_cleanup'"
                    ),
                    {"s": window_start},
                )
            ).scalar()
            or 0
        )
    except Exception:  # noqa: BLE001
        cleanup_count = 0

    # Legal hold tallies across the legal-holdable tables.
    legal_hold_counts: dict[str, int] = {}
    for tbl in ("evidence_blobs", "cases", "audit_logs", "alerts",
                "raw_intel", "iocs", "dlp_findings", "card_leakage_findings",
                "dmarc_reports"):
        try:
            n = int(
                (
                    await db.execute(
                        _text(f"SELECT COUNT(*) FROM {tbl} WHERE legal_hold = true")
                    )
                ).scalar()
                or 0
            )
            if n > 0:
                legal_hold_counts[tbl] = n
        except Exception:  # noqa: BLE001
            continue

    # DSAR activity.
    dsar_q = select(DsarRequest).where(DsarRequest.created_at >= window_start)
    if org_id is not None:
        dsar_q = dsar_q.where(DsarRequest.organization_id == org_id)
    dsars = (await db.execute(dsar_q)).scalars().all()
    dsar_summary = {
        "total": len(dsars),
        "by_type": {},
        "by_status": {},
        "open_past_deadline": 0,
    }
    for d in dsars:
        dsar_summary["by_type"][d.request_type] = (
            dsar_summary["by_type"].get(d.request_type, 0) + 1
        )
        dsar_summary["by_status"][d.status] = (
            dsar_summary["by_status"].get(d.status, 0) + 1
        )
        if d.deadline_at and d.deadline_at < now and d.status not in ("closed",):
            dsar_summary["open_past_deadline"] += 1

    # Recent open conflicts (notification_inbox).
    try:
        conflict_q = select(func.count()).select_from(NotificationInboxItem).where(
            and_(
                NotificationInboxItem.event_kind == "retention_policy_conflict",
                NotificationInboxItem.created_at >= window_start,
            )
        )
        if org_id is not None:
            conflict_q = conflict_q.where(
                NotificationInboxItem.organization_id == org_id
            )
        open_conflicts = int((await db.execute(conflict_q)).scalar() or 0)
    except Exception:  # noqa: BLE001
        open_conflicts = 0

    aggregate = {
        "period_days": period_days,
        "window_start": window_start.isoformat(),
        "window_end": now.isoformat(),
        "framework_list": framework_list,
        "policies": policies_block,
        "cleanup_runs_in_window": cleanup_count,
        "legal_hold_counts": legal_hold_counts,
        "dsar": dsar_summary,
        "open_retention_conflicts": open_conflicts,
    }

    sys_prompt = _ATTEST_SYS.format(
        period_days=period_days, framework_list=framework_list,
    )
    user_prompt = (
        f"Aggregated activity (JSON):\n{json.dumps(aggregate, default=str)}\n\n"
        "Write the attestation report now."
    )
    text, model_id = await call_bridge(sys_prompt, user_prompt)
    summary_md = (text or "").strip()[:32000]

    row = LearningsLog(
        organization_id=org_id,
        source_table="attestation",
        rows_summarised=len(policies),
        window_start=window_start,
        window_end=now,
        summary_md=summary_md,
        extracted_iocs=[],
        extracted_actors=[],
        extracted_techniques=[],
        model_id=model_id,
    )
    db.add(row)
    await db.flush()

    # Surface in inbox so a compliance officer sees it.
    if org_id is not None:
        db.add(
            NotificationInboxItem(
                organization_id=org_id,
                event_kind="compliance_attestation",
                severity="info",
                title=f"{period_days}-day compliance attestation ready",
                summary=summary_md[:8000],
                link_path="/retention",
                payload={
                    "kind": "compliance_attestation",
                    "learnings_log_id": str(row.id),
                    "period_days": period_days,
                    "framework_list": framework_list,
                    "model_id": model_id,
                },
            )
        )
    await db.commit()

    return {
        "attestation_id": str(row.id),
        "model_id": model_id,
        "summary_chars": len(summary_md),
        "framework_list": framework_list,
    }


register_handler("retention_attestation_generate", _h_attestation)


__all__: list[str] = []
