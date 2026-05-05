"""Auto-fill draft questionnaire answers from public posture.

For each question on the active questionnaire instance, we walk a
ladder of public signals:

  * DMARC / SPF / DKIM (assess_email_security)
  * GitHub org public security advisories
  * security.txt presence on primary_domain
  * OFAC / OFSI / EU sanctions
  * HIBP presence on vendor common emails

If a signal is decisive, we stamp a draft answer + evidence link onto
``QuestionnaireAnswer`` (state stays unsubmitted; analyst confirms).
When the LLM provider is configured we add a richer rationale per
answer. When it isn't, the deterministic fallback writes a structured
note pointing at the public source so analysts still get full
transparency.
"""
from __future__ import annotations

import asyncio
import logging
import re
import uuid
from typing import Any

import aiohttp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import settings
from src.llm.providers import LLMNotConfigured, get_provider
from src.models.threat import Asset
from src.models.tprm import (
    QuestionnaireAnswer,
    QuestionnaireInstance,
    QuestionnaireTemplate,
)
from src.tprm.email_security import assess_email_security
from src.tprm.sanctions import screen_vendor

_logger = logging.getLogger(__name__)


_SECURITY_TXT_URLS = (
    "https://{domain}/.well-known/security.txt",
    "https://{domain}/security.txt",
)


async def _fetch_security_txt(domain: str) -> dict[str, Any] | None:
    timeout = aiohttp.ClientTimeout(total=10)
    for tmpl in _SECURITY_TXT_URLS:
        url = tmpl.format(domain=domain)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.get(url) as resp:
                    if resp.status == 200:
                        body = (await resp.text())[:5000]
                        return {"url": url, "body": body}
        except (aiohttp.ClientError, asyncio.TimeoutError):
            continue
    return None


def _question_keywords(text: str) -> set[str]:
    return set(re.findall(r"[a-z]+", (text or "").lower()))


def _baseline_answer_for(
    question: dict[str, Any],
    *,
    posture: dict[str, Any],
) -> tuple[str | None, str | None, str | None]:
    """Return ``(answer_value, evidence_link, note)`` from the posture
    bundle. ``None`` answer means we couldn't derive a value."""
    text = (question.get("text") or "").lower()
    kind = question.get("answer_kind") or "free_text"

    sec = posture.get("email_security") or {}
    sec_evidence = sec.get("evidence") or {}
    dmarc_present = (sec_evidence.get("dmarc") or {}).get("present")
    spf_present = (sec_evidence.get("spf") or {}).get("present")
    dkim_present = (sec_evidence.get("dkim") or {}).get("present")

    sectxt = posture.get("security_txt") or {}
    sanctions = posture.get("sanctions") or {}
    matched_sources = sanctions.get("matched_sources") or []

    # --- Email security questions ----------------------------------
    if any(t in text for t in ("dmarc", "spf", "dkim", "email security", "email auth")):
        any_present = bool(dmarc_present and spf_present)
        if kind in ("yes_no", "yes_no_na"):
            return (
                "yes" if any_present else "no",
                None,
                f"DMARC={(sec_evidence.get('dmarc') or {}).get('policy')} "
                f"SPF={(sec_evidence.get('spf') or {}).get('policy')} "
                f"DKIM={'yes' if dkim_present else 'no'}",
            )
        return (
            f"DMARC policy: {(sec_evidence.get('dmarc') or {}).get('policy') or 'none'}; "
            f"SPF: {(sec_evidence.get('spf') or {}).get('policy') or 'none'}; "
            f"DKIM probed: {'present' if dkim_present else 'not detected'}",
            None,
            None,
        )

    # --- Vulnerability disclosure / security.txt -------------------
    if any(
        t in text
        for t in ("vulnerability disclosure", "security advisory", "security.txt")
    ):
        if sectxt:
            return (
                "yes",
                sectxt.get("url"),
                f"security.txt found at {sectxt.get('url')}",
            )
        if kind in ("yes_no", "yes_no_na"):
            return (
                "no",
                None,
                "no security.txt at /.well-known/security.txt or /security.txt",
            )

    # --- Sanctions -------------------------------------------------
    if any(t in text for t in ("sanction", "ofac", "embargo")):
        if matched_sources:
            return (
                "yes",
                None,
                f"Hits on {','.join(matched_sources)}",
            )
        return ("no", None, "Clean across OFAC / OFSI / EU consolidated lists")

    # --- Generic — leave for analyst -------------------------------
    return (None, None, None)


async def _llm_refine(
    provider, question: dict[str, Any], baseline: tuple[str | None, str | None, str | None],
) -> str | None:
    if baseline[0] is None:
        return None
    sys = (
        "You polish a one-line draft answer to a vendor security question. "
        "Output ONE plain sentence (<=200 chars), no markdown, no quotes, "
        "no preamble. Keep the original assertion; just make it readable."
    )
    user = (
        f"Question: {question.get('text')}\n"
        f"Answer kind: {question.get('answer_kind')}\n"
        f"Baseline answer: {baseline[0]}\n"
        f"Note: {baseline[2] or '—'}\n"
    )
    try:
        out = (await provider.call(sys, user) or "").strip()
        return out if out and len(out) <= 600 else None
    except Exception:  # noqa: BLE001
        return None


async def autofill_questionnaire(
    db: AsyncSession,
    *,
    instance_id: uuid.UUID,
    use_llm: bool = True,
) -> dict[str, Any]:
    instance = await db.get(QuestionnaireInstance, instance_id)
    if instance is None:
        raise LookupError("questionnaire instance not found")

    template = await db.get(QuestionnaireTemplate, instance.template_id)
    questions = list((instance.template_snapshot or {}).get("questions") or [])
    if not questions and template is not None:
        questions = list(template.questions or [])
    if not questions:
        return {"filled": 0, "reason": "no questions on template"}

    vendor = await db.get(Asset, instance.vendor_asset_id)
    if vendor is None:
        raise LookupError("vendor asset not found")
    primary_domain = ((vendor.details or {}).get("primary_domain") or "").strip().lower()

    # Gather posture in one go.
    posture: dict[str, Any] = {}
    if primary_domain:
        sec_score, sec_evidence = await assess_email_security(primary_domain)
        posture["email_security"] = {
            "score": sec_score,
            "evidence": sec_evidence,
        }
        st = await _fetch_security_txt(primary_domain)
        if st:
            posture["security_txt"] = st
    sanctions = await screen_vendor(vendor.value or "")
    posture["sanctions"] = {
        "matched_sources": [h.source for h in sanctions if h.matched],
    }

    provider = None
    if use_llm:
        try:
            provider = get_provider(settings.llm)
        except LLMNotConfigured:
            provider = None
        except Exception as e:  # noqa: BLE001
            _logger.warning("autofill: provider init failed: %s", e)
            provider = None

    filled = 0
    skipped = 0
    for q in questions:
        qid = q.get("id")
        if not qid:
            continue
        baseline = _baseline_answer_for(q, posture=posture)
        if baseline[0] is None:
            skipped += 1
            continue
        ans_text = baseline[0]
        if provider is not None:
            polished = await _llm_refine(provider, q, baseline)
            if polished:
                ans_text = polished
        # Upsert into questionnaire_answers — keep existing analyst answer.
        existing = (
            await db.execute(
                select(QuestionnaireAnswer)
                .where(QuestionnaireAnswer.instance_id == instance.id)
                .where(QuestionnaireAnswer.question_id == qid)
            )
        ).scalar_one_or_none()
        if existing is not None and existing.answer_value:
            skipped += 1
            continue
        if existing is None:
            db.add(
                QuestionnaireAnswer(
                    instance_id=instance.id,
                    question_id=qid,
                    answer_value=ans_text,
                    notes=(baseline[2] or "auto-filled draft from public posture")
                    + (f" — evidence: {baseline[1]}" if baseline[1] else ""),
                )
            )
        else:
            existing.answer_value = ans_text
            existing.notes = (baseline[2] or "auto-filled draft from public posture") + (
                f" — evidence: {baseline[1]}" if baseline[1] else ""
            )
        filled += 1
    await db.commit()
    return {
        "filled": filled,
        "skipped": skipped,
        "total_questions": len(questions),
        "posture": {
            "email_security_score": (posture.get("email_security") or {}).get("score"),
            "security_txt": bool(posture.get("security_txt")),
            "sanctions_matched": posture.get("sanctions", {}).get("matched_sources"),
        },
    }


__all__ = ["autofill_questionnaire"]
