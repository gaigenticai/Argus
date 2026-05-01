"""Questionnaire answer scoring.

For each answer in an instance:
    yes_no            yes=100, no=0
    yes_no_na         yes=100, n/a=neutral 75, no=0
    scale_1_5         (value − 1)/4 × 100
    free_text         empty=0; non-empty + evidence=100; non-empty short=60;
                      non-empty very-short=30. Analyst override still wins.
    evidence          present=100, absent=0

Final instance score = weighted average of per-question scores.
Required questions left blank zero out the entire instance.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.models.tprm import AnswerKind


@dataclass
class QuestionDef:
    id: str
    text: str
    answer_kind: AnswerKind
    weight: float = 1.0
    required: bool = True


def parse_question(q: dict) -> QuestionDef:
    return QuestionDef(
        id=str(q.get("id") or "").strip(),
        text=str(q.get("text") or ""),
        answer_kind=AnswerKind(q.get("answer_kind", "yes_no")),
        weight=float(q.get("weight", 1.0)),
        required=bool(q.get("required", True)),
    )


def score_answer(question: QuestionDef, answer_value: str | None, evidence_present: bool, override: float | None) -> float | None:
    """Returns 0..100 or None if unanswered for an optional free_text question.

    If `override` is provided (analyst writes a manual score), use that.
    """
    if override is not None:
        return max(0.0, min(100.0, float(override)))
    if question.answer_kind == AnswerKind.YES_NO:
        v = (answer_value or "").strip().lower()
        if v in {"yes", "y", "true", "1"}:
            return 100.0
        if v in {"no", "n", "false", "0"}:
            return 0.0
        return None
    if question.answer_kind == AnswerKind.YES_NO_NA:
        v = (answer_value or "").strip().lower()
        if v in {"yes", "y"}:
            return 100.0
        if v in {"no", "n"}:
            return 0.0
        if v in {"n/a", "na"}:
            return 75.0
        return None
    if question.answer_kind == AnswerKind.SCALE_1_5:
        try:
            v = int(answer_value or "")
        except ValueError:
            return None
        if 1 <= v <= 5:
            return ((v - 1) / 4.0) * 100.0
        return None
    if question.answer_kind == AnswerKind.FREE_TEXT:
        # G4 (Gemini audit): the previous version returned None and
        # required an analyst override on every free-text answer,
        # which made unanswered free-text questions silently ignored.
        # That hid required-question gaps from the aggregate score.
        #
        # Real heuristic: a non-empty answer of reasonable length
        # (≥ 20 chars) plus an evidence attachment scores 100; a
        # non-empty answer alone scores 60 (the vendor responded but
        # we can't verify); an empty answer scores 0 so the
        # ``required`` check at aggregate-time correctly flags the
        # gap. The analyst override still wins when set — we already
        # short-circuited at the top of the function.
        text = (answer_value or "").strip()
        if not text:
            return 0.0
        if evidence_present and len(text) >= 20:
            return 100.0
        if evidence_present:
            return 80.0
        if len(text) >= 20:
            return 60.0
        return 30.0  # vendor responded but only with a one-liner
    if question.answer_kind == AnswerKind.EVIDENCE:
        return 100.0 if evidence_present else 0.0
    return None


def aggregate_instance_score(questions: list[QuestionDef], answers: dict[str, dict]) -> float:
    """Compute the weighted score 0..100 for the instance.

    `answers` maps question_id → {value, evidence_present, override}.
    Returns 0 if any required question is missing or unscorable.
    """
    if not questions:
        return 0.0
    total_weight = sum(q.weight for q in questions)
    if total_weight <= 0:
        return 0.0
    accum = 0.0
    for q in questions:
        a = answers.get(q.id) or {}
        score = score_answer(
            q,
            a.get("value"),
            bool(a.get("evidence_present", False)),
            a.get("override"),
        )
        if score is None:
            if q.required:
                return 0.0
            continue
        accum += score * q.weight
    return round(accum / total_weight, 2)


__all__ = ["QuestionDef", "parse_question", "score_answer", "aggregate_instance_score"]


# --- Built-in templates -----------------------------------------------


def sig_lite_template() -> list[dict]:
    """Curated short-form SIG-Lite-style questions (open standard)."""
    return [
        {
            "id": "iso27001_certified",
            "text": "Are you ISO 27001 certified?",
            "answer_kind": "yes_no",
            "weight": 2.0,
            "required": True,
        },
        {
            "id": "soc2_type2",
            "text": "Have you completed a SOC 2 Type II audit in the last 12 months?",
            "answer_kind": "yes_no",
            "weight": 2.0,
            "required": True,
        },
        {
            "id": "encryption_in_transit",
            "text": "Do you encrypt customer data in transit using TLS 1.2+?",
            "answer_kind": "yes_no",
            "weight": 1.5,
            "required": True,
        },
        {
            "id": "encryption_at_rest",
            "text": "Do you encrypt customer data at rest using AES-256 or equivalent?",
            "answer_kind": "yes_no",
            "weight": 1.5,
            "required": True,
        },
        {
            "id": "mfa_internal",
            "text": "Is MFA enforced for all internal staff accessing customer data?",
            "answer_kind": "yes_no",
            "weight": 1.5,
            "required": True,
        },
        {
            "id": "incident_response_runbook",
            "text": "Do you have a documented incident response runbook tested in the last 12 months?",
            "answer_kind": "yes_no",
            "weight": 1.0,
            "required": True,
        },
        {
            "id": "vendor_security_program",
            "text": "How mature is your overall security program (1=ad-hoc, 5=optimised)?",
            "answer_kind": "scale_1_5",
            "weight": 1.0,
            "required": True,
        },
        {
            "id": "data_breach_history",
            "text": "Have you had a reportable data breach in the last 36 months?",
            "answer_kind": "yes_no",
            "weight": 1.5,
            "required": True,
        },
        {
            "id": "subprocessor_list",
            "text": "Do you publish or share a current list of subprocessors?",
            "answer_kind": "yes_no_na",
            "weight": 1.0,
            "required": True,
        },
        {
            "id": "soc2_evidence",
            "text": "Attach your most recent SOC 2 Type II report (PDF).",
            "answer_kind": "evidence",
            "weight": 1.0,
            "required": False,
        },
    ]


def caiq_v4_template() -> list[dict]:
    """A small subset of CSA CAIQ v4 questions (open standard)."""
    return [
        {
            "id": "AAC-01.1",
            "text": "Are audit and assurance plans approved by management at least annually?",
            "answer_kind": "yes_no",
            "weight": 1.0,
            "required": True,
        },
        {
            "id": "BCR-01.1",
            "text": "Is a business continuity plan tested at least annually?",
            "answer_kind": "yes_no",
            "weight": 1.5,
            "required": True,
        },
        {
            "id": "CCC-01.1",
            "text": "Are security baselines defined for all production systems?",
            "answer_kind": "yes_no",
            "weight": 1.5,
            "required": True,
        },
        {
            "id": "CEK-01.1",
            "text": "Are encryption keys rotated at defined intervals or upon compromise?",
            "answer_kind": "yes_no",
            "weight": 1.5,
            "required": True,
        },
        {
            "id": "DSP-01.1",
            "text": "Is data classified by sensitivity?",
            "answer_kind": "yes_no",
            "weight": 1.0,
            "required": True,
        },
        {
            "id": "GRC-01.1",
            "text": "Is GRC tooling used to manage controls and exceptions?",
            "answer_kind": "yes_no",
            "weight": 1.0,
            "required": True,
        },
        {
            "id": "HRS-01.1",
            "text": "Are background checks performed on personnel with privileged access?",
            "answer_kind": "yes_no",
            "weight": 1.0,
            "required": True,
        },
        {
            "id": "IAM-01.1",
            "text": "Is privileged-access reviewed at least quarterly?",
            "answer_kind": "yes_no",
            "weight": 1.5,
            "required": True,
        },
    ]


BUILTIN_TEMPLATES = {
    "sig_lite": sig_lite_template,
    "caiq_v4": caiq_v4_template,
}
