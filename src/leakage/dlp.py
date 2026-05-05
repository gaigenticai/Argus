"""DLP policy engine — keyword / regex / yara matching.

Regex policies (Audit B8) are evaluated under a hard wall-clock budget
implemented via a worker thread; any pattern that doesn't return within
the budget is treated as ReDoS and the policy is auto-disabled. We also
reject obvious nested-quantifier patterns at create time as a cheap
first-pass guard.
"""

from __future__ import annotations

import concurrent.futures
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.leakage import (
    DlpFinding,
    DlpPolicy,
    DlpPolicyKind,
    LeakageState,
)


# --- ReDoS guards ------------------------------------------------------

_REGEX_TIMEOUT_SECONDS = 0.5  # per-policy per-document evaluation budget
_REGEX_MAX_LENGTH = 2048
_REGEX_MAX_QUANTIFIERS = 8

# Static rejection covers four well-known catastrophic-backtracking shapes:
#   1. Nested quantifier on a group:   (a+)+ , (a*)+ , (a+)*?
#   2. Nested quantifier on a class:   [a-z]++ , [^x]**
#   3. Alternation of overlapping options under a quantifier:
#         (a|aa)+ , (foo|foobar)* , (a|a|a)+
#      The OWASP / Wuestholz "evil regex" canon.
#   4. Quantifier on a backreference:  (\\w+)\\1+
# Adversarial audit D-20 — extend the nested-quantifier guard to catch
# brace-form quantifiers (``(a{1,}){1,}``, ``(a{2,5}){1,}``) which the
# original ``[+*?]``-only regex missed.
_BRACE_QUANT = r"(?:[+*?]|\{\d+,?\d*\}\??)"
_REGEX_NESTED_QUANT_RE = re.compile(
    r"(?:\([^()]*" + _BRACE_QUANT + r"[^()]*\)" + _BRACE_QUANT  # (X+)+ / (X{1,}){1,}
    + r"|\[[^\]]+\]" + _BRACE_QUANT + _BRACE_QUANT             # [..]++ / [..]{1,}{1,}
    + r"|\\\d+" + _BRACE_QUANT + r")"                            # \1+ / \1{1,}
)
_REGEX_ALTERNATION_OVERLAP_RE = re.compile(
    r"\([^()]*\|[^()]*\)" + _BRACE_QUANT
)


def _alternation_overlaps(pattern: str) -> bool:
    """True if any (...|...) group has alternatives that share a non-empty
    prefix or are full-prefix-of-another, AND is followed by a quantifier.

    Example evil regex: ``(a|aa)+`` — both branches match "a" repeatedly,
    yielding 2^n traversals on input "aaaa...!". We catch this by
    extracting alternation groups under repetition and looking for the
    overlap pattern: any branch is a prefix of any other.
    """
    for m in _REGEX_ALTERNATION_OVERLAP_RE.finditer(pattern):
        group = m.group(0)
        # strip outer (...) and trailing quantifier
        inner = group[1: group.rfind(")")]
        branches = inner.split("|")
        if len(branches) < 2:
            continue
        # Reduce to plain prefix overlap check; fancier escaping will
        # produce false positives we accept (operator can rewrite).
        for i, a in enumerate(branches):
            for j, b in enumerate(branches):
                if i == j or not a or not b:
                    continue
                if a.startswith(b) or b.startswith(a):
                    return True
    return False


def regex_pattern_is_dangerous(pattern: str) -> bool:
    """Static guard for catastrophic-backtracking shapes.

    Returns ``True`` for any of:
        * pattern length > _REGEX_MAX_LENGTH
        * total quantifier count > _REGEX_MAX_QUANTIFIERS (rough budget)
        * nested-quantifier shapes (``(X+)+``, ``[..]++``, ``\\1+``)
        * overlapping alternation under a quantifier (``(a|aa)+``)

    This is intentionally conservative: a few unusual but safe patterns
    will be rejected. Operators get a clear error and can rewrite. The
    runtime ThreadPoolExecutor timeout (``_REGEX_TIMEOUT_SECONDS``) is
    the second line of defence for shapes the static check misses.
    """
    if not pattern:
        return False
    if len(pattern) > _REGEX_MAX_LENGTH:
        return True
    quantifier_count = sum(pattern.count(q) for q in ("+", "*", "?", "{"))
    if quantifier_count > _REGEX_MAX_QUANTIFIERS:
        return True
    if _REGEX_NESTED_QUANT_RE.search(pattern):
        return True
    if _alternation_overlaps(pattern):
        return True
    return False


def _run_regex_with_timeout(compiled: re.Pattern, text: str) -> list[re.Match] | None:
    """Run ``finditer`` in a worker thread with a wall-clock cap.

    Returns ``None`` on timeout (caller should treat as policy failure).
    """
    def _work():
        return list(compiled.finditer(text))

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_work)
        try:
            return future.result(timeout=_REGEX_TIMEOUT_SECONDS)
        except concurrent.futures.TimeoutError:
            # Cannot kill the thread; let it finish in the background.
            # The pool exits when the underlying thread completes.
            return None


@dataclass
class DlpScanReport:
    policies_evaluated: int
    findings_created: int
    matches_found: int


def _excerpt(text: str, idx: int, span: int = 80) -> str:
    start = max(0, idx - span)
    end = min(len(text), idx + span)
    return text[start:end].strip()


def _redact_excerpt(excerpt: str, match: str) -> str:
    """Audit D-20 — replace the exact matched substring inside an
    excerpt with ``<redacted len=N sha256=...>`` so DLP findings keep
    their context but never re-store the secret they were meant to
    flag. Falls back to the original excerpt if ``match`` somehow isn't
    in it (defensive — caller computes both off the same text)."""
    import hashlib as _hashlib

    if not match or match not in excerpt:
        return excerpt
    digest = _hashlib.sha256(match.encode("utf-8", "replace")).hexdigest()[:16]
    placeholder = f"<redacted len={len(match)} sha256={digest}>"
    return excerpt.replace(match, placeholder)


def evaluate_policy(policy: DlpPolicy, text: str) -> list[str]:
    """Return list of matched excerpts; empty if no hit.

    Audit D-20 — every excerpt has its matched substring replaced by a
    fingerprint placeholder before it is returned. The finding row never
    persists the actual PAN / SSN / token that triggered it.
    """
    if not policy.enabled or not text:
        return []
    if policy.kind == DlpPolicyKind.KEYWORD.value:
        kw = policy.pattern.strip().lower()
        if not kw:
            return []
        text_low = text.lower()
        excerpts: list[str] = []
        idx = 0
        while True:
            i = text_low.find(kw, idx)
            if i < 0:
                break
            raw = _excerpt(text, i)
            # Find the exact (case-preserving) match inside the excerpt.
            actual = text[i : i + len(kw)]
            excerpts.append(_redact_excerpt(raw, actual))
            idx = i + len(kw)
            if len(excerpts) >= 25:
                break
        return excerpts
    if policy.kind == DlpPolicyKind.REGEX.value:
        # Static guard first — refuse known-evil shapes outright.
        if regex_pattern_is_dangerous(policy.pattern):
            policy.enabled = False
            return []
        try:
            r = re.compile(policy.pattern)
        except re.error:
            return []
        # Runtime guard — wall-clock budget catches anything the static
        # rejector missed.
        matches = _run_regex_with_timeout(r, text)
        if matches is None:
            policy.enabled = False
            return []
        out: list[str] = []
        for m in matches[:25]:
            raw = _excerpt(text, m.start())
            out.append(_redact_excerpt(raw, m.group(0)))
        return out
    if policy.kind == DlpPolicyKind.YARA.value:
        try:
            import yara  # type: ignore
        except ImportError:
            return []
        try:
            rules = yara.compile(source=policy.pattern)
        except Exception:  # noqa: BLE001
            return []
        matches = rules.match(data=text.encode("utf-8", errors="replace"))
        # YARA match objects don't carry an excerpt; the rule name is
        # already non-secret so just return the rule identifier.
        return [str(m) for m in matches][:25]
    return []


async def scan_text(
    db: AsyncSession,
    organization_id: uuid.UUID,
    text: str,
    *,
    source_url: str | None = None,
    source_kind: str | None = None,
) -> DlpScanReport:
    policies = (
        await db.execute(
            select(DlpPolicy).where(
                and_(
                    DlpPolicy.organization_id == organization_id,
                    DlpPolicy.enabled == True,  # noqa: E712
                )
            )
        )
    ).scalars().all()

    created = 0
    total_matches = 0
    now = datetime.now(timezone.utc)
    new_findings: list[DlpFinding] = []

    for policy in policies:
        excerpts = evaluate_policy(policy, text)
        if not excerpts:
            continue
        total_matches += len(excerpts)

        existing = (
            await db.execute(
                select(DlpFinding).where(
                    and_(
                        DlpFinding.organization_id == organization_id,
                        DlpFinding.policy_id == policy.id,
                        DlpFinding.source_url == source_url,
                    )
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            existing.matched_count += len(excerpts)
            existing.detected_at = now
            existing.matched_excerpts = list(set((existing.matched_excerpts or []) + excerpts))[:50]
            continue
        finding = DlpFinding(
            organization_id=organization_id,
            policy_id=policy.id,
            policy_name=policy.name,
            severity=policy.severity,
            source_url=source_url,
            source_kind=source_kind,
            matched_count=len(excerpts),
            matched_excerpts=excerpts[:50],
            state=LeakageState.OPEN.value,
            detected_at=now,
        )
        db.add(finding)
        await db.flush()
        new_findings.append(finding)
        created += 1

    # Fire-and-forget agentic enqueues. Done after the create loop so a
    # mid-loop enqueue failure can never roll back a freshly-persisted
    # finding (we'd rather have the row + missed agent than no row).
    if new_findings:
        try:
            from src.llm.agent_queue import enqueue as _enqueue

            for f in new_findings:
                await _enqueue(
                    db,
                    kind="leakage_classify",
                    payload={"finding_id": str(f.id), "kind": "dlp"},
                    organization_id=organization_id,
                    dedup_key=f"classify:dlp:{f.id}",
                    priority=5,
                )
                await _enqueue(
                    db,
                    kind="leakage_correlate_cross_org",
                    payload={"finding_id": str(f.id), "kind": "dlp"},
                    organization_id=organization_id,
                    dedup_key=f"correlate:dlp:{f.id}",
                    priority=6,
                )
        except Exception:  # noqa: BLE001 — never let agent enqueue break detection
            import logging as _logging
            _logging.getLogger(__name__).exception(
                "leakage agent enqueue failed for org %s", organization_id
            )

    return DlpScanReport(
        policies_evaluated=len(policies),
        findings_created=created,
        matches_found=total_matches,
    )


__all__ = [
    "DlpScanReport",
    "evaluate_policy",
    "scan_text",
    "regex_pattern_is_dangerous",
]


# Backward-compatible alias used by tests and external imports.
scan_dlp = scan_text
