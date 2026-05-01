"""Credit-card leakage detection.

Workflow:
    1. Extract candidate PAN substrings from input text via regex
       (13-19 digits, possibly separated by spaces or hyphens).
    2. Validate each candidate via the Luhn checksum.
    3. Look up first6 against the BIN registry (tenant-scoped first,
       then global rows). Hit → bind to issuer/scheme/type.
    4. Build a CardLeakageFinding row keyed by sha256(PAN) so re-uploads
       of the same paste don't double-count.

We **never** persist or log the full PAN beyond the SHA-256 hash + first6
+ last4. PCI-DSS-compliant by design.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from typing import Iterable

from sqlalchemy import and_, select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.leakage import (
    CardLeakageFinding,
    CardScheme,
    CardType,
    CreditCardBin,
    LeakageState,
)


# Canonical PAN formats only — keeps us from greedy-grabbing exp dates.
#   contiguous            13–19 digits
#   visa/mc/disc style    4-4-4-{1..7}   (16–19 digits)
#   amex style            4-6-5          (15 digits)
#
# Separator class ``[ \-.‐-―]`` covers space, ASCII hyphen,
# dot, and the Unicode hyphen/dash family (figure/en/em dashes). Real
# paste-site dumps use any of these, often deliberately to evade naive
# scanners that key only on hyphen+space.
_PAN_SEP = r"[ \-.‐-―]"
_PAN_RE = re.compile(
    r"(?:(?<=\D)|(?<=^))("
    r"\d{13,19}"
    rf"|\d{{4}}{_PAN_SEP}\d{{4}}{_PAN_SEP}\d{{4}}{_PAN_SEP}\d{{1,7}}"
    rf"|\d{{4}}{_PAN_SEP}\d{{6}}{_PAN_SEP}\d{{5}}"
    r")(?:(?=\D)|(?=$))"
)
_PAN_NORMALISE_RE = re.compile(_PAN_SEP)


def _luhn(number: str) -> bool:
    """Return True iff the digit string passes the Luhn check."""
    if not number.isdigit() or not (12 <= len(number) <= 19):
        return False
    s = 0
    parity = len(number) % 2
    for i, d in enumerate(number):
        n = int(d)
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        s += n
    return s % 10 == 0


def _scheme_from_pan(pan: str) -> str:
    if pan.startswith("4"):
        return CardScheme.VISA.value
    if pan.startswith(("51", "52", "53", "54", "55")):
        return CardScheme.MASTERCARD.value
    if pan.startswith(("34", "37")):
        return CardScheme.AMEX.value
    if pan.startswith("6011") or pan.startswith("65"):
        return CardScheme.DISCOVER.value
    if pan.startswith("35"):
        return CardScheme.JCB.value
    if pan.startswith("62"):
        return CardScheme.UNIONPAY.value
    if pan.startswith(("300", "301", "302", "303", "304", "305", "36", "38")):
        return CardScheme.DINERS.value
    return CardScheme.OTHER.value


@dataclass
class CandidatePan:
    pan: str  # full digits (kept only in memory, never persisted)
    pan_sha256: str
    first6: str
    last4: str
    scheme_hint: str


def extract_candidates(text: str) -> list[CandidatePan]:
    if not text:
        return []
    seen: set[str] = set()
    out: list[CandidatePan] = []
    for raw in _PAN_RE.findall(text):
        digits = _PAN_NORMALISE_RE.sub("", raw)
        if len(digits) < 13 or len(digits) > 19:
            continue
        if not _luhn(digits):
            continue
        if digits in seen:
            continue
        seen.add(digits)
        out.append(
            CandidatePan(
                pan=digits,
                pan_sha256=hashlib.sha256(digits.encode()).hexdigest(),
                first6=digits[:6],
                last4=digits[-4:],
                scheme_hint=_scheme_from_pan(digits),
            )
        )
    return out


async def lookup_bin(
    db: AsyncSession,
    organization_id: uuid.UUID,
    first6: str,
) -> CreditCardBin | None:
    """Tenant-scoped first; falls back to global (organization_id IS NULL)."""
    # Try tenant-scoped longest-prefix match (8 → 6 chars).
    for prefix_len in (8, 7, 6):
        prefix = first6[:prefix_len]
        if len(prefix) < prefix_len:
            continue
        rows = (
            await db.execute(
                select(CreditCardBin).where(
                    and_(
                        or_(
                            CreditCardBin.organization_id == organization_id,
                            CreditCardBin.organization_id.is_(None),
                        ),
                        CreditCardBin.bin_prefix == prefix,
                    )
                )
            )
        ).scalars().all()
        if rows:
            # Prefer tenant-scoped over global
            tenant = [r for r in rows if r.organization_id == organization_id]
            return (tenant or rows)[0]
    return None


@dataclass
class CardScanReport:
    candidates: int
    new_findings: int
    seen_again: int


async def scan_text(
    db: AsyncSession,
    organization_id: uuid.UUID,
    text: str,
    *,
    source_url: str | None = None,
    source_kind: str | None = None,
    require_bin_match: bool = False,
) -> CardScanReport:
    """Scan text for card numbers.

    With the default ``require_bin_match=False``, Luhn-valid card numbers
    are reported even when the BIN table is empty (safe for fresh installs).
    Set ``require_bin_match=True`` only after seeding the CreditCardBin table
    to restrict detections to the organisation's own issuer BINs.
    """
    import logging as _logging
    if not require_bin_match:
        _logging.getLogger(__name__).debug(
            "BIN matching disabled — card detections use Luhn-only validation. "
            "Seed the CreditCardBin table and pass require_bin_match=True for "
            "issuer-confirmed detections."
        )
    candidates = extract_candidates(text)
    new = 0
    seen_again = 0
    from datetime import datetime, timezone

    for cand in candidates:
        bin_row = await lookup_bin(db, organization_id, cand.first6)
        if require_bin_match and bin_row is None:
            continue

        existing = (
            await db.execute(
                select(CardLeakageFinding).where(
                    and_(
                        CardLeakageFinding.organization_id == organization_id,
                        CardLeakageFinding.pan_sha256 == cand.pan_sha256,
                    )
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            seen_again += 1
            continue

        finding = CardLeakageFinding(
            organization_id=organization_id,
            pan_first6=cand.first6,
            pan_last4=cand.last4,
            pan_sha256=cand.pan_sha256,
            matched_bin_id=bin_row.id if bin_row else None,
            issuer=bin_row.issuer if bin_row else None,
            scheme=(bin_row.scheme if bin_row else cand.scheme_hint),
            card_type=(bin_row.card_type if bin_row else CardType.UNKNOWN.value),
            source_url=source_url,
            source_kind=source_kind,
            excerpt=text[:500] if text else None,
            state=LeakageState.OPEN.value,
            detected_at=datetime.now(timezone.utc),
        )
        db.add(finding)
        await db.flush()
        new += 1

        # Audit D12 + D13 — banks always want to know about a card leak.
        # Treat every new CardLeakageFinding as HIGH severity for the
        # purposes of auto-casing and notification dispatch.
        try:
            from src.cases.auto_link import auto_link_finding

            await auto_link_finding(
                db,
                organization_id=organization_id,
                finding_type="card_leakage",
                finding_id=finding.id,
                severity="high",
                title=f"Card leak: BIN {cand.first6}··{cand.last4}",
                summary=f"PAN matching {cand.first6}··{cand.last4} found at {source_url}",
                event_kind="data_leakage",
                dedup_key=f"card_leakage:{cand.pan_sha256}",
                tags=("card_leakage",),
            )
        except Exception:  # noqa: BLE001
            import logging as _logging
            _logging.getLogger(__name__).exception(
                "auto_link_finding failed for card leakage %s", finding.id
            )

    return CardScanReport(
        candidates=len(candidates),
        new_findings=new,
        seen_again=seen_again,
    )


__all__ = [
    "CandidatePan",
    "CardScanReport",
    "extract_candidates",
    "lookup_bin",
    "scan_text",
]
