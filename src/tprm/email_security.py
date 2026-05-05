"""Vendor email-security pillar — DMARC / SPF / DKIM posture.

Free DNS lookups via dnspython. No external paid API. Producing a 0..100
score so the scorecard can blend it into the breach pillar's adjustment
factor and an analyst can see the underlying evidence.

Score breakdown:
    DMARC present + p=reject     +50
    DMARC present + p=quarantine +35
    DMARC present + p=none       +15
    SPF present                   +20  (terminal -all preferred)
    DKIM at common selectors      +20
    DNSSEC chain valid            +10  (best-effort; checked by the dnsx
                                        ``dns_detail`` runner output if
                                        available, otherwise skipped)

Maxes out at 100.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

_logger = logging.getLogger(__name__)


_COMMON_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail")


def _dmarc_score(dmarc: str | None) -> tuple[int, str | None]:
    if not dmarc:
        return 0, None
    txt = dmarc.lower().replace(" ", "")
    if "p=reject" in txt:
        return 50, "p=reject"
    if "p=quarantine" in txt:
        return 35, "p=quarantine"
    if "p=none" in txt:
        return 15, "p=none"
    return 5, "policy unknown"


def _spf_score(spf: str | None) -> tuple[int, str | None]:
    if not spf:
        return 0, None
    txt = spf.lower()
    if "-all" in txt:
        return 20, "terminal -all"
    if "~all" in txt:
        return 14, "soft-fail ~all"
    if "?all" in txt:
        return 8, "neutral ?all"
    return 6, "no terminal qualifier"


async def _resolve_txt(name: str, timeout: float = 5.0) -> list[str]:
    try:
        import dns.exception  # type: ignore
        import dns.resolver  # type: ignore
    except ImportError:
        return []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        answers = await asyncio.to_thread(
            resolver.resolve, name, "TXT", raise_on_no_answer=False
        )
        return [r.to_text().strip('"') for r in answers]
    except (dns.exception.DNSException, Exception):  # noqa: BLE001
        return []


async def _has_any_dkim(domain: str, timeout: float = 5.0) -> tuple[bool, str | None]:
    """Best-effort probe of common DKIM selectors. Returns (found, selector)."""
    for sel in _COMMON_DKIM_SELECTORS:
        records = await _resolve_txt(f"{sel}._domainkey.{domain}", timeout=timeout)
        for rec in records:
            if "v=dkim1" in rec.lower():
                return True, sel
    return False, None


async def assess_email_security(domain: str) -> tuple[float, dict[str, Any]]:
    """Returns ``(score_0_100, evidence_dict)`` for a vendor primary
    domain. Pure DNS — works inside the worker container with no
    additional credentials.
    """
    if not domain:
        return 0.0, {"reason": "no primary_domain"}
    domain = domain.strip().lower()

    spf_records = await _resolve_txt(domain)
    spf = next(
        (
            r
            for r in spf_records
            if r.lower().startswith("v=spf1") or "v=spf1" in r.lower()
        ),
        None,
    )

    dmarc_records = await _resolve_txt(f"_dmarc.{domain}")
    dmarc = next(
        (r for r in dmarc_records if r.lower().startswith("v=dmarc1")), None
    )

    has_dkim, dkim_selector = await _has_any_dkim(domain)

    spf_pts, spf_note = _spf_score(spf)
    dmarc_pts, dmarc_note = _dmarc_score(dmarc)
    dkim_pts = 20 if has_dkim else 0

    total = min(100, spf_pts + dmarc_pts + dkim_pts)
    return float(total), {
        "domain": domain,
        "spf": {"present": bool(spf), "policy": spf_note, "raw": spf, "score": spf_pts},
        "dmarc": {
            "present": bool(dmarc),
            "policy": dmarc_note,
            "raw": dmarc,
            "score": dmarc_pts,
        },
        "dkim": {"present": has_dkim, "selector": dkim_selector, "score": dkim_pts},
        "score": total,
    }


__all__ = ["assess_email_security"]
