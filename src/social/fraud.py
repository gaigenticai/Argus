"""Online anti-fraud classifier (Phase 4.3).

Lightweight keyword-and-pattern scorer (per ``docs/HARDWARE_DECISIONS.md``).
Scores a chunk of text or a Telegram-channel description for
investment-scam / crypto-giveaway / job-offer / tech-support fraud
patterns, weighted by whether brand terms are referenced.

The scoring is interpretable on purpose: rationale + matched keywords
go on the FraudFinding row so analysts can sanity-check why a page got
flagged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


# Keyword vocabularies — short, high-precision sets curated from
# FCA/SEC/CFPB consumer-warning bulletins.
_INVESTMENT_SCAM = {
    "guaranteed returns", "double your money", "risk-free", "no risk",
    "high yield", "100% safe", "earn daily", "daily profit", "passive income guaranteed",
    "10x returns", "100x returns", "limited slots", "exclusive vip",
    "minimum deposit", "withdraw anytime", "ROI", "guaranteed roi",
    "fxinvestment", "binary options",
}
_CRYPTO_GIVEAWAY = {
    "send btc", "send eth", "send 0.5 btc", "double your btc",
    "official giveaway", "giveaway closing", "claim your airdrop",
    "exclusive presale", "wallet drainer", "verify your wallet",
}
_JOB_OFFER = {
    "remote opportunity", "no experience needed", "weekly payout",
    "quick onboarding", "pay $200/day", "telegram interview",
    "work from home immediately", "prepaid card",
}
_TECH_SUPPORT = {
    "your computer is infected", "microsoft support", "apple security",
    "call this number immediately", "your account is compromised",
    "remote desktop access", "anydesk", "teamviewer support",
}
_ROMANCE = {
    "darling please", "i love you my dear", "send me money to",
    "stuck overseas", "western union", "moneygram",
}
_SHILL = {
    "this gem will pump", "ape in", "100x play", "low cap gem",
    "buy now or regret", "moon soon", "next solana",
}

_VOCAB = {
    "investment_scam": _INVESTMENT_SCAM,
    "crypto_giveaway": _CRYPTO_GIVEAWAY,
    "job_offer": _JOB_OFFER,
    "tech_support": _TECH_SUPPORT,
    "romance_scam": _ROMANCE,
    "shill_channel": _SHILL,
}

_URL_RE = re.compile(r"https?://[^\s]+", re.I)
_BTC_ADDR = re.compile(r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
_ETH_ADDR = re.compile(r"\b0x[a-fA-F0-9]{40}\b")


@dataclass
class FraudScore:
    kind: str
    score: float
    matched_keywords: list[str]
    matched_brand_terms: list[str]
    rationale: str
    extra: dict = field(default_factory=dict)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def score_text(
    text: str, *, brand_terms: Iterable[str] = ()
) -> FraudScore:
    norm = _norm(text)
    if not norm:
        return FraudScore(
            kind="other",
            score=0.0,
            matched_keywords=[],
            matched_brand_terms=[],
            rationale="empty input",
        )

    # Per-vocab match counts
    best_kind = "other"
    best_count = 0
    matched_kw_per_kind: dict[str, list[str]] = {}
    for kind, vocab in _VOCAB.items():
        hits = [kw for kw in vocab if kw in norm]
        if hits:
            matched_kw_per_kind[kind] = hits
            if len(hits) > best_count:
                best_count = len(hits)
                best_kind = kind

    matched_kw = matched_kw_per_kind.get(best_kind, [])

    # Brand-term overlap
    brand_hits = [
        b for b in brand_terms if b and len(b) >= 3 and b.lower() in norm
    ]

    # Crypto / wire indicators (extra evidence weight)
    has_crypto_addr = bool(_BTC_ADDR.search(text or "") or _ETH_ADDR.search(text or ""))
    urgency = bool(re.search(r"\b(urgent|now|today only|last chance|limited|expires)\b", norm))

    # Score: 0..1
    base = min(1.0, 0.18 * best_count)
    if brand_hits:
        base += 0.25
    if has_crypto_addr:
        base += 0.2
    if urgency:
        base += 0.1
    score = min(1.0, round(base, 4))

    rationale_parts = []
    if matched_kw:
        rationale_parts.append(
            f"{len(matched_kw)} {best_kind.replace('_', ' ')} keyword(s)"
        )
    if brand_hits:
        rationale_parts.append(f"brand mentions: {', '.join(brand_hits)}")
    if has_crypto_addr:
        rationale_parts.append("crypto wallet address present")
    if urgency:
        rationale_parts.append("urgency phrasing")
    rationale = "; ".join(rationale_parts) or "no evidence"

    return FraudScore(
        kind=best_kind if best_count > 0 else "other",
        score=score,
        matched_keywords=matched_kw,
        matched_brand_terms=brand_hits,
        rationale=rationale,
        extra={
            "vocab_hit_counts": {k: len(v) for k, v in matched_kw_per_kind.items()},
            "has_crypto_address": has_crypto_addr,
            "urgency": urgency,
        },
    )


__all__ = ["FraudScore", "score_text"]
