"""GCC ransomware DLS filter (P1 #1.5).

Scores ransomware data-leak-site (DLS) victim posts for GCC relevance
across four signals — country code, ccTLD, Arabic letters in the
victim name, and curated GCC company / city keyword fuzzy matching.

Wired into ``src/feeds/ransomware_feed.py``: every victim record
emitted by the feed gets a ``gcc_relevance`` block in ``feed_metadata``
so downstream filters (threat map, feed UI, alert pipeline) can pull
only the GCC subset without re-scoring.

Watchlist groups (per MEGA_PHASE.md item 1.5):
    RansomHub · Akira · Play · Qilin · LockBit (and successors) ·
    BlackSuit · Hunters International · INC Ransom

The list is informational — the filter applies to every group; the
watchlist drives a separate ``watchlisted_group`` signal that bumps
confidence when a known-aggressive group claims a GCC victim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse

import unicodedata


# ── ISO-3166 country codes for the GCC + Egypt ───────────────────────


GCC_COUNTRY_CODES: frozenset[str] = frozenset({
    "SA",  # Saudi Arabia
    "AE",  # United Arab Emirates
    "QA",  # Qatar
    "KW",  # Kuwait
    "BH",  # Bahrain
    "OM",  # Oman
    "EG",  # Egypt — included per MEGA_PHASE; primary GCC adjacent market
})


# ── ccTLDs (incl. second-level country domains) ──────────────────────


GCC_CCTLDS: tuple[str, ...] = (
    ".sa", ".com.sa", ".gov.sa", ".net.sa", ".edu.sa",
    ".ae", ".com.ae", ".gov.ae", ".net.ae",
    ".qa", ".com.qa", ".gov.qa", ".net.qa",
    ".kw", ".com.kw", ".gov.kw",
    ".bh", ".com.bh", ".gov.bh",
    ".om", ".com.om", ".gov.om",
    ".eg", ".com.eg", ".gov.eg", ".org.eg",
)


# ── Curated brand / company keywords ────────────────────────────────
# Extend with care: each entry gets a fuzzy substring match against
# the victim name, so over-broad terms create false positives. The
# bias is toward heavy hitters whose names are unique enough.


GCC_COMPANY_KEYWORDS: tuple[str, ...] = (
    # Saudi Arabia
    "aramco", "saudi aramco", "sabic", "stc", "saudi telecom",
    "ma'aden", "maaden", "almarai", "al rajhi", "rajhi bank",
    "samba", "ncb", "saudi national bank", "snb", "tasi", "ntg",
    "zatca", "gosi", "absher", "tawakkalna", "saudia", "sar",
    "saudi airlines", "neom", "red sea global", "diriyah gate",
    "qiddiya", "roshn", "the line",
    # UAE
    "adnoc", "emaar", "etisalat", "du", "dewa", "ewa", "ewec",
    "fab", "first abu dhabi", "emirates nbd", "enbd",
    "emirates", "etihad", "flydubai", "air arabia",
    "majid al futtaim", "lulu group", "al-futtaim", "al futtaim",
    "mubadala", "dp world", "adq", "tdra",
    "salik", "darb", "rta", "dubai roads",
    # Qatar
    "qatarenergy", "qatar energy", "qatar petroleum",
    "qatar airways", "ooredoo", "vodafone qatar", "qnb",
    "commercial bank of qatar", "doha bank", "qatar national bank",
    "msheireb",
    # Kuwait
    "kuwait petroleum", "knpc", "kpc", "boubyan", "nbk",
    "national bank of kuwait", "kuwait airways", "stc kuwait",
    "kfh", "kuwait finance house", "zain",
    # Bahrain
    "alba", "aluminium bahrain", "bapco", "gulf air",
    "ahli united", "national bank of bahrain",
    "bisb", "abc bahrain",
    # Oman
    "petroleum development oman", "pdo", "omantel", "omanair",
    "bank muscat", "nbo", "national bank of oman",
    "duqm", "salalah port",
    # Egypt
    "telecom egypt", "we egypt", "vodafone egypt", "orange egypt",
    "national bank of egypt", "nbe", "cib", "qnb alahli",
    "egyptair", "suez canal", "scct", "egypt sugar",
    "edita", "olympic group", "talaat moustafa",
)


# ── City / region keywords (used for low-confidence boosts) ──────────


GCC_CITY_KEYWORDS: tuple[str, ...] = (
    "riyadh", "jeddah", "dammam", "mecca", "makkah", "medina",
    "madinah", "khobar", "yanbu", "al ula", "al-ula", "neom",
    "abu dhabi", "dubai", "sharjah", "ajman", "fujairah",
    "ras al khaimah", "rak", "umm al quwain",
    "doha", "lusail", "al wakrah",
    "kuwait city", "salmiya", "hawalli",
    "manama", "muharraq",
    "muscat", "sohar", "salalah", "duqm",
    "cairo", "alexandria", "giza", "sharm el sheikh", "luxor",
)


# ── Watchlist of groups MEGA_PHASE.md called out by name ─────────────


WATCHLIST_GROUPS: frozenset[str] = frozenset({
    "ransomhub", "akira", "play", "playcrypt", "qilin", "agenda",
    "lockbit", "lockbit3", "lockbit3.0", "lockbit-ng", "dragonforce",
    "blacksuit", "hunters", "hunters international", "inc",
    "inc ransom", "inc.ransom",
})


# ── Scoring ──────────────────────────────────────────────────────────


@dataclass
class GccRelevanceScore:
    """Outcome of a single victim-post evaluation."""

    is_gcc: bool
    confidence: float
    signals: list[str] = field(default_factory=list)
    matched_country: str | None = None
    matched_cctld: str | None = None
    matched_company_keyword: str | None = None
    matched_city_keyword: str | None = None
    has_arabic: bool = False
    watchlisted_group: bool = False

    def to_dict(self) -> dict:
        return {
            "is_gcc": self.is_gcc,
            "confidence": round(self.confidence, 3),
            "signals": self.signals,
            "matched_country": self.matched_country,
            "matched_cctld": self.matched_cctld,
            "matched_company_keyword": self.matched_company_keyword,
            "matched_city_keyword": self.matched_city_keyword,
            "has_arabic": self.has_arabic,
            "watchlisted_group": self.watchlisted_group,
        }


# Confidence threshold above which the entry is treated as GCC-relevant
# downstream. Tunable from settings later if needed.
GCC_CONFIDENCE_THRESHOLD = 0.65


def _has_arabic_letters(text: str) -> bool:
    """Detect Arabic-script characters (U+0600..U+06FF and supplementary
    blocks). One letter is enough — names like 'ARAMCO السعودية' should
    flag even when the Latin half is brand-only."""
    if not text:
        return False
    for ch in text:
        cp = ord(ch)
        if 0x0600 <= cp <= 0x06FF or 0x0750 <= cp <= 0x077F or \
           0x08A0 <= cp <= 0x08FF or 0xFB50 <= cp <= 0xFDFF or \
           0xFE70 <= cp <= 0xFEFF:
            return True
    return False


def _normalise(text: str) -> str:
    """Lower-case, strip accents, collapse whitespace, drop punctuation
    that breaks substring matching ('al-rajhi' vs 'al rajhi')."""
    if not text:
        return ""
    nfkd = unicodedata.normalize("NFKD", text)
    no_accents = "".join(c for c in nfkd if not unicodedata.combining(c))
    lowered = no_accents.lower()
    cleaned = re.sub(r"[\-_/\\.]+", " ", lowered)
    return re.sub(r"\s+", " ", cleaned).strip()


def _extract_cctld_from_url_or_domain(s: str) -> str | None:
    """Best-effort extraction of the GCC ccTLD suffix from a URL or
    bare domain. Returns the matched suffix (with leading dot) or None.
    Order matters — longer suffixes (.com.sa) must win over .sa."""
    if not s:
        return None
    candidate = s.strip().lower()
    try:
        parsed = urlparse(candidate if "://" in candidate else f"http://{candidate}")
        host = parsed.hostname or candidate
    except Exception:
        host = candidate
    host = host.strip(".").lower()
    for suffix in sorted(GCC_CCTLDS, key=len, reverse=True):
        if host.endswith(suffix):
            return suffix
    return None


def _normalise_group_name(group: str | None) -> str:
    if not group:
        return ""
    return re.sub(r"[\s\-._]+", "", group.lower())


def _match_keyword(text_norm: str, keywords: Iterable[str]) -> str | None:
    for kw in keywords:
        kw_norm = _normalise(kw)
        if not kw_norm:
            continue
        # Word-boundary match — substring would over-match (e.g. "du"
        # in "Saudi" would false-positive). We rebuild the haystack
        # with single-space separators in _normalise so a word match
        # is a space-padded substring lookup.
        if f" {kw_norm} " in f" {text_norm} ":
            return kw
    return None


def score_gcc_relevance(
    *,
    victim_name: str | None,
    country: str | None = None,
    url: str | None = None,
    sector: str | None = None,
    group: str | None = None,
    description: str | None = None,
) -> GccRelevanceScore:
    """Score a ransomware DLS victim record for GCC relevance.

    Pure function — no IO, deterministic. The caller passes whatever
    the upstream feed exposes; missing fields contribute 0 confidence.
    """
    score = GccRelevanceScore(is_gcc=False, confidence=0.0)

    # 1. Country code — strongest signal when present.
    cc = (country or "").strip().upper()
    if cc and cc in GCC_COUNTRY_CODES:
        score.matched_country = cc
        score.confidence += 0.85
        score.signals.append(f"country={cc}")

    # 2. ccTLD on the victim URL or victim name (if it looks like a domain).
    cctld = _extract_cctld_from_url_or_domain(url or "")
    if cctld is None:
        # Some feeds put the domain into the victim name. Try that.
        cctld = _extract_cctld_from_url_or_domain(victim_name or "")
    if cctld:
        score.matched_cctld = cctld
        score.confidence += 0.6
        score.signals.append(f"cctld={cctld}")

    # 3. Arabic letters in the victim name or description.
    haystack_for_arabic = " ".join(filter(None, [victim_name, description]))
    if _has_arabic_letters(haystack_for_arabic):
        score.has_arabic = True
        score.confidence += 0.4
        score.signals.append("arabic_letters")

    # 4. Company / brand keyword fuzzy match.
    norm_text = _normalise(" ".join(filter(None, [
        victim_name, description, sector,
    ])))
    company_match = _match_keyword(norm_text, GCC_COMPANY_KEYWORDS)
    if company_match:
        score.matched_company_keyword = company_match
        # Curated GCC brands are unique enough that a single match is
        # high-confidence on its own (e.g. "ARAMCO leak" with no country
        # or ccTLD must clear the threshold).
        score.confidence += 0.7
        score.signals.append(f"company={company_match}")

    # 5. City / region keyword fuzzy match.
    city_match = _match_keyword(norm_text, GCC_CITY_KEYWORDS)
    if city_match:
        score.matched_city_keyword = city_match
        score.confidence += 0.25
        score.signals.append(f"city={city_match}")

    # 6. Watchlisted group bump (only when at least one other signal fired).
    group_norm = _normalise_group_name(group)
    if group_norm and group_norm in WATCHLIST_GROUPS:
        score.watchlisted_group = True
        if score.confidence > 0:
            score.confidence += 0.1
            score.signals.append(f"watchlist_group={group}")

    # Cap at 1.0 and decide.
    score.confidence = min(score.confidence, 1.0)
    score.is_gcc = score.confidence >= GCC_CONFIDENCE_THRESHOLD
    return score


def is_gcc_victim(score: GccRelevanceScore) -> bool:
    """Convenience wrapper kept symmetric with the model used in tests."""
    return score.is_gcc
