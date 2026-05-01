"""Arabic phishing pretext detector (P1 #1.6).

Pure analyzer over a piece of email-or-message content. Returns a
structured scoreboard the caller can attach to alert.details, render
in the dashboard, or feed into the triage agent's prompt.

Five detection families:

  1. Homoglyph substitution
     - Latin look-alikes from Cyrillic / Greek / Cherokee / IPA
       (e.g. "ARAMCO" with the Cyrillic 'А' in place of Latin 'A')
     - Arabic-Indic digits (٠–٩) used to mimic Latin digits in URLs
       and totals
  2. Bidi-control abuse
     - U+202E RIGHT-TO-LEFT OVERRIDE and friends, used to disguise
       file extensions and URL paths
  3. Mixed-script IDN
     - A domain label whose codepoints span more than one Unicode
       script (e.g. "aramco.com" with the 'a' as Cyrillic 'а')
  4. GCC pretext patterns
     - 12 curated pretext families covering Hajj/Umrah, government
       services (Absher / Tawakkalna / TAM / ICA / UAE Pass / Nafath),
       energy-bonus, airline refunds, ZATCA tax refunds, GOSI / TASI
       subsidies, Ramadan e-cards, utility bills (SEC / DEWA / EWA),
       toll fines (Salik / Darb), and traffic fines (Saher / Muroor)
  5. Brand impersonation
     - Substring match against the same curated GCC company keywords
       used by :mod:`src.intel.gcc_ransomware_filter` — when a brand
       hit co-occurs with any of (1)–(3) the analyzer flags
       impersonation rather than legitimate brand mention

The analyzer is language-aware where it matters (Arabic vs Latin
patterns) but works on raw mixed-script content end-to-end.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse


# ── Latin look-alike codepoints ──────────────────────────────────────


# Per Unicode TR39 confusables data, narrowed to the codepoints actually
# observed in real-world phishing. Keys are the visually-Latin look-alike
# codepoint; values are (real_latin, source_script).
LATIN_LOOKALIKES: dict[str, tuple[str, str]] = {
    # Cyrillic
    "А": ("A", "Cyrillic"), "В": ("B", "Cyrillic"), "Е": ("E", "Cyrillic"),
    "К": ("K", "Cyrillic"), "М": ("M", "Cyrillic"), "Н": ("H", "Cyrillic"),
    "О": ("O", "Cyrillic"), "Р": ("P", "Cyrillic"), "С": ("C", "Cyrillic"),
    "Т": ("T", "Cyrillic"), "Х": ("X", "Cyrillic"), "У": ("Y", "Cyrillic"),
    "а": ("a", "Cyrillic"), "е": ("e", "Cyrillic"), "о": ("o", "Cyrillic"),
    "р": ("p", "Cyrillic"), "с": ("c", "Cyrillic"), "у": ("y", "Cyrillic"),
    "х": ("x", "Cyrillic"), "і": ("i", "Cyrillic"), "ј": ("j", "Cyrillic"),
    # Greek
    "Α": ("A", "Greek"), "Β": ("B", "Greek"), "Ε": ("E", "Greek"),
    "Η": ("H", "Greek"), "Ι": ("I", "Greek"), "Κ": ("K", "Greek"),
    "Μ": ("M", "Greek"), "Ν": ("N", "Greek"), "Ο": ("O", "Greek"),
    "Ρ": ("P", "Greek"), "Τ": ("T", "Greek"), "Χ": ("X", "Greek"),
    "Υ": ("Y", "Greek"), "Ζ": ("Z", "Greek"),
    "α": ("a", "Greek"), "ο": ("o", "Greek"), "ρ": ("p", "Greek"),
    # Mathematical alphanumeric (used by attackers to evade naive ASCII
    # comparison). Common ones only.
    "𝐀": ("A", "MathAlpha"), "𝐁": ("B", "MathAlpha"),
    "𝟎": ("0", "MathDigit"), "𝟏": ("1", "MathDigit"),
    "𝟐": ("2", "MathDigit"), "𝟑": ("3", "MathDigit"),
    "𝟒": ("4", "MathDigit"), "𝟓": ("5", "MathDigit"),
    "𝟔": ("6", "MathDigit"), "𝟕": ("7", "MathDigit"),
    "𝟖": ("8", "MathDigit"), "𝟗": ("9", "MathDigit"),
    # Arabic-Indic digits used to mimic Latin digits in URLs / amounts.
    "٠": ("0", "Arabic"), "١": ("1", "Arabic"), "٢": ("2", "Arabic"),
    "٣": ("3", "Arabic"), "٤": ("4", "Arabic"), "٥": ("5", "Arabic"),
    "٦": ("6", "Arabic"), "٧": ("7", "Arabic"), "٨": ("8", "Arabic"),
    "٩": ("9", "Arabic"),
    # Eastern Arabic-Indic digits (Persian)
    "۰": ("0", "Persian"), "۱": ("1", "Persian"), "۲": ("2", "Persian"),
    "۳": ("3", "Persian"), "۴": ("4", "Persian"), "۵": ("5", "Persian"),
    "۶": ("6", "Persian"), "۷": ("7", "Persian"), "۸": ("8", "Persian"),
    "۹": ("9", "Persian"),
}


# ── Bidi control characters ─────────────────────────────────────────


BIDI_CONTROL_CHARS: dict[str, str] = {
    "‪": "LRE — Left-to-Right Embedding",
    "‫": "RLE — Right-to-Left Embedding",
    "‬": "PDF — Pop Directional Formatting",
    "‭": "LRO — Left-to-Right Override",
    "‮": "RLO — Right-to-Left Override",
    "⁦": "LRI — Left-to-Right Isolate",
    "⁧": "RLI — Right-to-Left Isolate",
    "⁨": "FSI — First Strong Isolate",
    "⁩": "PDI — Pop Directional Isolate",
}


# ── GCC pretext catalog ─────────────────────────────────────────────


# Each pretext gets:
#   id          short identifier used in the output
#   label       human-readable name
#   keywords    tuple of substrings — at least one must appear (case- and
#               diacritic-insensitive). Mixed Arabic + English. The
#               analyzer is intentionally permissive — short keywords
#               combined with the homoglyph / RTL-override signals
#               surface real campaigns without false-positive on an
#               innocent newsletter.

PRETEXTS: list[dict] = [
    {
        "id": "hajj_umrah",
        "label": "Hajj / Umrah religious-obligation pretext",
        "keywords": (
            "hajj", "umrah", "hajj registration", "umrah voucher",
            "حج", "عمرة", "تسجيل الحج", "قسيمة العمرة",
            "moi hajj", "moi umrah", "nusuk", "tasreeh",
        ),
    },
    {
        "id": "ksa_gov_services",
        "label": "KSA gov-service login pretext (Absher / Tawakkalna / TAM)",
        "keywords": (
            "absher", "tawakkalna", "tam ksa", "tam.gov", "tam app",
            "أبشر", "توكلنا", "تم",
            "moi ksa", "absher business", "muqeem",
        ),
    },
    {
        "id": "uae_gov_services",
        "label": "UAE gov-service login pretext (ICA / UAE Pass / Nafath)",
        "keywords": (
            "ica uae", "ica smart", "uae pass", "uaepass", "nafath",
            "هوية", "إقامة الإمارات", "نفاذ",
            "moi uae", "icp gov", "icp.gov.ae",
        ),
    },
    {
        "id": "energy_bonus",
        "label": "Energy-sector bonus pretext (Aramco / ADNOC / QatarEnergy)",
        "keywords": (
            "aramco bonus", "saudi aramco bonus", "aramco salary",
            "adnoc bonus", "adnoc reward", "adnoc salary",
            "qatarenergy bonus", "qatar energy bonus",
            "مكافأة أرامكو", "أرامكو مكافأة", "مكافأة أدنوك",
        ),
    },
    {
        "id": "airline_refund",
        "label": "Airline refund pretext (Saudia / Etihad / flydubai / Emirates)",
        "keywords": (
            "saudia refund", "saudi airlines refund", "sv refund",
            "etihad refund", "ey refund", "etihad rewards",
            "flydubai refund", "fz refund", "emirates refund",
            "ek refund", "skywards refund",
            "استرداد سعودية", "استرداد الاتحاد", "استرداد طيران الإمارات",
        ),
    },
    {
        "id": "zatca_tax_refund",
        "label": "ZATCA tax-refund pretext (KSA)",
        "keywords": (
            "zatca", "zakat tax", "vat refund ksa", "ضريبة",
            "هيئة الزكاة والضريبة", "استرداد الضريبة",
            "zatca refund", "vat return ksa",
        ),
    },
    {
        "id": "gosi_tasi_subsidy",
        "label": "GOSI / TASI social-subsidy pretext",
        "keywords": (
            "gosi", "tasi", "tasi support", "saned", "ساند",
            "التأمينات الاجتماعية", "حساب المواطن",
            "gosi update", "gosi subsidy",
        ),
    },
    {
        "id": "ramadan_ecard",
        "label": "Ramadan / Eid e-card pretext",
        "keywords": (
            "ramadan kareem", "ramadan greetings", "eid mubarak",
            "ramadan ecard", "ramadan e-card", "eid e-card",
            "رمضان كريم", "عيد مبارك", "بطاقة عيد",
            "ramadan offer", "ramadan voucher",
        ),
    },
    {
        "id": "uae_pass_otp",
        "label": "UAE Pass / Nafath OTP-stealing pretext",
        "keywords": (
            "uae pass otp", "uaepass code", "nafath otp",
            "نفاذ otp", "رمز نفاذ", "uae pass verify",
            "verify uae pass", "nafath verify",
        ),
    },
    {
        "id": "utility_bill",
        "label": "Utility-bill pretext (SEC / DEWA / EWA / Sewa)",
        "keywords": (
            "sec bill", "saudi electricity bill", "dewa bill",
            "dewa overdue", "ewa bahrain", "sewa sharjah",
            "kahramaa", "addc", "aadc",
            "فاتورة الكهرباء", "السعودية للكهرباء", "ديوا",
        ),
    },
    {
        "id": "toll_fine",
        "label": "Toll-system pretext (Salik / Darb)",
        "keywords": (
            "salik fine", "salik violation", "salik unpaid",
            "darb violation", "darb unpaid",
            "سالك", "درب",
        ),
    },
    {
        "id": "traffic_fine",
        "label": "Traffic-fine pretext (Saher / Muroor)",
        "keywords": (
            "saher fine", "saher violation", "muroor fine",
            "muroor violation", "uae traffic fine", "ksa traffic fine",
            "ساهر", "المرور",
            "absher traffic", "moi traffic fine",
        ),
    },
]


# Brand impersonation candidates — same list as the GCC ransomware
# filter; reusing keeps the curated set in one mental place.
from src.intel.gcc_ransomware_filter import GCC_COMPANY_KEYWORDS

# ── Result types ─────────────────────────────────────────────────────


@dataclass
class Homoglyph:
    char: str
    real_char: str
    source_script: str
    position: int

    def to_dict(self) -> dict:
        return {
            "char": self.char,
            "real_char": self.real_char,
            "source_script": self.source_script,
            "position": self.position,
        }


@dataclass
class BidiControlHit:
    char: str
    name: str
    position: int

    def to_dict(self) -> dict:
        return {"char": self.char, "name": self.name, "position": self.position}


@dataclass
class MixedScriptDomain:
    domain: str
    scripts: list[str]

    def to_dict(self) -> dict:
        return {"domain": self.domain, "scripts": self.scripts}


@dataclass
class PretextHit:
    id: str
    label: str
    matched_keyword: str

    def to_dict(self) -> dict:
        return {
            "id": self.id, "label": self.label,
            "matched_keyword": self.matched_keyword,
        }


@dataclass
class PhishingScore:
    """Aggregate score returned by :func:`analyze_message`."""

    confidence: float
    is_phish: bool
    homoglyphs: list[Homoglyph] = field(default_factory=list)
    bidi_overrides: list[BidiControlHit] = field(default_factory=list)
    mixed_script_domains: list[MixedScriptDomain] = field(default_factory=list)
    pretexts: list[PretextHit] = field(default_factory=list)
    impersonated_brands: list[str] = field(default_factory=list)
    has_arabic: bool = False

    def to_dict(self) -> dict:
        return {
            "confidence": round(self.confidence, 3),
            "is_phish": self.is_phish,
            "homoglyphs": [h.to_dict() for h in self.homoglyphs],
            "bidi_overrides": [b.to_dict() for b in self.bidi_overrides],
            "mixed_script_domains": [d.to_dict() for d in self.mixed_script_domains],
            "pretexts": [p.to_dict() for p in self.pretexts],
            "impersonated_brands": self.impersonated_brands,
            "has_arabic": self.has_arabic,
        }


PHISHING_THRESHOLD = 0.6


# ── Detection helpers ────────────────────────────────────────────────


def _script_of(ch: str) -> str | None:
    """Best-effort script classification using Unicode block names."""
    cp = ord(ch)
    if cp < 0x80:
        return "Latin" if ch.isalnum() else None
    if 0x0400 <= cp <= 0x04FF:
        return "Cyrillic"
    if 0x0370 <= cp <= 0x03FF:
        return "Greek"
    if 0x0600 <= cp <= 0x06FF or 0x0750 <= cp <= 0x077F or 0x08A0 <= cp <= 0x08FF \
       or 0xFB50 <= cp <= 0xFDFF or 0xFE70 <= cp <= 0xFEFF:
        return "Arabic"
    if 0x0590 <= cp <= 0x05FF:
        return "Hebrew"
    if 0x4E00 <= cp <= 0x9FFF:
        return "Han"
    if 0x13A0 <= cp <= 0x13FF:
        return "Cherokee"
    return None


def detect_homoglyphs(text: str) -> list[Homoglyph]:
    if not text:
        return []
    hits: list[Homoglyph] = []
    for i, ch in enumerate(text):
        if ch in LATIN_LOOKALIKES:
            real, src = LATIN_LOOKALIKES[ch]
            hits.append(Homoglyph(char=ch, real_char=real,
                                  source_script=src, position=i))
    return hits


def detect_bidi_overrides(text: str) -> list[BidiControlHit]:
    if not text:
        return []
    hits: list[BidiControlHit] = []
    for i, ch in enumerate(text):
        if ch in BIDI_CONTROL_CHARS:
            hits.append(BidiControlHit(char=ch, name=BIDI_CONTROL_CHARS[ch],
                                       position=i))
    return hits


def detect_mixed_script_domains(urls: Iterable[str]) -> list[MixedScriptDomain]:
    out: list[MixedScriptDomain] = []
    for u in urls or []:
        if not u:
            continue
        try:
            parsed = urlparse(u if "://" in u else f"http://{u}")
            host = parsed.hostname or u
        except Exception:
            host = u
        labels = (host or "").split(".")
        for label in labels:
            if len(label) <= 2:
                continue
            scripts = set()
            for ch in label:
                s = _script_of(ch)
                if s and s != "Latin" or s == "Latin":
                    if s:
                        scripts.add(s)
            # Mixed only if it contains at least Latin AND something else,
            # OR more than one non-Latin script in a single label.
            non_latin = scripts - {"Latin"}
            if "Latin" in scripts and non_latin:
                out.append(MixedScriptDomain(
                    domain=host or label, scripts=sorted(scripts),
                ))
                break
            if len(non_latin) > 1:
                out.append(MixedScriptDomain(
                    domain=host or label, scripts=sorted(scripts),
                ))
                break
    return out


def _has_arabic(text: str) -> bool:
    return any(_script_of(ch) == "Arabic" for ch in (text or ""))


def _normalise(text: str) -> str:
    if not text:
        return ""
    nfkd = unicodedata.normalize("NFKD", text)
    no_accents = "".join(c for c in nfkd if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", no_accents.lower()).strip()


def detect_pretexts(text: str) -> list[PretextHit]:
    if not text:
        return []
    norm = _normalise(text)
    hits: list[PretextHit] = []
    seen_ids: set[str] = set()
    for entry in PRETEXTS:
        for kw in entry["keywords"]:
            kw_norm = _normalise(kw)
            if not kw_norm:
                continue
            # word-boundary-ish: substring search in space-padded haystack
            if f" {kw_norm} " in f" {norm} " or kw_norm in norm:
                if entry["id"] in seen_ids:
                    break
                seen_ids.add(entry["id"])
                hits.append(PretextHit(
                    id=entry["id"], label=entry["label"], matched_keyword=kw,
                ))
                break
    return hits


def _resolve_homoglyphs(text: str) -> str:
    """Substitute every Latin look-alike character back to its
    canonical Latin form. ``ARАMCO`` (with Cyrillic А) becomes
    ``ARAMCO`` so brand-keyword matching catches the impersonation."""
    if not text:
        return ""
    return "".join(LATIN_LOOKALIKES[ch][0] if ch in LATIN_LOOKALIKES else ch
                   for ch in text)


def detect_brand_impersonation(text: str) -> list[str]:
    """Return GCC brand keywords mentioned in the text after resolving
    homoglyph substitutions. Caller decides whether the mention is
    legitimate or impersonation based on the co-occurrence with
    homoglyph / RTL / mixed-script signals."""
    if not text:
        return []
    # Normalise homoglyphs first — an attacker writing 'аramco' (Cyrillic)
    # is still impersonating Aramco; a strict-Latin keyword match would
    # miss this exact case the analyzer is built to catch.
    norm = _normalise(_resolve_homoglyphs(text))
    out: list[str] = []
    for kw in GCC_COMPANY_KEYWORDS:
        kn = _normalise(kw)
        if not kn:
            continue
        if f" {kn} " in f" {norm} ":
            out.append(kw)
    return out


# ── Main entry point ────────────────────────────────────────────────


_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def _extract_urls(*texts: str) -> list[str]:
    out: list[str] = []
    for t in texts:
        if not t:
            continue
        out.extend(_URL_RE.findall(t))
    return out


def analyze_message(
    *,
    subject: str = "",
    body: str = "",
    sender: str = "",
    urls: Iterable[str] | None = None,
) -> PhishingScore:
    """Run the full analyzer over an email-like message.

    All fields are optional — pass whatever the caller has.
    """
    combined = " ".join(filter(None, [subject, body]))

    homoglyphs = detect_homoglyphs(combined) + detect_homoglyphs(sender)
    bidi = detect_bidi_overrides(combined) + detect_bidi_overrides(sender)

    url_list = list(urls or []) + _extract_urls(combined, sender)
    mixed = detect_mixed_script_domains(url_list)

    pretexts = detect_pretexts(combined)
    brands = detect_brand_impersonation(combined)
    arabic = _has_arabic(combined)

    score = 0.0
    if homoglyphs:
        # Single homoglyph in a brand-context is a strong signal; saturate
        # quickly so 5 vs 50 hits don't materially differ.
        score += min(0.5 + 0.05 * (len(homoglyphs) - 1), 0.7)
    if bidi:
        # RTL-override in user-content is almost always malicious — crosses
        # the threshold on its own so the analyzer flags a one-off
        # "invoice‮gpj.exe" filename trick without any other signal.
        score += 0.65
    if mixed:
        score += 0.5
    if pretexts:
        score += min(0.3 + 0.1 * (len(pretexts) - 1), 0.5)
    if brands and (homoglyphs or bidi or mixed):
        # Brand mention combined with any deception signal = impersonation.
        score += 0.3

    score = min(score, 1.0)
    return PhishingScore(
        confidence=score,
        is_phish=score >= PHISHING_THRESHOLD,
        homoglyphs=homoglyphs,
        bidi_overrides=bidi,
        mixed_script_domains=mixed,
        pretexts=pretexts,
        impersonated_brands=brands if (homoglyphs or bidi or mixed) else [],
        has_arabic=arabic,
    )
