"""Extract IOCs / CVEs / MITRE techniques / threat-actor names from text.

Pure regex / dictionary-based — no NER model dependency. The output is
fed into:

  * /iocs    (IPs, domains, URLs, hashes, emails) via canonical upsert
  * /mitre   (T#### attachments to the article entity)
  * /actors  (fuzzy-match against ThreatActor + MitreGroup aliases)

Defang-aware: recognises ``hxxp://`` / ``[.]`` / ``[at]`` and refangs
before classifying.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# --------------------------- defanging ---------------------------------

_REFANG_REPLACEMENTS = (
    (re.compile(r"\bhxxps?://", re.I), "http://"),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\[dot\]", re.I), "."),
    (re.compile(r"\[at\]", re.I), "@"),
    (re.compile(r"\(at\)", re.I), "@"),
    (re.compile(r"\[:\]"), ":"),
)


def refang(text: str) -> str:
    """Convert defanged IOC notation back to canonical form."""
    if not text:
        return text
    out = text
    for pat, repl in _REFANG_REPLACEMENTS:
        out = pat.sub(repl, out)
    return out


def defang(value: str) -> str:
    """Convert a canonical IOC into a safe-to-display defanged form."""
    return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]").replace("@", "[at]")


# --------------------------- patterns ---------------------------------

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_T_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
_IPV6 = re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.I)
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|co|app|dev|info|biz|us|uk|eu|de|fr|cn|ru|jp|kr|in|br|au|ca|"
    r"cz|pl|nl|es|it|me|gov|mil|edu|ai|cloud|tech|sh|xyz|to|ws|cc|tk|gq|ml|cf|ga)\b",
    re.I,
)
_URL = re.compile(r"\bhttps?://[^\s<>\"']+", re.I)
_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)

# Domains common in articles that are noise (the article URL itself,
# CDNs, social media). Skip them when extracting.
_NOISE_DOMAINS = frozenset(
    {
        "twitter.com",
        "x.com",
        "facebook.com",
        "linkedin.com",
        "youtube.com",
        "youtu.be",
        "github.com",
        "github.io",
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "wikipedia.org",
        "schema.org",
        "w3.org",
        "creativecommons.org",
        "doubleclick.net",
        "wordpress.com",
        "medium.com",
        "bleepingcomputer.com",
        "krebsonsecurity.com",
        "thehackernews.com",
        "darkreading.com",
        "securityweek.com",
        "schneier.com",
        "mandiant.com",
        "crowdstrike.com",
        "talosintelligence.com",
        "paloaltonetworks.com",
        "trendmicro.com",
        "checkpoint.com",
        "kaspersky.com",
        "securelist.com",
        "microsoft.com",
        "msrc.microsoft.com",
        "cisa.gov",
        "ncsc.gov.uk",
    }
)


@dataclass
class ExtractedIoc:
    type: str  # ip | ipv6 | domain | url | md5 | sha1 | sha256 | email
    value: str

    def as_dict(self) -> dict[str, str]:
        return {"type": self.type, "value": self.value}


@dataclass
class ExtractionResult:
    cves: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    iocs: list[ExtractedIoc] = field(default_factory=list)
    actor_names: list[str] = field(default_factory=list)


def _normalize_domain(d: str) -> str:
    d = d.strip(".").lower()
    return d


def _is_noise_domain(d: str) -> bool:
    return d in _NOISE_DOMAINS or any(
        d.endswith("." + n) for n in _NOISE_DOMAINS
    )


def extract_entities(
    text: str,
    *,
    actor_alias_lookup: Iterable[tuple[str, str]] = (),
) -> ExtractionResult:
    """Extract IOCs, CVEs, MITRE techniques, and threat-actor mentions.

    ``actor_alias_lookup`` is an iterable of (alias_lowercase, canonical_id)
    pairs. Caller passes (MitreGroup.aliases ∪ ThreatActor.aliases).
    Match is whole-word, case-insensitive, length>=4 to keep precision up.
    """
    if not text:
        return ExtractionResult()

    refanged = refang(text)
    res = ExtractionResult()
    seen_ioc: set[tuple[str, str]] = set()

    # CVEs
    for m in _CVE.findall(refanged):
        m_up = m.upper()
        if m_up not in res.cves:
            res.cves.append(m_up)

    # MITRE technique IDs (T1234 / T1234.001)
    for m in _T_ID.findall(refanged):
        if m not in res.techniques:
            res.techniques.append(m)

    # IPs
    for m in _IPV4.findall(refanged):
        # Filter private + loopback + multicast.
        first = int(m.split(".")[0])
        if first in (10, 127) or m.startswith("192.168.") or m.startswith("172.16."):
            continue
        key = ("ip", m)
        if key not in seen_ioc:
            seen_ioc.add(key)
            res.iocs.append(ExtractedIoc("ip", m))

    for m in _IPV6.findall(refanged):
        if "::" not in m and ":" not in m:
            continue
        key = ("ipv6", m.lower())
        if key not in seen_ioc:
            seen_ioc.add(key)
            res.iocs.append(ExtractedIoc("ipv6", m.lower()))

    # URLs
    for m in _URL.findall(refanged):
        # Strip trailing punctuation common in prose.
        cleaned = m.rstrip(".,)\"'")
        key = ("url", cleaned.lower())
        if key not in seen_ioc:
            seen_ioc.add(key)
            res.iocs.append(ExtractedIoc("url", cleaned))

    # Domains (only keep what's not already in a URL above + not noise)
    url_hosts = {
        re.sub(r"^https?://", "", x.value, flags=re.I).split("/")[0].lower()
        for x in res.iocs
        if x.type == "url"
    }
    for m in _DOMAIN.findall(refanged):
        d = _normalize_domain(m)
        if d in url_hosts or _is_noise_domain(d):
            continue
        if "." not in d or len(d) > 253:
            continue
        key = ("domain", d)
        if key not in seen_ioc:
            seen_ioc.add(key)
            res.iocs.append(ExtractedIoc("domain", d))

    # File hashes — order matters: SHA256 then SHA1 then MD5 so longer
    # matches take precedence and aren't double-counted as MD5 substrings.
    for pat, kind in ((_SHA256, "sha256"), (_SHA1, "sha1"), (_MD5, "md5")):
        for m in pat.findall(refanged):
            key = (kind, m.lower())
            # If the same hex string already matched a longer hash type,
            # skip it (prevents an SHA-256 leading 32 chars being doubled
            # as an MD5).
            longer = False
            for existing_kind, existing_val in seen_ioc:
                if (
                    existing_kind in ("sha256", "sha1")
                    and existing_val.startswith(m.lower())
                ):
                    longer = True
                    break
            if longer:
                continue
            if key not in seen_ioc:
                seen_ioc.add(key)
                res.iocs.append(ExtractedIoc(kind, m.lower()))

    # Emails
    for m in _EMAIL.findall(refanged):
        key = ("email", m.lower())
        if key not in seen_ioc:
            seen_ioc.add(key)
            res.iocs.append(ExtractedIoc("email", m.lower()))

    # Threat actor name fuzzy match.
    text_lower = " " + re.sub(r"[^\w\s\-/.]", " ", refanged.lower()) + " "
    for alias_lc, canonical in actor_alias_lookup:
        if not alias_lc or len(alias_lc) < 4:
            continue
        # Whole-word match.
        if f" {alias_lc} " in text_lower or f" {alias_lc}." in text_lower:
            if canonical not in res.actor_names:
                res.actor_names.append(canonical)

    return res


__all__ = [
    "ExtractedIoc",
    "ExtractionResult",
    "extract_entities",
    "refang",
    "defang",
]
