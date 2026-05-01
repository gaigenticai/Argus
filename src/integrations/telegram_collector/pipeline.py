"""Per-message processing pipeline (P3 #3.10).

A Telegram collector message goes through three stages before it's
ready for the case timeline:

  1. Language detection (``language.detect_language``)
  2. IOC extraction (``src.enrichment.ioc_extractor.extract_iocs``)
  3. Light heuristic flags — actor mentions, victim mentions, leak
     vs hacktivism vs carding categorisation. We deliberately keep
     this lightweight and rule-based; full LLM-summary translation
     happens downstream in ``src.agents.feed_triage``.

This module is pure-compute / no network — Telegram fetch happens in
``client.py`` and feeds messages here.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from src.enrichment.ioc_extractor import extract_iocs

from .language import LangCode, detect_language


# Coarse keyword cues per category — message-level, not author-level.
# Listed in lowercase; matched case-insensitively against the body.
_LEAK_CUES = (
    "leak", "dump", "doxx", "exfil", "stolen",
    "تسريب", "تسريبات",                    # Arabic "leak(s)"
    "نشت",                                  # Persian "leak"
)
_HACKTIVISM_CUES = (
    "ddos", "down for", "owned", "pwn3d",
    "اختراق", "هاكر",                      # Arabic "breach", "hacker"
    "هک", "هکرها",                          # Persian "hack", "hackers"
)
_CARDING_CUES = (
    "cc", "cvv", "fullz", "bin ", "bins ",
    "بطاقة", "بطاقات",                     # Arabic "card", "cards"
    "كارت",
)
_RANSOM_CUES = (
    "ransom", "decryptor", "encryptor",
    "lockbit", "alphv", "blackcat", "cl0p", "akira", "ransomhub",
    "فدية",                                 # Arabic "ransom"
)
_VICTIM_CALLOUT = re.compile(
    r"\b(victim|target|leaked from|exfiltrated from|"
    r"اخترقنا|سحبنا|هاجمنا|"
    r"قربانی|هدف)\b",
    re.IGNORECASE,
)


def _flag_categories(text: str) -> list[str]:
    """Best-effort categorisation cues; multiple may fire."""
    t = text.lower()
    cats: list[str] = []
    if any(c in t for c in _LEAK_CUES):
        cats.append("leak")
    if any(c in t for c in _HACKTIVISM_CUES):
        cats.append("hacktivism")
    if any(c in t for c in _CARDING_CUES):
        cats.append("carding")
    if any(c in t for c in _RANSOM_CUES):
        cats.append("ransomware")
    return cats


@dataclass
class ProcessedMessage:
    """Pipeline output. Persisted as a row on the alert / source-event
    timeline; the IOC list is split off into the IOC table."""

    channel: str
    message_id: int | None
    text: str
    language: LangCode
    iocs: list[dict[str, Any]] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    has_victim_callout: bool = False
    sender_id: int | None = None
    posted_at: str | None = None    # ISO-8601 string
    raw: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Avoid leaking ``raw`` into the dashboard payload by default.
        d.pop("raw", None)
        return d


def process_message(
    text: str, *,
    channel: str,
    message_id: int | None = None,
    sender_id: int | None = None,
    posted_at: str | None = None,
    raw: dict[str, Any] | None = None,
) -> ProcessedMessage:
    """Run the language + IOC + category pipeline over one message body."""
    lang = detect_language(text or "")
    iocs = extract_iocs(text or "")
    return ProcessedMessage(
        channel=channel,
        message_id=message_id,
        text=text or "",
        language=lang,
        iocs=[{
            "type": ioc.ioc_type.value,
            "value": ioc.value,
            "confidence": ioc.confidence,
            "context_snippet": ioc.context_snippet,
        } for ioc in iocs],
        categories=_flag_categories(text or ""),
        has_victim_callout=bool(_VICTIM_CALLOUT.search(text or "")),
        sender_id=sender_id,
        posted_at=posted_at,
        raw=raw,
    )


def process_messages(
    messages: list[dict[str, Any]],
) -> list[ProcessedMessage]:
    """Batch convenience: each input dict needs ``text`` + ``channel``;
    other fields are forwarded if present."""
    out: list[ProcessedMessage] = []
    for m in messages:
        if not isinstance(m, dict):
            continue
        out.append(process_message(
            text=m.get("text") or "",
            channel=m.get("channel") or "",
            message_id=m.get("message_id"),
            sender_id=m.get("sender_id"),
            posted_at=m.get("posted_at"),
            raw=m.get("raw"),
        ))
    return out
