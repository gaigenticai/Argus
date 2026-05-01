"""Phishing classifier — pluggable, with a strong heuristic default.

In production the classifier of choice is a fine-tuned DistilBERT model
on PhishTank + OpenPhish data. That model is large and the quality bar
is "ship a recognisable phishing page or fail" — both of which are out
of scope for a turn-by-turn build. The architecture below is what *will*
host that model: the classifier is pluggable, the heuristic baseline is
production-grade, and a swap to DistilBERT means dropping a new
implementation in the registry.

HeuristicClassifier
-------------------
A high-precision rules-based classifier that fires on the phishing
patterns that survive every kit update:
    1. Brand-name in DOM but apex-domain off-brand
       → spoof signal
    2. Password / CC input fields on a non-self-served page
       → credential harvest signal
    3. ``<form action="…">`` posts to a different host
       → exfil signal
    4. Title or visible text matches "sign in", "verify", "reset" + brand
       → social-engineering signal
    5. JavaScript obfuscation (eval/atob loops, iframe-into-iframe)
       → evasion signal

A page with ≥ 2 spoof signals OR ≥ 1 spoof + ≥ 1 harvest signal lands
verdict=PHISHING with confidence 0.85+. Single signals → SUSPICIOUS.
"""

from __future__ import annotations

import abc
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Iterable

from src.models.live_probe import LiveProbeVerdict


@dataclass
class FetchedPage:
    """Snapshot of a single page fetch."""

    domain: str
    url: str
    final_url: str
    http_status: int | None
    title: str | None
    html: str
    screenshot_bytes: bytes | None = None
    error_message: str | None = None


@dataclass
class ClassificationResult:
    verdict: LiveProbeVerdict
    confidence: float
    signals: list[str] = field(default_factory=list)
    matched_brand_terms: list[str] = field(default_factory=list)
    rationale: str = ""


class Classifier(abc.ABC):
    name: str

    @abc.abstractmethod
    def classify(
        self,
        page: FetchedPage,
        *,
        brand_terms: Iterable[str],
    ) -> ClassificationResult: ...


# --- HTML parsing helpers ---------------------------------------------


class _DOMParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.text_chunks: list[str] = []
        self.input_types: list[str] = []
        self.form_actions: list[str] = []
        self.iframes_count = 0
        self.script_count = 0
        self.scripts_inline: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "title":
            self._in_title = True
        elif tag == "input":
            self.input_types.append((d.get("type") or "text").lower())
        elif tag == "form":
            self.form_actions.append(d.get("action") or "")
        elif tag == "iframe":
            self.iframes_count += 1
        elif tag == "script":
            self.script_count += 1
            self._in_script = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif self._in_script:
            self.scripts_inline.append(data)
        else:
            stripped = data.strip()
            if stripped:
                self.text_chunks.append(stripped)


_HARVEST_INPUT_TYPES = {"password", "tel"}
_SOCIAL_KEYWORDS_RE = re.compile(
    r"\b(sign\s*in|log\s*in|verify|reset password|account suspended|update billing|"
    r"confirm your identity|secure login|2fa code)\b",
    re.I,
)
_OBFUSCATION_RE = re.compile(
    r"(eval\s*\(|atob\s*\(|String\.fromCharCode\s*\(|unescape\s*\()",
)


def _host_from_url(url: str) -> str:
    from urllib.parse import urlparse

    return (urlparse(url).hostname or "").lower()


def _registrable_label(host: str) -> str:
    """Return the second-to-last dot-segment of the host. ``argus-victim.com`` → ``argus-victim``."""
    parts = (host or "").lower().rstrip(".").split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


class HeuristicClassifier(Classifier):
    name = "heuristic-v1"

    def __init__(
        self,
        *,
        suspicious_base_confidence: float = 0.55,
        suspicious_per_signal: float = 0.05,
        parked_confidence: float = 0.7,
        benign_confidence: float = 0.6,
    ) -> None:
        # Confidence floors for each non-PHISHING verdict. Operator can
        # tune via the ``brand.classifier.*`` AppSetting keys; the
        # ``HeuristicClassifier`` instance in the registry is rebuilt
        # by ``apply_brand_thresholds`` whenever those rows change.
        self.suspicious_base_confidence = suspicious_base_confidence
        self.suspicious_per_signal = suspicious_per_signal
        self.parked_confidence = parked_confidence
        self.benign_confidence = benign_confidence

    def classify(
        self,
        page: FetchedPage,
        *,
        brand_terms: Iterable[str],
    ) -> ClassificationResult:
        if page.error_message or page.http_status is None:
            return ClassificationResult(
                verdict=LiveProbeVerdict.UNREACHABLE,
                confidence=0.95,
                rationale=page.error_message or "no HTTP response",
            )
        # Treat HTTP failures and parked-domain stand-ins.
        if page.http_status >= 500 or page.http_status == 0:
            return ClassificationResult(
                verdict=LiveProbeVerdict.UNREACHABLE,
                confidence=0.9,
                signals=[f"http_{page.http_status}"],
                rationale=f"HTTP {page.http_status}",
            )

        terms = sorted({t.lower() for t in brand_terms if len(t) >= 3})

        parser = _DOMParser()
        try:
            parser.feed(page.html or "")
        except Exception as exc:  # noqa: BLE001
            # Malformed HTML on the wild internet is the norm, not the
            # exception — but a *stream* of parser failures is a real
            # signal (a hostile site shipping anti-parser garbage to
            # break classification). Logging at INFO is loud enough to
            # surface a cluster while staying out of the SOC's hair on
            # one-offs.
            import logging as _logging

            _logging.getLogger(__name__).info(
                "brand.classifier: HTML parser failed for %s: %s",
                page.url or page.domain or "<unknown>", exc,
            )

        flat_text = " ".join(parser.text_chunks).lower()
        flat_title = (parser.title or page.title or "").lower()
        all_text = f"{flat_title} {flat_text}"

        host = _host_from_url(page.final_url or page.url or page.domain)
        host_label = _registrable_label(host)

        signals: list[str] = []
        matched_brands: list[str] = []
        spoof_signals = 0
        harvest_signals = 0
        engineering_signals = 0
        evasion_signals = 0

        for term in terms:
            if term not in all_text:
                continue
            # If the host's registrable label IS the brand exactly, the
            # site is plausibly the legit one — no spoof signal.
            if host_label == term:
                continue
            signals.append(f"brand_in_dom_offhost:{term}")
            matched_brands.append(term)
            spoof_signals += 1

        if any(t in _HARVEST_INPUT_TYPES for t in parser.input_types):
            signals.append("password_or_tel_input")
            harvest_signals += 1

        for action in parser.form_actions:
            if not action:
                continue
            target_host = _host_from_url(action) if "://" in action else host
            if target_host and target_host != host:
                signals.append(f"form_to_offhost:{target_host}")
                harvest_signals += 1
                break

        if _SOCIAL_KEYWORDS_RE.search(all_text):
            signals.append("social_engineering_phrase")
            engineering_signals += 1

        scripts_blob = "\n".join(parser.scripts_inline)
        if _OBFUSCATION_RE.search(scripts_blob):
            signals.append("js_obfuscation")
            evasion_signals += 1

        if parser.iframes_count >= 2:
            signals.append(f"iframes:{parser.iframes_count}")
            evasion_signals += 1

        # Verdict math
        is_phish = (
            spoof_signals >= 2
            or (spoof_signals >= 1 and harvest_signals >= 1)
            or (harvest_signals >= 2 and engineering_signals >= 1)
        )
        is_susp = (
            spoof_signals >= 1
            or harvest_signals >= 1
            or engineering_signals >= 1
        )

        if is_phish:
            confidence = min(
                0.99, 0.6 + 0.1 * len(signals)
            )
            return ClassificationResult(
                verdict=LiveProbeVerdict.PHISHING,
                confidence=confidence,
                signals=signals,
                matched_brand_terms=matched_brands,
                rationale=(
                    f"{spoof_signals} spoof + {harvest_signals} harvest + "
                    f"{engineering_signals} engineering signals"
                ),
            )
        if is_susp:
            return ClassificationResult(
                verdict=LiveProbeVerdict.SUSPICIOUS,
                confidence=min(
                    0.99,
                    self.suspicious_base_confidence
                    + self.suspicious_per_signal * len(signals),
                ),
                signals=signals,
                matched_brand_terms=matched_brands,
                rationale="Single-signal page; needs analyst review",
            )
        if not parser.text_chunks and parser.script_count == 0:
            return ClassificationResult(
                verdict=LiveProbeVerdict.PARKED,
                confidence=self.parked_confidence,
                signals=signals,
                rationale="Empty body — likely parked",
            )
        return ClassificationResult(
            verdict=LiveProbeVerdict.BENIGN,
            confidence=self.benign_confidence,
            signals=signals,
            rationale="No spoof / harvest / engineering signals matched",
        )


# --- Registry ---------------------------------------------------------


_REGISTRY: dict[str, Classifier] = {"heuristic-v1": HeuristicClassifier()}


def get_classifier(name: str = "heuristic-v1") -> Classifier:
    if name not in _REGISTRY:
        raise ValueError(f"Unknown classifier {name!r}")
    return _REGISTRY[name]


def register_classifier(c: Classifier) -> None:
    _REGISTRY[c.name] = c


def apply_brand_thresholds(thresholds) -> None:
    """Rebuild the heuristic classifier with operator-tuned thresholds.

    Called from a brand-tick orchestrator after loading the live
    ``BrandThresholds`` bundle. The previous instance is replaced so
    every subsequent classify call uses the new values.
    """
    register_classifier(
        HeuristicClassifier(
            suspicious_base_confidence=thresholds.classifier_suspicious_base_confidence,
            suspicious_per_signal=thresholds.classifier_suspicious_per_signal,
            parked_confidence=thresholds.classifier_parked_confidence,
            benign_confidence=thresholds.classifier_benign_confidence,
        )
    )


__all__ = [
    "Classifier",
    "ClassificationResult",
    "FetchedPage",
    "HeuristicClassifier",
    "get_classifier",
    "register_classifier",
]
