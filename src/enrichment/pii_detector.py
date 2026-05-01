"""PII detection and redaction module — SSN, credit cards, phone numbers, emails."""

from __future__ import annotations


import re
from dataclasses import dataclass


@dataclass
class PIIMatch:
    pii_type: str
    value: str
    start: int
    end: int


# --- Regex Patterns ---

_SSN_RE = re.compile(r"\b(\d{3}-\d{2}-\d{4})\b")

# Credit card: 13-19 digit sequences (with optional spaces/dashes between groups)
_CC_RAW_RE = re.compile(r"\b(\d[\d\s\-]{11,22}\d)\b")

# US phone numbers: various formats
_PHONE_US_RE = re.compile(
    r"(?<!\d)"
    r"(?:"
    r"\+?1[\s.-]?"                       # optional country code
    r")?"
    r"(?:"
    r"\(?\d{3}\)?[\s.-]?"                # area code
    r"\d{3}[\s.-]?"                      # exchange
    r"\d{4}"                             # subscriber
    r")"
    r"(?!\d)"
)

# International phone: +XX followed by 7-14 digits with optional separators
_PHONE_INTL_RE = re.compile(
    r"(?<!\d)"
    r"\+(?!1[\s.-]?\(?\d{3})"           # exclude US numbers already matched
    r"(\d{1,3}[\s.-]?\d{1,4}[\s.-]?\d{1,4}[\s.-]?\d{1,4}[\s.-]?\d{0,4})"
    r"(?!\d)"
)

# Email addresses
_EMAIL_RE = re.compile(
    r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"
)


# --- Luhn Algorithm ---


def _luhn_check(number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    # Luhn: starting from rightmost digit, double every second digit
    total = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d

    return total % 10 == 0


def _extract_cc_digits(raw: str) -> str:
    """Strip separators from a potential credit card match."""
    return re.sub(r"[\s\-]", "", raw)


# --- Detection ---


def detect_pii(text: str) -> list[PIIMatch]:
    """Detect PII in text. Returns list of PIIMatch with type, value, and positions."""
    matches: list[PIIMatch] = []
    seen_ranges: set[tuple[int, int]] = set()

    def _add(pii_type: str, value: str, start: int, end: int) -> None:
        key = (start, end)
        if key not in seen_ranges:
            seen_ranges.add(key)
            matches.append(PIIMatch(pii_type=pii_type, value=value, start=start, end=end))

    # SSNs
    for m in _SSN_RE.finditer(text):
        _add("ssn", m.group(1), m.start(1), m.end(1))

    # Credit cards (Luhn-validated)
    for m in _CC_RAW_RE.finditer(text):
        raw = m.group(1)
        digits = _extract_cc_digits(raw)
        if digits.isdigit() and 13 <= len(digits) <= 19 and _luhn_check(digits):
            # Make sure it's not an SSN we already caught
            if not _SSN_RE.match(raw):
                _add("credit_card", raw, m.start(1), m.end(1))

    # Emails (before phone to avoid false overlap)
    for m in _EMAIL_RE.finditer(text):
        _add("email", m.group(1), m.start(1), m.end(1))

    # US phone numbers
    for m in _PHONE_US_RE.finditer(text):
        val = m.group(0)
        digits_only = re.sub(r"\D", "", val)
        # Must have 10 or 11 digits to be a valid US phone
        if len(digits_only) in (10, 11):
            # Skip if this range overlaps with an SSN or CC
            overlaps = any(
                not (m.end() <= existing.start or m.start() >= existing.end)
                for existing in matches
            )
            if not overlaps:
                _add("phone", val, m.start(), m.end())

    # International phone numbers
    for m in _PHONE_INTL_RE.finditer(text):
        full = "+" + m.group(1)
        digits_only = re.sub(r"\D", "", full)
        if 8 <= len(digits_only) <= 15:
            overlaps = any(
                not (m.start() >= existing.end or m.end() <= existing.start)
                for existing in matches
            )
            if not overlaps:
                _add("phone", full, m.start(), m.start() + len(full))

    # Sort by position
    matches.sort(key=lambda x: x.start)
    return matches


# --- Redaction ---

_REDACT_LABELS = {
    "ssn": "[REDACTED-SSN]",
    "credit_card": "[REDACTED-CC]",
    "phone": "[REDACTED-PHONE]",
    "email": "[REDACTED-EMAIL]",
}


def redact_pii(text: str) -> str:
    """Replace all detected PII with redaction labels."""
    pii_matches = detect_pii(text)
    if not pii_matches:
        return text

    # Build result by replacing matches from end to start to preserve positions
    result = text
    for match in reversed(pii_matches):
        label = _REDACT_LABELS.get(match.pii_type, "[REDACTED]")
        result = result[:match.start] + label + result[match.end:]

    return result
