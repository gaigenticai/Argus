"""Persian / Arabic / English language detection (P3 #3.10).

Telegram messages flow into the IOC pipeline in three dominant
languages: Arabic (hacktivist clusters), Persian (Iranian-APT
chatter), English (ransomware-leak mirrors). The pipeline tags each
message with a language so the dashboard can:

  - route Persian/Arabic content through Mistral-Saba-24b for
    translation + analyst-facing summary
  - keep English content on the cheaper inference path
  - apply per-language phishing rules (the existing Arabic-phishing
    analyzer in src/intel/arabic_phishing.py is the canonical Arabic
    analyzer)

We deliberately don't pull a heavy ML model in here (langdetect /
fastText) — Persian and Arabic have distinctive Unicode block
distributions that a counting heuristic resolves cleanly. Mixed-
language messages tag as the dominant script.

Public surface:
  detect_language(text)   "ar" | "fa" | "en" | "unknown"
"""

from __future__ import annotations

from typing import Literal

LangCode = Literal["ar", "fa", "en", "unknown"]


# Arabic block: U+0600 – U+06FF, Arabic Supplement: U+0750 – U+077F,
# Arabic Extended-A: U+08A0 – U+08FF, Presentation Forms-A: U+FB50 –
# U+FDFF, Presentation Forms-B: U+FE70 – U+FEFF.
_ARABIC_RANGES = (
    (0x0600, 0x06FF),
    (0x0750, 0x077F),
    (0x08A0, 0x08FF),
    (0xFB50, 0xFDFF),
    (0xFE70, 0xFEFF),
)

# Persian-distinguishing letters (present in Persian, absent or rare
# in Standard Arabic): گ ک پ چ ژ ی (ی has both forms; the Persian
# YEH at U+06CC is the discriminator vs Arabic YEH at U+064A).
_PERSIAN_DISTINCTIVE = {
    "پ",   # PEH (پ)
    "چ",   # TCHEH (چ)
    "ژ",   # JEH (ژ)
    "ک",   # KEHEH (ک)
    "گ",   # GAF (گ)
    "ی",   # FARSI YEH (ی)
}


def _is_arabic_codepoint(cp: int) -> bool:
    for lo, hi in _ARABIC_RANGES:
        if lo <= cp <= hi:
            return True
    return False


def detect_language(text: str) -> LangCode:
    """Heuristic language detection over Telegram message bodies.

    Decision rule:
      - count Arabic-script codepoints; if >=8 *and* >=15% of all
        non-whitespace characters, the message is Arabic-script
      - within Arabic-script messages, Persian-distinguishing letters
        flip the verdict to "fa" (any Persian-distinctive char wins)
      - otherwise: if at least one ASCII letter appears, return "en"
      - else "unknown"
    """
    if not text:
        return "unknown"
    arabic_count = 0
    persian_hit = False
    ascii_letter = False
    nonspace_count = 0
    for ch in text:
        if not ch.isspace():
            nonspace_count += 1
        cp = ord(ch)
        if _is_arabic_codepoint(cp):
            arabic_count += 1
            if ch in _PERSIAN_DISTINCTIVE:
                persian_hit = True
        elif (0x41 <= cp <= 0x5A) or (0x61 <= cp <= 0x7A):
            ascii_letter = True

    if arabic_count >= 8 and (
        nonspace_count == 0 or arabic_count / nonspace_count >= 0.15
    ):
        return "fa" if persian_hit else "ar"
    if ascii_letter:
        return "en"
    return "unknown"
