"""Brand-name, email, and username permutations.

This module is the string-level companion to
``src/brand/permutations.py`` (which is domain-focused — it operates on
``label.tld`` and feeds the typosquat scanner). Here we generate
permutations on free-form names and identifiers, used by:

* ``src/agents/triage_agent.py`` — the LLM prompt expands ``keywords``
  and VIP emails so the model sees the full match surface without
  bloating the org config row.
* The leakage / stealer-log scanner — when checking if a compromised
  credential mentions a tracked VIP, the matcher looks for any of the
  generated email patterns instead of just the literal entries.
* The brand-abuse detector — keyword scan on raw_intel uses the
  expanded brand-name set so impersonators using leetspeak or
  homoglyphs don't slip through.

Scope is **moderate** by default:

* Homoglyphs only for ASCII characters that have a clearly similar
  Unicode counterpart (Latin → Cyrillic / accented).
* Leet only common substitutions: ``a/4``, ``e/3``, ``i/1``, ``o/0``,
  ``s/5``.
* Up to ~30 brand variants and ~12 email patterns per VIP.

Tuning these knobs is a deliberate trade-off between recall and false
positives — see the constants below.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Iterable


# Subset of homoglyphs from src.brand.permutations._HOMOGLYPHS — only
# the ones that are plausible substitutions a human attacker would
# actually use in a brand-impersonation attempt. Single Cyrillic /
# accented look-alikes per ASCII char keeps the variant set small.
_HOMOGLYPHS = {
    "a": ["а", "@"],   # cyrillic а / at-sign
    "e": ["е", "3"],   # cyrillic е / leet
    "i": ["і", "1"],   # cyrillic і / leet
    "o": ["о", "0"],   # cyrillic о / leet
    "s": ["ѕ", "5"],   # cyrillic ѕ / leet
    "c": ["с"],        # cyrillic с
    "p": ["р"],        # cyrillic р
    "x": ["х"],        # cyrillic х
    "y": ["у"],        # cyrillic у
    "k": ["к"],        # cyrillic к
}

# Limited leet — only the safe-bet substitutions. Going further (e.g.
# ``b/8``, ``g/9``) tends to produce variants no real attacker uses
# and just inflates the candidate set.
_LEET = {
    "a": "4",
    "e": "3",
    "i": "1",
    "o": "0",
    "s": "5",
}

# Common typo patterns — single-character delete/swap on every position
# is too aggressive (n^2 variants for an n-char name). We only do the
# higher-probability ones: trailing-char drop, doubled-char drop,
# adjacent-swap on consonant clusters.
_VOWELS = "aeiouAEIOU"


# ----------------------------------------------------------------------
# Brand-name permutations
# ----------------------------------------------------------------------

def brand_permutations(name: str, *, max_variants: int = 30) -> list[str]:
    """Return up to ``max_variants`` plausible look-alikes of a brand name.

    The output ALWAYS includes the original name as the first element
    (so callers can use the returned list as a ready-to-use match set).

    Variant categories (in priority order — homoglyphs are
    highest-recall for impersonation, leet is medium, typos are lower):

    1. Concatenation / spacing variants (no-space, hyphen, underscore)
    2. Acronym / dotted forms (``Emirates NBD`` → ``E.N.B.D.``, ``ENBD``)
    3. Homoglyphs (Cyrillic look-alikes)
    4. Leet substitutions (selective)
    5. Common typo patterns (vowel drop / doubled-char)

    Pure ASCII inputs only produce ASCII + selective Cyrillic outputs.
    Empty / whitespace-only inputs return ``[]``.
    """
    base = (name or "").strip()
    if not base:
        return []

    out: list[str] = [base]
    seen: set[str] = {base.lower()}

    def _add(candidate: str) -> None:
        c = candidate.strip()
        if not c:
            return
        key = c.lower()
        if key in seen:
            return
        seen.add(key)
        out.append(c)

    # 1. Concatenation / spacing
    if " " in base:
        _add(base.replace(" ", ""))
        _add(base.replace(" ", "-"))
        _add(base.replace(" ", "_"))
        _add(base.replace(" ", "."))

    # 2. Acronym forms (only multi-word names)
    words = [w for w in re.split(r"\s+", base) if w]
    if len(words) >= 2:
        # Initials of words ≥ 2 chars (skips one-letter joiners like "&")
        initials = "".join(w[0] for w in words if len(w) >= 1)
        if initials:
            _add(initials.upper())
            _add(".".join(initials.upper()) + ".")
            _add("-".join(initials.upper()))

    # 3. Homoglyph substitutions — single-character replacement at each
    # position with a confusable look-alike. We cap at the first match
    # per character class to avoid combinatorial blow-up.
    lowered = base.lower()
    for i, ch in enumerate(lowered):
        if ch in _HOMOGLYPHS:
            for repl in _HOMOGLYPHS[ch]:
                _add(base[:i] + repl + base[i + 1:])
                if len(out) >= max_variants:
                    return out

    # 4. Leet — apply ONE substitution at a time (single-char swaps
    # produce more believable impersonations than full-leet).
    for i, ch in enumerate(lowered):
        if ch in _LEET:
            _add(base[:i] + _LEET[ch] + base[i + 1:])
            if len(out) >= max_variants:
                return out

    # 5. Typos — vowel drop on each position, doubled-char drop.
    for i, ch in enumerate(base):
        if ch in _VOWELS:
            _add(base[:i] + base[i + 1:])
            if len(out) >= max_variants:
                return out
    # Doubled-char collapse (e.g. ``Emmirates`` if anyone typed double m)
    for i in range(1, len(base)):
        if base[i] == base[i - 1] and base[i].isalpha():
            _add(base[:i] + base[i + 1:])
            if len(out) >= max_variants:
                return out

    return out[:max_variants]


# ----------------------------------------------------------------------
# Email permutations
# ----------------------------------------------------------------------

# Patterns are in descending order of how common they are at large
# enterprises. The first 6–7 cover ~80% of real-world cases; the rest
# catch edge cases without exploding the candidate set.
_EMAIL_PATTERNS = (
    "{first}.{last}",        # john.smith
    "{f}{last}",             # jsmith
    "{first}",               # john
    "{first}{last}",         # johnsmith
    "{first}_{last}",        # john_smith
    "{f}.{last}",            # j.smith
    "{first}.{l}",           # john.s
    "{last}.{first}",        # smith.john
    "{last}{f}",             # smithj
    "{first}-{last}",        # john-smith
    "{f}{l}",                # js
    "{last}",                # smith
)


def email_permutations(
    first: str | None,
    last: str | None,
    domains: Iterable[str],
    *,
    max_patterns: int = 12,
) -> list[str]:
    """Return common ``firstname/lastname @ domain`` combinations.

    Pulls from the most-used corporate email conventions. Output is
    deduplicated, lowercased, and stable-ordered (highest-probability
    first). When ``first`` and ``last`` are both provided we generate
    cross-products for every ``domain``; if only one name field is set
    we fall back to a smaller pattern subset.

    Domain inputs are accepted as-is (no normalisation) so subdomains
    like ``corp.example.com`` work alongside primary domains.
    """
    first_n = _strip_to_alnum_lower(first or "")
    last_n = _strip_to_alnum_lower(last or "")
    if not first_n and not last_n:
        return []

    f_init = first_n[:1]
    l_init = last_n[:1]

    if first_n and last_n:
        patterns = _EMAIL_PATTERNS[:max_patterns]
    elif first_n:
        patterns = ("{first}", "{f}")
    else:
        patterns = ("{last}", "{l}")

    out: list[str] = []
    seen: set[str] = set()
    for domain in domains:
        d = (domain or "").strip().lower().lstrip("@")
        if not d:
            continue
        for p in patterns:
            try:
                local = p.format(
                    first=first_n, last=last_n, f=f_init, l=l_init,
                )
            except (KeyError, IndexError):
                continue
            local = local.strip(".-_")
            if not local:
                continue
            email = f"{local}@{d}"
            if email in seen:
                continue
            seen.add(email)
            out.append(email)
    return out


# ----------------------------------------------------------------------
# Username permutations
# ----------------------------------------------------------------------

# Username patterns mirror email locals (no ``@domain`` part). Useful
# for matching display handles on Telegram, Twitter, Discord, GitHub.
_USERNAME_PATTERNS = (
    "{first}{last}",
    "{first}.{last}",
    "{first}_{last}",
    "{f}{last}",
    "{first}",
    "{last}{first}",
    "{last}_{first}",
    "{first}-{last}",
    "{f}.{last}",
    "{last}",
)


def username_permutations(
    first: str | None,
    last: str | None,
    *,
    max_patterns: int = 10,
) -> list[str]:
    """Return common username conventions for a real-world name.

    Same contract as :func:`email_permutations` minus the domain.
    """
    first_n = _strip_to_alnum_lower(first or "")
    last_n = _strip_to_alnum_lower(last or "")
    if not first_n and not last_n:
        return []
    f_init = first_n[:1]

    out: list[str] = []
    seen: set[str] = set()
    for p in _USERNAME_PATTERNS[:max_patterns]:
        try:
            u = p.format(first=first_n, last=last_n, f=f_init)
        except (KeyError, IndexError):
            continue
        u = u.strip(".-_")
        if not u or u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _strip_to_alnum_lower(s: str) -> str:
    """Normalise a name part to lowercase alphanumerics.

    Drops accents (José → jose), strips spaces and punctuation, and
    lowercases. Keeps the result safe for use in email locals and
    usernames where most providers reject non-ASCII or punctuation.
    """
    if not s:
        return ""
    nfkd = unicodedata.normalize("NFKD", s)
    ascii_only = "".join(ch for ch in nfkd if not unicodedata.combining(ch))
    return re.sub(r"[^A-Za-z0-9]", "", ascii_only).lower()


def split_name(full_name: str) -> tuple[str, str]:
    """Best-effort first/last split.

    Single-token names → ``(name, "")``. Multi-token → first token is
    ``first``, last token is ``last``. Middle names / particles like
    "Al" / "de" / "van" are dropped — they're noise for permutation
    purposes since most enterprises don't include them in email locals.
    """
    parts = [p for p in re.split(r"\s+", (full_name or "").strip()) if p]
    if not parts:
        return ("", "")
    if len(parts) == 1:
        return (parts[0], "")
    # Drop common Arabic / Dutch / Spanish particles when sandwiched.
    PARTICLES = {"al", "el", "de", "del", "la", "le", "van", "von", "bin", "ben"}
    middle = [p for p in parts[1:-1] if p.lower() not in PARTICLES]
    # If after particle-stripping we collapse to two parts, use them.
    # Otherwise stick with the original endpoints.
    cleaned = [parts[0], *middle, parts[-1]]
    return (cleaned[0], cleaned[-1])


__all__ = [
    "brand_permutations",
    "email_permutations",
    "username_permutations",
    "split_name",
]
