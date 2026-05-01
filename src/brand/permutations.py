"""Typosquat permutation engine.

Generates lookalike variants for a given domain or brand label, exactly
the categories dnstwist surfaces — but implemented in pure Python so we
control the algorithm and don't need an external binary.

Generated permutation kinds (matching dnstwist taxonomy):
    addition       a → ab, ac, ad...
    insertion      a → ab → adb (qwerty-adjacent)
    omission       argus → arus, ages, augs
    repetition     argus → aargus, arrgus
    replacement    qwerty-adjacent letter swaps (a→s, q→w, etc.)
    transposition  argus → ragus, agrus, arusg
    homoglyph      a → @, o → 0, l → 1
    bitsquatting   single-bit flip per char
    hyphenation    a-rgus, ar-gus, argu-s
    subdomain      argus.com → app.argus-com.example  (handled by separate scanner)
    tld_swap       argus.com → argus.net, argus.io
    vowel_swap     argus → ergus, irgus, urgus

Output: ``Permutation(domain, kind)`` dataclasses. The caller resolves
each candidate (DNS / WHOIS / cert) to confirm whether it actually
exists.
"""

from __future__ import annotations

import string
from dataclasses import dataclass

import tldextract

# QWERTY adjacency map for typo-replacement / insertion.
_QWERTY = {
    "q": "wa", "w": "qeas", "e": "wrds", "r": "etfd", "t": "ryfg",
    "y": "tugh", "u": "yihj", "i": "uojk", "o": "ipkl", "p": "ol",
    "a": "qwsz", "s": "wedxza", "d": "erfcxs", "f": "rtgvcd",
    "g": "tyhbvf", "h": "yujnbg", "j": "uikmnh", "k": "iolmj",
    "l": "opk", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk",
}

_HOMOGLYPHS = {
    "a": ["à", "á", "â", "ã", "ä", "@", "4"],
    "b": ["8", "ḃ", "ƅ"],
    "c": ["ç", "ć", "č"],
    "d": ["ḋ", "đ"],
    "e": ["è", "é", "ê", "ë", "3"],
    "g": ["ǵ", "ġ", "9"],
    "h": ["ħ", "ḣ"],
    "i": ["í", "ì", "î", "ï", "1", "l", "!"],
    "k": ["ḱ"],
    "l": ["ĺ", "ḷ", "1", "i"],
    "m": ["ṁ"],
    "n": ["ǹ", "ń", "ñ"],
    "o": ["ò", "ó", "ô", "õ", "ö", "0"],
    "p": ["ṗ"],
    "q": ["ɋ"],
    "r": ["ŕ", "ř"],
    "s": ["ś", "š", "5", "$"],
    "t": ["ť", "ṫ", "7"],
    "u": ["ù", "ú", "û", "ü"],
    "v": ["ѵ"],
    "w": ["ẁ", "ẃ", "ẅ"],
    "x": ["×"],
    "y": ["ý", "ÿ"],
    "z": ["ź", "ž", "2"],
}

# tldextract uses an offline-capable Public Suffix List snapshot. We
# pre-load it once at import time so domain splitting is fast and the
# TLD universe used for ``tld_swap`` is the same that the PSL knows
# about (~1500 entries) rather than a hand-curated 23-entry tuple.
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)


def _public_suffixes() -> tuple[str, ...]:
    """Return the active PSL ICANN-domain suffix list.

    tldextract exposes ``_extractor`` lazily; we reach in once to build
    a frozen tuple, then cache it on the module. The list is filtered
    to ICANN entries (``co.uk``, ``com``, ``net``, …) and excludes
    private-domain suffixes (``blogspot.com``, ``herokuapp.com``) which
    would produce nonsense permutations.
    """
    global _CACHED_TLDS
    if _CACHED_TLDS is not None:
        return _CACHED_TLDS
    # Force an extract to materialise the internal trie.
    _TLD_EXTRACT("argus.example.com")
    extractor = _TLD_EXTRACT._extractor  # type: ignore[attr-defined]
    tlds = sorted({s for s in extractor.tlds(include_psl_private_domains=False)})
    # The PSL contains entries with leading ``!`` (exception rules) and
    # wildcards (``*.foo``); filter those out.
    cleaned = tuple(
        t for t in tlds
        if not t.startswith(("!", "*"))
        and "." not in t  # only single-label TLDs for swap candidates
        and t.isascii()
        and t.replace("-", "").isalpha()
    )
    _CACHED_TLDS = cleaned
    return _CACHED_TLDS


_CACHED_TLDS: tuple[str, ...] | None = None


# Subset used by ``_tld_swap``: bias toward the TLDs phishers actually
# pivot to. Any TLD outside this set is still emitted but with lower
# priority by being appended after the bias set.
_TLD_BIAS = (
    "com", "net", "org", "io", "co", "info", "biz", "online", "site",
    "app", "live", "shop", "ai", "us", "ltd", "global", "support",
    "help", "secure", "login", "account", "auth", "tech",
    "xyz", "top", "club", "vip", "zone", "world", "fund", "pay",
)

_VOWELS = "aeiou"


@dataclass(frozen=True)
class Permutation:
    domain: str
    kind: str


def _split(domain: str) -> tuple[str, str]:
    """Return ``(label, tld)`` using the Public Suffix List.

    For ``argus.co.uk`` we return ``("argus", "co.uk")`` rather than
    splitting on the final dot, because typosquatters target the
    registrable label, not a one-level subdomain. tldextract handles
    the PSL lookup; the fallback (no PSL match) is a single-label
    behaviour identical to the original implementation.
    """
    norm = domain.lower().strip().rstrip(".")
    if not norm:
        return "", ""
    if "." not in norm:
        return norm, ""
    parts = _TLD_EXTRACT(norm)
    label = parts.domain or ""
    tld = parts.suffix or ""
    if not label and not tld:
        # PSL couldn't classify; fall back to the simple last-dot split.
        label, _, tld = norm.rpartition(".")
    return label, tld


def _addition(label: str, tld: str):
    for c in string.ascii_lowercase:
        yield Permutation(f"{label}{c}.{tld}" if tld else f"{label}{c}", "addition")


def _omission(label: str, tld: str):
    for i in range(len(label)):
        new = label[:i] + label[i + 1:]
        if new and new != label:
            yield Permutation(f"{new}.{tld}" if tld else new, "omission")


def _repetition(label: str, tld: str):
    seen = set()
    for i, c in enumerate(label):
        new = label[:i] + c + label[i:]
        if new not in seen:
            seen.add(new)
            yield Permutation(f"{new}.{tld}" if tld else new, "repetition")


def _replacement(label: str, tld: str):
    for i, c in enumerate(label):
        for swap in _QWERTY.get(c, ""):
            new = label[:i] + swap + label[i + 1:]
            if new != label:
                yield Permutation(f"{new}.{tld}" if tld else new, "replacement")


def _transposition(label: str, tld: str):
    for i in range(len(label) - 1):
        new = label[:i] + label[i + 1] + label[i] + label[i + 2:]
        if new != label:
            yield Permutation(f"{new}.{tld}" if tld else new, "transposition")


def _homoglyph(label: str, tld: str):
    for i, c in enumerate(label):
        for swap in _HOMOGLYPHS.get(c, []):
            new = label[:i] + swap + label[i + 1:]
            yield Permutation(f"{new}.{tld}" if tld else new, "homoglyph")


def _bitsquat(label: str, tld: str):
    masks = [1, 2, 4, 8, 16, 32, 64, 128]
    for i, c in enumerate(label):
        for m in masks:
            flipped = chr(ord(c) ^ m)
            if flipped.isalnum() and flipped != c:
                new = label[:i] + flipped.lower() + label[i + 1:]
                yield Permutation(f"{new}.{tld}" if tld else new, "bitsquatting")


def _hyphenation(label: str, tld: str):
    for i in range(1, len(label)):
        new = label[:i] + "-" + label[i:]
        yield Permutation(f"{new}.{tld}" if tld else new, "hyphenation")


def _vowel_swap(label: str, tld: str):
    for i, c in enumerate(label):
        if c in _VOWELS:
            for v in _VOWELS:
                if v != c:
                    new = label[:i] + v + label[i + 1:]
                    yield Permutation(f"{new}.{tld}" if tld else new, "vowel_swap")


def _tld_swap(label: str, tld: str):
    if not tld:
        return
    bias_set = set(_TLD_BIAS)
    # First emit the high-priority phisher-favourite TLDs, then the
    # rest of the PSL ICANN universe so brand monitoring can't be
    # bypassed by an attacker registering on a fringe TLD we never
    # enumerated.
    seen: set[str] = set()
    for new_tld in _TLD_BIAS:
        if new_tld == tld or new_tld in seen:
            continue
        seen.add(new_tld)
        yield Permutation(f"{label}.{new_tld}", "tld_swap")
    for new_tld in _public_suffixes():
        if new_tld == tld or new_tld in seen or new_tld in bias_set:
            continue
        seen.add(new_tld)
        yield Permutation(f"{label}.{new_tld}", "tld_swap")


_GENERATORS = (
    _addition,
    _omission,
    _repetition,
    _replacement,
    _transposition,
    _homoglyph,
    _bitsquat,
    _hyphenation,
    _vowel_swap,
    _tld_swap,
)


def generate_permutations(domain: str, *, max_per_kind: int = 200) -> list[Permutation]:
    """Generate up to ``max_per_kind`` permutations per kind, deduped."""
    label, tld = _split(domain.lower().strip().rstrip("."))
    if not label:
        return []
    seen: set[str] = set()
    out: list[Permutation] = []
    for gen in _GENERATORS:
        kind_count = 0
        for p in gen(label, tld):
            if kind_count >= max_per_kind:
                break
            if p.domain in seen or p.domain == domain:
                continue
            seen.add(p.domain)
            out.append(p)
            kind_count += 1
    return out


# --- Similarity scoring -------------------------------------------------


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def domain_similarity(a: str, b: str) -> float:
    """Levenshtein-based similarity in [0, 1]. 1.0 = identical."""
    a, b = a.lower(), b.lower()
    if not a or not b:
        return 0.0
    distance = _levenshtein(a, b)
    longest = max(len(a), len(b))
    return max(0.0, 1.0 - (distance / longest))


__all__ = [
    "Permutation",
    "generate_permutations",
    "domain_similarity",
]
