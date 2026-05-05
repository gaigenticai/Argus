"""Lookalike-domain generator for DMARC RUF spoof attribution.

Produces typosquat / homoglyph / bitsquat permutations of a brand
domain. Used by ``dmarc_lookalike_detect`` to decide whether a RUF
record's Return-Path domain is a lookalike of the brand we monitor.

We deliberately keep this self-contained (rather than shelling out to
``dnstwist`` at runtime) so the agent can fire synchronously inside
the Bridge handler without IPC overhead.

Coverage (deduped, capped at ~50/brand):

    typo        — adjacent-key swaps, deletions, insertions, doubles
    homoglyph   — common Latin/Cyrillic visual confusables
    bitsquat    — single-bit-flip ASCII (RAM-corruption squats)
    tld_swap    — same name on .co/.net/.org/.io/.app/.support/...

Output format:

    list[str]  domains in punycode-safe lower-case form
"""
from __future__ import annotations

import string
from typing import Iterable

# Visual confusables curated from Unicode's confusables.txt — the ones
# that actually look like their Latin counterparts in modern fonts.
_HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["à", "á", "â", "ä", "ã", "å", "ɑ"],
    "b": ["d", "lb"],
    "c": ["ç", "ć"],
    "d": ["b", "cl"],
    "e": ["è", "é", "ê", "ë", "ē", "ĕ"],
    "g": ["q", "ɡ"],
    "h": ["lh", "ĥ"],
    "i": ["1", "l", "ï", "í", "ı"],
    "k": ["lc"],
    "l": ["1", "i", "ł"],
    "m": ["rn", "nn"],
    "n": ["m", "ñ", "ń"],
    "o": ["0", "ò", "ó", "ô", "ö", "õ", "ø", "ɵ"],
    "p": ["ρ"],
    "q": ["g"],
    "s": ["ş", "ś", "š", "5"],
    "t": ["7", "ţ"],
    "u": ["v", "ù", "ú", "û", "ü", "ū"],
    "v": ["u", "w"],
    "w": ["vv"],
    "x": ["ks"],
    "y": ["ý", "ÿ"],
    "z": ["ż", "ź", "ž", "2"],
    "0": ["o", "O"],
    "1": ["i", "l"],
    "5": ["s"],
}

# Common alternate TLDs spoofers register. Keep terse — the agent
# is interested in obvious phishing TLDs, not exotica.
_TLD_SWAPS = (
    "com", "net", "org", "io", "co", "app", "support", "help",
    "secure", "login", "verify", "info", "online", "site", "live",
)


def _split(domain: str) -> tuple[str, str]:
    """Return (label, tld). For ``argus.bank``, that's ('argus', 'bank')."""
    domain = domain.strip().lower().lstrip(".")
    parts = domain.split(".")
    if len(parts) < 2:
        return domain, ""
    # Treat anything beyond the first label as the TLD (handles co.uk).
    return parts[0], ".".join(parts[1:])


def _typo_perms(label: str) -> Iterable[str]:
    if len(label) < 2:
        return
    # adjacent swaps
    for i in range(len(label) - 1):
        yield label[:i] + label[i + 1] + label[i] + label[i + 2 :]
    # deletions
    for i in range(len(label)):
        yield label[:i] + label[i + 1 :]
    # doubles
    for i in range(len(label)):
        yield label[:i] + label[i] * 2 + label[i + 1 :]
    # insertions of common letters
    for i in range(len(label) + 1):
        for c in "aeiouns":
            yield label[:i] + c + label[i:]


def _homoglyph_perms(label: str) -> Iterable[str]:
    for i, c in enumerate(label):
        for repl in _HOMOGLYPHS.get(c, []):
            yield label[:i] + repl + label[i + 1 :]


def _bitsquat_perms(label: str) -> Iterable[str]:
    """Single-bit ASCII flips that land on a printable letter/digit."""
    allowed = set(string.ascii_lowercase + string.digits + "-")
    for i, c in enumerate(label):
        if not c.isascii():
            continue
        b = ord(c)
        for bit in range(7):
            flip = chr(b ^ (1 << bit))
            if flip != c and flip in allowed:
                yield label[:i] + flip + label[i + 1 :]


def generate(domain: str, *, cap: int = 50) -> list[str]:
    """Produce up to ``cap`` lookalike domain candidates.

    Order is stable: typo first (most common in real campaigns), then
    homoglyph, then bitsquat, then TLD swaps. That stability matters
    because we use the list as a deterministic fingerprint in the
    agent's dedup_key.
    """
    label, tld = _split(domain)
    if not label:
        return []
    seen: set[str] = set()
    out: list[str] = []

    def _push(d: str) -> bool:
        d = d.strip().lower().strip(".")
        if not d or d == domain or d in seen:
            return False
        # ASCII-only labels keep DNS lookups cheap; for IDN we punycode.
        try:
            d.encode("ascii")
        except UnicodeEncodeError:
            try:
                d = d.encode("idna").decode("ascii")
            except UnicodeError:
                return False
        seen.add(d)
        out.append(d)
        return len(out) >= cap

    full_tld = tld or "com"
    for perm in _typo_perms(label):
        if _push(f"{perm}.{full_tld}"):
            return out
    for perm in _homoglyph_perms(label):
        if _push(f"{perm}.{full_tld}"):
            return out
    for perm in _bitsquat_perms(label):
        if _push(f"{perm}.{full_tld}"):
            return out
    for alt in _TLD_SWAPS:
        if alt == full_tld:
            continue
        if _push(f"{label}.{alt}"):
            return out
    return out


def is_lookalike(candidate: str, brand: str, *, cap: int = 50) -> bool:
    """True if ``candidate`` is in the brand's permutation set."""
    if not candidate or not brand:
        return False
    candidate = candidate.strip().lower().lstrip(".")
    brand = brand.strip().lower().lstrip(".")
    if candidate == brand:
        return False
    perms = set(generate(brand, cap=cap))
    # Also flag direct subdomain hijacks (brand.example.com).
    if candidate in perms:
        return True
    # Match if the registrable label of candidate is in the perm set.
    cand_label, cand_tld = _split(candidate)
    return f"{cand_label}.{cand_tld}" in perms


__all__ = ["generate", "is_lookalike"]
