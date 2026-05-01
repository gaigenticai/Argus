"""Logo abuse — perceptual hashing + multi-hash voting.

Uses :mod:`imagehash` (pHash, dHash, aHash, ~30 MB total deps incl. PIL).
Per `docs/HARDWARE_DECISIONS.md` this is the lightweight production-grade
alternative to OpenCLIP+FAISS for first-pass logo-abuse detection.

Why three hashes plus a colour vector
-------------------------------------
- pHash (DCT-based)  → robust to JPEG re-encode, scaling, mild blur.
- dHash (gradient)   → robust to brightness shifts; stronger on simple icons.
- aHash (mean)       → fast smoke-test; good at killing obvious mismatches early.
- color histogram    → catches re-coloured copies (white-on-blue → blue-on-white).

A candidate is flagged when **any two of pHash/dHash/aHash** are within
threshold (Hamming distance ≤ 12 out of 64), or when one is very close
(≤ 6) and the colour distance is < 0.25.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Iterable

# Hard-fail at import-time if Pillow / imagehash are missing — these are
# core deps, not optional. We never silently degrade.
import imagehash  # noqa: I001
from PIL import Image


_PHASH_TIGHT = 6
_PHASH_LOOSE = 12
_COLOR_TIGHT = 0.25


# --- Hashing -----------------------------------------------------------


@dataclass(frozen=True)
class LogoFingerprint:
    phash_hex: str
    dhash_hex: str
    ahash_hex: str
    color_histogram: list[float]  # length-48 RGB histogram (16 bins/channel)
    width: int
    height: int


def _color_histogram(img: Image.Image, bins: int = 16) -> list[float]:
    rgb = img.convert("RGB").resize((128, 128))
    pixels = list(rgb.getdata())
    n = len(pixels) or 1
    hist = [0.0] * (bins * 3)
    bucket = 256 // bins
    for r, g, b in pixels:
        hist[r // bucket] += 1
        hist[bins + g // bucket] += 1
        hist[2 * bins + b // bucket] += 1
    return [c / n for c in hist]


def fingerprint(image_bytes: bytes) -> LogoFingerprint:
    if not image_bytes:
        raise ValueError("image_bytes must not be empty")
    img = Image.open(io.BytesIO(image_bytes))
    img.load()
    img_rgb = img.convert("RGB")
    return LogoFingerprint(
        phash_hex=str(imagehash.phash(img_rgb)),
        dhash_hex=str(imagehash.dhash(img_rgb)),
        ahash_hex=str(imagehash.average_hash(img_rgb)),
        color_histogram=_color_histogram(img_rgb),
        width=img.width,
        height=img.height,
    )


# --- Distance ----------------------------------------------------------


def _hex_to_hash(h: str):
    return imagehash.hex_to_hash(h)


def _hamming(a_hex: str, b_hex: str) -> int:
    return _hex_to_hash(a_hex) - _hex_to_hash(b_hex)


def _color_distance(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 1.0
    # Sum of absolute differences; histograms each sum to 3.0 (3 channels),
    # so max possible difference is 6.0. Normalize.
    return sum(abs(x - y) for x, y in zip(a, b)) / 6.0


@dataclass
class MatchResult:
    phash_distance: int
    dhash_distance: int
    ahash_distance: int
    color_distance: float
    similarity: float       # 0..1, higher is closer
    verdict: str            # "likely_abuse" / "possible_abuse" / "no_match"
    rationale: str


def compare(
    candidate: LogoFingerprint,
    registered_phash_hex: str,
    registered_dhash_hex: str,
    registered_ahash_hex: str,
    registered_histogram: list[float],
) -> MatchResult:
    p = _hamming(candidate.phash_hex, registered_phash_hex)
    d = _hamming(candidate.dhash_hex, registered_dhash_hex)
    a = _hamming(candidate.ahash_hex, registered_ahash_hex)
    c = _color_distance(candidate.color_histogram, registered_histogram)

    # Multi-hash voting — at least 2 of 3 within loose threshold == likely abuse.
    tight_count = sum(1 for x in (p, d, a) if x <= _PHASH_TIGHT)
    loose_count = sum(1 for x in (p, d, a) if x <= _PHASH_LOOSE)

    if tight_count >= 2 or (tight_count >= 1 and c < _COLOR_TIGHT):
        verdict = "likely_abuse"
        rationale = (
            f"{tight_count} hash(es) in tight range, color_distance={c:.2f}"
        )
    elif loose_count >= 2:
        verdict = "possible_abuse"
        rationale = (
            f"{loose_count} hash(es) in loose range; needs analyst review"
        )
    else:
        verdict = "no_match"
        rationale = (
            f"only {loose_count} hash(es) within loose range, color={c:.2f}"
        )

    similarity = max(
        0.0,
        1.0 - (
            (min(p, d, a) / 64.0) * 0.7
            + c * 0.3
        ),
    )

    return MatchResult(
        phash_distance=p,
        dhash_distance=d,
        ahash_distance=a,
        color_distance=round(c, 4),
        similarity=round(similarity, 4),
        verdict=verdict,
        rationale=rationale,
    )


__all__ = [
    "LogoFingerprint",
    "MatchResult",
    "fingerprint",
    "compare",
]
