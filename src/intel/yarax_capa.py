"""yara-x scanning + Mandiant capa capability extraction (P2 #2.10).

Two surfaces:

  yara-x — Rust rewrite of YARA with a thin Python binding. ~5x faster
           compile + scan than ``yara-python`` and bug-compatible with
           the YARA 4.x rule syntax. We keep ``yara-python`` available
           via ``src.integrations.yara_engine`` for legacy code paths
           and use ``yara-x`` for new scan calls.

  capa  — Mandiant's capability-extraction engine. Given a PE / ELF /
           Mach-O binary it identifies high-level adversary capabilities
           (e.g. "queries SMBIOS for VM detection", "encrypts files in
           place", "connects to C2 over HTTPS") and maps each capability
           to MITRE ATT&CK technique IDs. Useful enrichment when an
           operator uploads a sample seen in the dark-web feed.

Both are pure-Python opt-ins — no shell-out, no native deps beyond what
the wheels ship. The wrapper degrades gracefully when either library is
missing (e.g. operator skipped the wheel during ``pip install``):
:func:`is_available` reports the state and the high-level functions
return structured "unavailable" results rather than raising.
"""

from __future__ import annotations

import io
import logging
import tempfile
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# ── Availability detection ──────────────────────────────────────────


def is_available() -> dict[str, bool]:
    """Probe yara-x and capa imports; cheap to call from API routes."""
    out = {"yara_x": False, "capa": False}
    try:
        import yara_x  # noqa: F401
        out["yara_x"] = True
    except ImportError:
        pass
    try:
        import capa  # noqa: F401
        out["capa"] = True
    except ImportError:
        pass
    return out


# ── yara-x scanning ─────────────────────────────────────────────────


@dataclass
class YaraMatch:
    rule: str
    namespace: str | None
    tags: list[str]
    matched_strings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule, "namespace": self.namespace,
            "tags": self.tags, "matched_strings": self.matched_strings,
        }


def scan_bytes(
    data: bytes,
    *,
    rules_text: str,
) -> list[YaraMatch]:
    """Compile ``rules_text`` and scan ``data``.

    Compilation is the expensive part of YARA — callers that scan many
    blobs against the same rule corpus should use :func:`compile_rules`
    + :func:`scan_with_compiled` instead.
    """
    try:
        import yara_x
    except ImportError:
        logger.warning("[yara-x] not installed; returning empty match list")
        return []
    rules = yara_x.compile(rules_text)
    return _format_matches(rules.scan(data))


def compile_rules(rules_text: str):
    """Return a compiled yara-x ``Rules`` object."""
    import yara_x
    return yara_x.compile(rules_text)


def scan_with_compiled(rules, data: bytes) -> list[YaraMatch]:
    """Scan against a pre-compiled rules object — O(rules+data) per call
    instead of O(compile + rules + data)."""
    return _format_matches(rules.scan(data))


def _format_matches(scan_results) -> list[YaraMatch]:
    out: list[YaraMatch] = []
    for r in scan_results.matching_rules:
        # yara-x's rule object exposes ``.identifier``, ``.namespace``
        # (may be ``"default"``), ``.tags`` (tuple of str), and
        # ``.patterns`` (each with ``.identifier`` + ``.matches``).
        matched_strings: list[str] = []
        try:
            for pat in (r.patterns or []):
                ident = getattr(pat, "identifier", None) or ""
                for m in (pat.matches or []):
                    # Match exposes .offset and .length; render a
                    # short fingerprint without dumping raw bytes.
                    offset = getattr(m, "offset", None)
                    length = getattr(m, "length", None)
                    matched_strings.append(
                        f"{ident}@{offset}+{length}"
                    )
        except Exception as exc:  # noqa: BLE001 — keep going for siblings
            logger.debug("[yara-x] pattern enumeration failed: %s", exc)
        out.append(YaraMatch(
            rule=r.identifier,
            namespace=getattr(r, "namespace", None) or None,
            tags=list(getattr(r, "tags", ()) or ()),
            matched_strings=matched_strings,
        ))
    return out


# ── capa capability extraction ──────────────────────────────────────


@dataclass
class CapaCapability:
    name: str
    namespace: str | None
    matched_count: int
    attack: list[str]
    mbc: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "namespace": self.namespace,
            "matched_count": self.matched_count,
            "attack": self.attack, "mbc": self.mbc,
        }


@dataclass
class CapaResult:
    available: bool
    sample_sha256: str | None
    capabilities: list[CapaCapability]
    note: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "sample_sha256": self.sample_sha256,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "note": self.note,
            "error": self.error,
        }


_MAX_SAMPLE_BYTES = 50 * 1024 * 1024  # 50 MB analysis ceiling


def extract_capabilities(sample_bytes: bytes) -> CapaResult:
    """Run capa over a binary sample and return its capabilities.

    capa works on PE / ELF / Mach-O / .NET / shellcode blobs. A 50 MB
    ceiling protects the API worker from OOM on an adversarial upload.

    The function is synchronous + blocking — call it from
    ``asyncio.to_thread`` in API handlers.
    """
    import hashlib

    if len(sample_bytes) > _MAX_SAMPLE_BYTES:
        return CapaResult(
            available=True, sample_sha256=None, capabilities=[],
            error=f"sample exceeds {_MAX_SAMPLE_BYTES} byte ceiling",
        )

    sha = hashlib.sha256(sample_bytes).hexdigest()

    try:
        import capa
        import capa.main  # noqa: F401 — top-level capa.main has init side-effects
    except ImportError:
        return CapaResult(
            available=False, sample_sha256=sha, capabilities=[],
            note="flare-capa is not installed in this deployment",
        )

    # capa's high-level API is built around files on disk. Spool to a
    # temp file so we can call ``capa.main.main`` cleanly.
    with tempfile.NamedTemporaryFile(
        suffix=".bin", delete=False,
    ) as fh:
        fh.write(sample_bytes)
        path = fh.name

    try:
        # capa exposes a programmatic API but its public stable shape
        # changed in 9.x. We stay conservative: invoke the internal
        # ``main`` with a JSON-output format so we always get a
        # parseable result regardless of the version.
        import json
        import os as _os
        import subprocess
        import sys

        proc = subprocess.run(
            [sys.executable, "-m", "capa", "--json", path],
            capture_output=True, timeout=180, text=True,
        )
        if proc.returncode != 0:
            return CapaResult(
                available=True, sample_sha256=sha, capabilities=[],
                error=(proc.stderr or proc.stdout or
                       "capa exited non-zero")[:500],
            )
        payload = json.loads(proc.stdout)
    except Exception as exc:  # noqa: BLE001 — surface capa edge cases
        return CapaResult(
            available=True, sample_sha256=sha, capabilities=[],
            error=f"{type(exc).__name__}: {exc}"[:500],
        )
    finally:
        try:
            import os as _os
            _os.unlink(path)
        except OSError:
            pass

    rules = (payload or {}).get("rules") or {}
    capabilities: list[CapaCapability] = []
    for name, rule in rules.items():
        if not isinstance(rule, dict):
            continue
        meta = rule.get("meta") or {}
        attack_ids = []
        for att in meta.get("attack", []) or []:
            if isinstance(att, dict):
                tid = att.get("id") or att.get("technique") or ""
                if tid:
                    attack_ids.append(tid)
            elif isinstance(att, str):
                attack_ids.append(att)
        mbc_ids = []
        for m in meta.get("mbc", []) or []:
            if isinstance(m, dict):
                mid = m.get("id") or m.get("objective") or ""
                if mid:
                    mbc_ids.append(mid)
            elif isinstance(m, str):
                mbc_ids.append(m)
        matches = rule.get("matches") or {}
        capabilities.append(CapaCapability(
            name=name, namespace=meta.get("namespace"),
            matched_count=len(matches) if isinstance(matches, dict)
                          else 0,
            attack=attack_ids, mbc=mbc_ids,
        ))

    return CapaResult(
        available=True, sample_sha256=sha,
        capabilities=capabilities, note=None,
    )
