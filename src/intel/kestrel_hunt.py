"""Kestrel threat-hunting DSL — opt-in wrapper (P2 #2.4).

Kestrel (https://kestrel.readthedocs.io/) is a hunting language IBM/OCA
maintains alongside stix-shifter. A hunt is a multi-step query that
projects across heterogeneous sources (Splunk, Elastic, Sentinel, …)
into a unified data table.

Why "opt-in" — Kestrel pulls in pandas, pyarrow, opensearch-py, and
hard-pins ``stix-shifter==6.2.1`` which conflicts with the 8.x line we
use for the P2 #2.5 STIX-Shifter integration. So Argus does **not**
include ``kestrel-lang`` in ``requirements.txt``. Customers who want
Kestrel install it in a sibling venv (or a separate container) and
Argus shells out to the ``kestrel`` CLI.

This module provides:

  :func:`is_available` — does this deployment have Kestrel?
  :func:`render_hunt`  — pure compose: produce a Kestrel hunt script
                         from a (technique_id, source_name, indicators)
                         tuple. The script is valid even when Kestrel
                         isn't installed — analysts can copy/paste it.
  :func:`execute_hunt` — run the script via the ``kestrel`` CLI when
                         present; otherwise return ``unavailable``.

Usage from the case timeline / threat_hunter_agent: every alert with
attached MITRE techniques can spawn a hunt artefact (Kestrel script)
attached to its case — even when Kestrel isn't running, the script is
still saved as ``case_artifact.kestrel`` for the analyst to run later.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# ── Availability detection ──────────────────────────────────────────


def _kestrel_cli_path() -> str | None:
    """Return the ``kestrel`` CLI's path, or None when unavailable.

    The operator can override the lookup with ``ARGUS_KESTREL_CLI``
    pointing at e.g. ``/opt/kestrel-venv/bin/kestrel`` if Kestrel
    lives in a sibling venv to keep its hard-pinned deps from clashing
    with Argus's own."""
    override = (os.environ.get("ARGUS_KESTREL_CLI") or "").strip()
    if override:
        return override if os.path.exists(override) else None
    return shutil.which("kestrel")


def _kestrel_module_available() -> bool:
    try:
        import kestrel  # noqa: F401
        return True
    except ImportError:
        return False


def is_available() -> dict[str, Any]:
    """Return availability metadata for the dashboard / API to surface."""
    cli = _kestrel_cli_path()
    return {
        "available": bool(cli) or _kestrel_module_available(),
        "cli_path": cli,
        "module_importable": _kestrel_module_available(),
    }


# ── Hunt-script composer ────────────────────────────────────────────


# IOC type → Kestrel ``ENTITY-TYPE`` literal.
_IOC_KESTREL_MAP: dict[str, tuple[str, str]] = {
    "ip":     ("ipv4-addr", "value"),
    "ipv4":   ("ipv4-addr", "value"),
    "ipv6":   ("ipv6-addr", "value"),
    "domain": ("domain-name", "value"),
    "url":    ("url", "value"),
    "hash":   ("file", "hashes.'SHA-256'"),
    "sha256": ("file", "hashes.'SHA-256'"),
    "sha1":   ("file", "hashes.'SHA-1'"),
    "md5":    ("file", "hashes.MD5"),
}


@dataclass
class HuntScript:
    """Structured Kestrel hunt artifact attached to a case timeline."""

    title: str
    technique_id: str | None
    source_name: str
    iocs: list[tuple[str, str]]   # [(ioc_type, ioc_value), …]
    script: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "technique_id": self.technique_id,
            "source_name": self.source_name,
            "iocs": [{"type": t, "value": v} for t, v in self.iocs],
            "script": self.script,
        }


def render_hunt(
    *,
    title: str,
    source_name: str,
    iocs: list[tuple[str, str]],
    technique_id: str | None = None,
) -> HuntScript:
    """Compose a Kestrel hunt script from a list of IOCs.

    The script:
      1. Establishes the data source (``GET <var> FROM stixshifter://<source>``)
      2. Filters by every IOC pattern (UNION across patterns)
      3. ``DISP`` the result table

    The output is a valid Kestrel hunt regardless of whether Kestrel is
    installed in this deployment — the script string is the durable
    artifact saved to the case timeline.
    """
    if not iocs:
        raise ValueError("at least one IOC required to render a Kestrel hunt")

    # Build patterns per IOC.
    patterns: list[str] = []
    for kind, val in iocs:
        kestrel_kind = _IOC_KESTREL_MAP.get(
            kind.lower(), (kind.lower(), "value"),
        )
        ent_type, attr = kestrel_kind
        # Hash by length when caller said "hash"
        if kind.lower() == "hash":
            n = len(val)
            if n == 32:
                attr = "hashes.MD5"
            elif n == 40:
                attr = "hashes.'SHA-1'"
            else:
                attr = "hashes.'SHA-256'"
        safe = val.replace("'", "''")
        patterns.append(f"[{ent_type}:{attr} = '{safe}']")

    pattern_union = " OR ".join(patterns) if len(patterns) > 1 else patterns[0]

    # Compose the hunt. Kestrel syntax:
    #   nthits = GET ipv4-addr FROM stixshifter://splunk
    #            WHERE [ipv4-addr:value = '203.0.113.7']
    #            START 1d
    var_name = f"hits_{(technique_id or 'argus').replace('.', '_').lower()}"
    title_comment = f"# Argus hunt: {title}"
    technique_comment = (
        f"# MITRE ATT&CK technique: {technique_id}" if technique_id else ""
    )
    script_lines = [
        title_comment,
    ]
    if technique_comment:
        script_lines.append(technique_comment)
    script_lines += [
        "",
        f"{var_name} = GET ipv4-addr FROM stixshifter://{source_name}",
        f"   WHERE {pattern_union}",
        "   START 7d STOP now",
        "",
        f"DISP {var_name} ATTR id, value, src, dst",
    ]
    script = "\n".join(script_lines) + "\n"

    return HuntScript(
        title=title, technique_id=technique_id,
        source_name=source_name, iocs=iocs, script=script,
    )


# ── Execution ───────────────────────────────────────────────────────


@dataclass
class HuntResult:
    available: bool
    script: str
    stdout: str | None = None
    stderr: str | None = None
    returncode: int | None = None
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "script": self.script,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "returncode": self.returncode,
            "note": self.note,
        }


async def execute_hunt(script: str, *, timeout_seconds: int = 120) -> HuntResult:
    """Execute a Kestrel hunt via the CLI when available.

    When Kestrel is not installed the function returns
    ``available=False`` with the script preserved so the analyst can
    copy it into a Kestrel-equipped environment (e.g. an SOC playbook
    runner).
    """
    cli = _kestrel_cli_path()
    if cli is None:
        return HuntResult(
            available=False, script=script,
            note=(
                "Kestrel is not installed in this deployment. The hunt "
                "script above is preserved as a case artefact; install "
                "kestrel-lang in a sibling venv and set "
                "ARGUS_KESTREL_CLI to its path to enable execution."
            ),
        )

    import tempfile

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".hf", delete=False,
    ) as fh:
        fh.write(script)
        path = fh.name

    try:
        proc = await asyncio.create_subprocess_exec(
            cli, path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_seconds,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return HuntResult(
                available=True, script=script,
                stdout=None, stderr=None, returncode=None,
                note=f"timeout after {timeout_seconds}s",
            )
        return HuntResult(
            available=True, script=script,
            stdout=stdout_b.decode("utf-8", errors="replace"),
            stderr=stderr_b.decode("utf-8", errors="replace"),
            returncode=proc.returncode, note=None,
        )
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
