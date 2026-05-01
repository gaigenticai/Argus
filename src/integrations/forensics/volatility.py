"""Volatility 3 wrapper (P3 #3.11).

Volatility 3 is a memory-image analysis framework. It's a heavy
dependency (large symbol files, native deps) so we **don't** bundle
it. Operators install ``vol3`` (or ``volatility3``) into a sibling
venv or system package; this wrapper shells out to whatever's on
PATH (override via ``ARGUS_VOLATILITY_CLI``).

Output is JSON when the plugin supports ``--renderer=json``; we parse
it into a normalised :class:`VolatilityResult` so the case_copilot
agent can attach findings to the case timeline.

Common plugins:
  windows.pslist   running processes
  windows.netscan  network sockets
  windows.malfind  injected code
  linux.pslist
  linux.bash
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


def _cli_path() -> str | None:
    override = (os.environ.get("ARGUS_VOLATILITY_CLI") or "").strip()
    if override:
        return override if os.path.exists(override) else None
    for name in ("vol", "vol3", "volatility3"):
        p = shutil.which(name)
        if p:
            return p
    return None


def is_available() -> dict[str, Any]:
    cli = _cli_path()
    return {"available": bool(cli), "cli_path": cli}


@dataclass
class VolatilityResult:
    available: bool
    plugin: str
    image_path: str
    rows: list[dict[str, Any]] = field(default_factory=list)
    stderr: str | None = None
    returncode: int | None = None
    note: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "plugin": self.plugin,
            "image_path": self.image_path,
            "rows": self.rows,
            "stderr": self.stderr,
            "returncode": self.returncode,
            "note": self.note,
            "error": self.error,
        }


_DEFAULT_TIMEOUT = 1800  # 30 min — memory analysis is slow


async def run_plugin(
    *,
    plugin: str,
    image_path: str,
    extra_args: list[str] | None = None,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
) -> VolatilityResult:
    """Run a Volatility 3 plugin against a memory image and return
    parsed JSON rows.

    ``image_path`` should be an absolute path the operator has placed
    on disk (Argus does NOT accept binary uploads here — operators
    push memory images via the case-evidence-vault upload path).
    """
    cli = _cli_path()
    if cli is None:
        return VolatilityResult(
            available=False, plugin=plugin, image_path=image_path,
            note=(
                "Volatility 3 is not installed in this deployment. Install "
                "vol3 in a sibling venv and set ARGUS_VOLATILITY_CLI."
            ),
        )

    if not os.path.isabs(image_path):
        return VolatilityResult(
            available=True, plugin=plugin, image_path=image_path,
            error="image_path must be absolute",
        )
    if not os.path.exists(image_path):
        return VolatilityResult(
            available=True, plugin=plugin, image_path=image_path,
            error=f"image not found: {image_path}",
        )

    args = [cli, "-q", "--renderer=json", "-f", image_path, plugin]
    if extra_args:
        args.extend(extra_args)

    logger.info("[volatility] running %s on %s", plugin, image_path)
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
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
            return VolatilityResult(
                available=True, plugin=plugin, image_path=image_path,
                note=f"timeout after {timeout_seconds}s",
            )
    except FileNotFoundError as exc:
        return VolatilityResult(
            available=True, plugin=plugin, image_path=image_path,
            error=str(exc),
        )

    stdout = stdout_b.decode("utf-8", errors="replace")
    stderr = stderr_b.decode("utf-8", errors="replace")
    rows: list[dict[str, Any]] = []
    if proc.returncode == 0 and stdout.strip():
        try:
            data = json.loads(stdout)
            # Volatility 3 JSON renderer emits a list of {column: value}
            # dicts at top level for most plugins. Some plugins wrap in
            # ``{"rows": [...]}`` — handle both.
            if isinstance(data, list):
                rows = data
            elif isinstance(data, dict) and "rows" in data:
                rows = list(data["rows"]) if isinstance(data["rows"], list) else []
        except ValueError as exc:
            return VolatilityResult(
                available=True, plugin=plugin, image_path=image_path,
                stderr=stderr, returncode=proc.returncode,
                error=f"failed to parse Volatility JSON: {exc}",
            )

    return VolatilityResult(
        available=True, plugin=plugin, image_path=image_path,
        rows=rows, stderr=stderr or None,
        returncode=proc.returncode,
    )
