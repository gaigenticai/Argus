"""Prowler cloud security scanner — CLI-based, no API.

Like the nuclei wrapper, this surface raises on transport failures
rather than returning ``[]``. A regulated buyer's compliance report
must be able to tell "scan succeeded with zero findings" from "scan
never ran" — the latter is a deployment bug worth alerting on.
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path


logger = logging.getLogger(__name__)


_DEFAULT_TIMEOUT_SECONDS = 1800  # prowler scans are heavy


class ProwlerError(RuntimeError):
    """Base for prowler runner errors."""


class BinaryNotFound(ProwlerError):
    """prowler binary missing on PATH."""


class ScanTimedOut(ProwlerError):
    """Wall-clock budget exceeded; subprocess was killed."""


class ScanFailed(ProwlerError):
    """Non-zero exit (other than 0/2 which both mean "scan completed")."""


class ProwlerRunner:
    """Runs Prowler cloud security assessments via the CLI.

    Prowler is a command-line tool (not an HTTP API), so this class
    shells out via :func:`asyncio.create_subprocess_exec` and parses
    the JSON output. Output bytes are bounded by the temporary
    directory + the prowler --output-* flags; we don't read the JSON
    until prowler exits.
    """

    async def check_installed(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "prowler", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.error("[prowler] CLI not found on PATH")
            return False

        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        except asyncio.TimeoutError:
            with _suppress():
                proc.kill()
                await proc.wait()
            logger.error("[prowler] --version timed out")
            return False

        if proc.returncode == 0:
            version = stdout.decode().strip()
            logger.info("[prowler] Installed — %s", version)
            return True
        logger.warning("[prowler] CLI exited with code %d", proc.returncode)
        return False

    async def run_scan(
        self,
        provider: str = "aws",
        checks: list[str] | None = None,
        *,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> list[dict]:
        """Execute a Prowler scan and return parsed findings.

        Raises:
            BinaryNotFound: prowler not installed.
            ScanTimedOut:   ``timeout`` exceeded before scan completion.
            ScanFailed:     non-zero exit (other than 0 / 2).

        Returns the list of normalised finding dicts (see
        :meth:`parse_findings`). Empty list is a real signal — the scan
        ran and saw nothing.
        """
        if not await self.check_installed():
            raise BinaryNotFound("prowler CLI not installed; cannot run scan")

        # Adversarial audit D-18 — ``checks`` and ``provider`` are
        # operator-supplied and get joined into a CLI argv. Even with
        # ``create_subprocess_exec`` (no shell), an unexpected character
        # in a check name (commas, semicolons, flag-leading dashes) can
        # break Prowler's own arg parser. Lock both to a strict
        # character class.
        import re as _re

        _SAFE = _re.compile(r"^[A-Za-z0-9_.-]+$")
        if not _SAFE.match(provider):
            raise ValueError(f"prowler provider {provider!r} contains unsafe characters")
        validated_checks: list[str] = []
        if checks:
            for c in checks:
                if not isinstance(c, str) or not _SAFE.match(c):
                    raise ValueError(
                        f"prowler check {c!r} must match [A-Za-z0-9_.-]+"
                    )
                validated_checks.append(c)

        with tempfile.TemporaryDirectory(prefix="prowler-argus-") as tmpdir:
            cmd: list[str] = [
                "prowler",
                provider,
                "--output-formats", "json",
                "--output-directory", tmpdir,
                "--output-filename", "output",
            ]
            if validated_checks:
                cmd.extend(["--checks", ",".join(validated_checks)])

            logger.info("[prowler] Running: %s", " ".join(cmd))

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError as exc:
                raise BinaryNotFound("prowler CLI not on PATH") from exc

            try:
                _, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                with _suppress():
                    proc.kill()
                    await proc.wait()
                raise ScanTimedOut(
                    f"prowler exceeded {timeout}s budget"
                )

            # Exit codes: 0 = success-no-failures, 2 = success-with-failures.
            # Anything else = transport failure.
            if proc.returncode not in (0, 2):
                raise ScanFailed(
                    f"prowler exited with code {proc.returncode}: "
                    f"{(stderr or b'').decode()[:500]}"
                )

            json_path = self._find_json_output(Path(tmpdir))
            if json_path is None:
                raise ScanFailed(
                    f"prowler succeeded but produced no JSON output in {tmpdir}"
                )

            try:
                raw = json.loads(json_path.read_text())
            except json.JSONDecodeError as exc:
                raise ScanFailed(
                    f"prowler output is not valid JSON: {exc}"
                ) from exc

            raw_list = raw if isinstance(raw, list) else [raw]
            return self.parse_findings(raw_list)

    def parse_findings(self, raw_output: list[dict]) -> list[dict]:
        findings: list[dict] = []
        for item in raw_output:
            findings.append({
                "provider": item.get("Provider", item.get("provider", "")),
                "service": item.get("ServiceName", item.get("service", "")),
                "severity": item.get(
                    "Severity", item.get("severity", "info")
                ).lower(),
                "finding": (
                    item.get("CheckTitle")
                    or item.get("Description")
                    or item.get("finding", "")
                ),
                "resource": (
                    item.get("ResourceId")
                    or item.get("ResourceArn")
                    or item.get("resource", "")
                ),
                "remediation": (
                    item.get("Remediation", {})
                        .get("Recommendation", {})
                        .get("Text", "")
                    if isinstance(item.get("Remediation"), dict)
                    else item.get("remediation", "")
                ),
                "status": item.get(
                    "Status", item.get("status", "unknown")
                ).lower(),
            })

        logger.info("[prowler] Parsed %d finding(s)", len(findings))
        return findings

    @staticmethod
    def _find_json_output(directory: Path) -> Path | None:
        for p in directory.rglob("*.json"):
            return p
        return None


class _suppress:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return True


__all__ = [
    "ProwlerRunner",
    "ProwlerError",
    "BinaryNotFound",
    "ScanTimedOut",
    "ScanFailed",
]
