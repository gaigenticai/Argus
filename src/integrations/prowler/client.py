"""Prowler cloud security scanner — CLI-based, no API."""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


class ProwlerRunner:
    """Runs Prowler cloud security assessments via the CLI.

    Prowler is a command-line tool (not an HTTP API), so this class
    shells out via :func:`asyncio.create_subprocess_exec` and parses
    the JSON output.
    """

    async def check_installed(self) -> bool:
        """Verify that the ``prowler`` CLI is available on the system.

        Returns:
            *True* if ``prowler --version`` exits successfully.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "prowler", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                version = stdout.decode().strip()
                logger.info("[prowler] Installed — %s", version)
                return True
            logger.warning("[prowler] CLI exited with code %d", proc.returncode)
            return False
        except FileNotFoundError:
            logger.error("[prowler] CLI not found on PATH")
            return False
        except Exception as e:
            logger.error("[prowler] Failed to check installation: %s", e)
            return False

    async def run_scan(
        self,
        provider: str = "aws",
        checks: list[str] | None = None,
    ) -> list[dict]:
        """Execute a Prowler scan and return parsed findings.

        Args:
            provider: Cloud provider to scan (``aws``, ``azure``, ``gcp``).
            checks: Optional list of specific check IDs to run. When *None*,
                Prowler runs all checks for the provider.

        Returns:
            A list of normalised finding dicts (see :meth:`parse_findings`).
            Empty list on failure.
        """
        if not await self.check_installed():
            logger.error("[prowler] Cannot run scan — CLI not installed")
            return []

        with tempfile.TemporaryDirectory(prefix="prowler-argus-") as tmpdir:
            output_file = Path(tmpdir) / "output"

            cmd: list[str] = [
                "prowler",
                provider,
                "--output-formats", "json",
                "--output-directory", tmpdir,
                "--output-filename", "output",
            ]

            if checks:
                cmd.extend(["--checks", ",".join(checks)])

            logger.info("[prowler] Running: %s", " ".join(cmd))

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await proc.communicate()

                if proc.returncode not in (0, 2):
                    # Prowler returns 2 when findings have failures — that's normal
                    logger.error(
                        "[prowler] Exited with code %d: %s",
                        proc.returncode,
                        stderr.decode()[:500],
                    )
                    return []

                # Prowler may append .json or place inside subdirectory
                json_path = self._find_json_output(Path(tmpdir))
                if json_path is None:
                    logger.error("[prowler] No JSON output file found in %s", tmpdir)
                    return []

                raw = json.loads(json_path.read_text())
                raw_list = raw if isinstance(raw, list) else [raw]
                return self.parse_findings(raw_list)

            except Exception as e:
                logger.error("[prowler] Scan failed: %s", e)
                return []

    def parse_findings(self, raw_output: list[dict]) -> list[dict]:
        """Normalise raw Prowler JSON findings into a consistent schema.

        Args:
            raw_output: List of raw finding dicts as emitted by Prowler.

        Returns:
            A list of dicts with keys: ``provider``, ``service``,
            ``severity``, ``finding``, ``resource``, ``remediation``,
            ``status``.
        """
        findings: list[dict] = []

        for item in raw_output:
            findings.append(
                {
                    "provider": item.get("Provider", item.get("provider", "")),
                    "service": item.get("ServiceName", item.get("service", "")),
                    "severity": item.get("Severity", item.get("severity", "info")).lower(),
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
                        item.get("Remediation", {}).get("Recommendation", {}).get("Text", "")
                        if isinstance(item.get("Remediation"), dict)
                        else item.get("remediation", "")
                    ),
                    "status": item.get("Status", item.get("status", "unknown")).lower(),
                }
            )

        logger.info("[prowler] Parsed %d finding(s)", len(findings))
        return findings

    @staticmethod
    def _find_json_output(directory: Path) -> Path | None:
        """Locate the JSON output file in the prowler output directory."""
        for p in directory.rglob("*.json"):
            return p
        return None
