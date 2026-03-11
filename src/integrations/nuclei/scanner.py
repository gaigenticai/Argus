"""Nuclei vulnerability scanner — runs nuclei as a local subprocess."""

import asyncio
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class NucleiScanner:
    """Wrapper around the nuclei binary for template-based vulnerability scanning.

    This is a local subprocess integration and does NOT inherit from
    BaseIntegration (no remote API involved).
    """

    def __init__(
        self,
        binary_path: str = "nuclei",
        templates_path: str | None = None,
    ):
        self.binary_path = binary_path
        self.templates_path = templates_path

    async def scan_target(
        self,
        target: str,
        templates: list[str] | None = None,
        severity: str | None = None,
    ) -> list[dict]:
        """Run a nuclei scan against a target and return structured findings.

        Args:
            target: URL or host to scan.
            templates: Optional list of template IDs/paths to use.
            severity: Optional comma-separated severity filter
                      (e.g. "critical,high").

        Returns:
            List of finding dicts with keys: template_id, name, severity,
            url, matched_at, description, cve_ids, remediation.
        """
        cmd: list[str] = [
            self.binary_path,
            "-target", target,
            "-json",
            "-silent",
        ]

        if self.templates_path:
            cmd.extend(["-t", self.templates_path])

        if templates:
            for tmpl in templates:
                cmd.extend(["-t", tmpl])

        if severity:
            cmd.extend(["-severity", severity])

        logger.info("Running nuclei: %s", " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except FileNotFoundError:
            logger.error(
                "nuclei binary not found at '%s'. Is it installed?",
                self.binary_path,
            )
            return []
        except Exception as exc:
            logger.error("Failed to run nuclei: %s", exc)
            return []

        if proc.returncode not in (0, None):
            stderr_text = stderr.decode(errors="replace").strip()
            if stderr_text:
                logger.warning("nuclei stderr: %s", stderr_text[:500])

        findings: list[dict] = []
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Skipping non-JSON nuclei output line: %s", line[:120])
                continue

            info = raw.get("info", {})
            classification = info.get("classification", {})

            finding = {
                "template_id": raw.get("template-id", raw.get("template_id", "")),
                "name": info.get("name", ""),
                "severity": info.get("severity", "unknown"),
                "url": raw.get("host", raw.get("url", target)),
                "matched_at": raw.get("matched-at", raw.get("matched_at", "")),
                "description": info.get("description", ""),
                "cve_ids": classification.get("cve-id", classification.get("cve_id", [])) or [],
                "remediation": info.get("remediation", ""),
            }
            findings.append(finding)

        logger.info(
            "Nuclei scan of %s completed — %d finding(s)", target, len(findings)
        )
        return findings

    async def check_installed(self) -> bool:
        """Verify that the nuclei binary is available."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary_path, "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            output = (stdout or stderr).decode(errors="replace").strip()
            logger.info("nuclei version: %s", output.split("\n")[0])
            return proc.returncode == 0
        except FileNotFoundError:
            logger.warning("nuclei binary not found at '%s'", self.binary_path)
            return False
        except Exception as exc:
            logger.error("Error checking nuclei installation: %s", exc)
            return False

    async def update_templates(self) -> None:
        """Run ``nuclei -update-templates`` to pull the latest template set."""
        logger.info("Updating nuclei templates...")
        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary_path, "-update-templates",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            output = (stdout.decode(errors="replace") + stderr.decode(errors="replace")).strip()
            if proc.returncode == 0:
                logger.info("nuclei templates updated successfully:\n%s", output[:500])
            else:
                logger.error("nuclei template update failed (rc=%d): %s", proc.returncode, output[:500])
        except FileNotFoundError:
            logger.error("nuclei binary not found at '%s'", self.binary_path)
        except Exception as exc:
            logger.error("Failed to update nuclei templates: %s", exc)
