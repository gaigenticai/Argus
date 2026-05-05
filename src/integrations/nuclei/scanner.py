"""Nuclei vulnerability scanner — runs nuclei as a local subprocess.

The wrapper exposes one async surface (``scan_target``) that returns
parsed findings. Failure modes are surfaced as exceptions so callers
can distinguish:

    * ``BinaryNotFound``     — nuclei binary missing (deployment misconfig)
    * ``ScanTimedOut``       — wall-clock budget exceeded
    * ``ScanFailed``         — non-zero exit, non-recognised stderr

Returning an empty list silently is a footgun in regulated installs:
the API consumer can't tell "no findings" from "scan crashed", which
breaks compliance reporting. We raise — the worker translates that
into a job FAILED row with the underlying error text.
"""

from __future__ import annotations


import asyncio
import json
import logging

from src.config.settings import settings


logger = logging.getLogger(__name__)


# Default wall-clock budget. Caller can override via the ``timeout``
# kwarg on ``scan_target``.
_DEFAULT_TIMEOUT_SECONDS = 900


class ScannerError(RuntimeError):
    """Base for nuclei scanner errors."""


class BinaryNotFound(ScannerError):
    """nuclei binary missing on PATH / configured location."""


class ScanTimedOut(ScannerError):
    """Wall-clock budget exceeded; subprocess was killed."""


class ScanFailed(ScannerError):
    """Non-zero exit or other transport failure."""


class NucleiScanner:
    def __init__(
        self,
        binary_path: str | None = None,
        templates_path: str | None = None,
    ):
        self.binary_path = binary_path or settings.integrations.nuclei_binary
        self.templates_path = templates_path or settings.integrations.nuclei_templates

    async def scan_target(
        self,
        target: str,
        templates: list[str] | None = None,
        severity: str | None = None,
        *,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> list[dict]:
        """Run a nuclei scan against a target and return structured findings.

        Runs inside a Bubblewrap sandbox with the templates directory
        mounted read-only — nuclei cannot escape into the host
        filesystem even if a template parser is exploitable.

        Raises:
            BinaryNotFound: nuclei binary not on PATH / configured path.
            ScanTimedOut:   ``timeout`` seconds elapsed before completion.
            ScanFailed:     non-zero exit or unparseable output stream.

        Returns the parsed finding list on success (empty list = scan
        succeeded but found nothing — a real, actionable signal).
        """
        from src.core.sandbox import SandboxPolicy, run_sandboxed

        # Adversarial audit D-18 — ``templates`` is operator-supplied and
        # gets fed straight into the subprocess argv + bubblewrap binds.
        # A directory-traversal template path (``../../../etc/shadow``)
        # would otherwise be readable inside the sandbox. Resolve every
        # entry against ``templates_path`` and refuse anything that
        # escapes the rules root.
        sanitised_templates: list[str] = []
        if templates:
            if not self.templates_path:
                raise ScanFailed(
                    "nuclei: cannot accept ``templates=`` overrides without a "
                    "configured templates_path root"
                )
            from pathlib import Path as _P

            root = _P(self.templates_path).expanduser().resolve()
            for tmpl in templates:
                candidate = (root / tmpl).resolve()
                if not (candidate == root or candidate.is_relative_to(root)):
                    raise ScanFailed(
                        f"nuclei: template {tmpl!r} escapes templates_path"
                    )
                sanitised_templates.append(str(candidate))

        cmd: list[str] = [
            self.binary_path,
            "-target", target,
            "-json",
            "-silent",
            "-disable-update-check",
        ]
        if self.templates_path:
            cmd.extend(["-t", self.templates_path])
        for tmpl in sanitised_templates:
            cmd.extend(["-t", tmpl])
        if severity:
            cmd.extend(["-severity", severity])

        logger.info("Running nuclei: %s", " ".join(cmd))

        binds = []
        if self.templates_path:
            binds.append(self.templates_path)
        binds.extend(sanitised_templates)

        policy = SandboxPolicy(
            share_net=True,
            readonly_binds=tuple(binds),
            timeout_seconds=timeout,
        )

        try:
            returncode, stdout, stderr = await run_sandboxed(cmd, policy=policy)
        except FileNotFoundError as exc:
            raise BinaryNotFound(
                f"nuclei binary not found at {self.binary_path!r}. "
                f"Ensure it is installed in the runtime image."
            ) from exc
        except asyncio.TimeoutError as exc:
            raise ScanTimedOut(
                f"nuclei exceeded {timeout}s budget on target {target!r}"
            ) from exc

        if returncode not in (0, None):
            stderr_text = (stderr or b"").decode(errors="replace").strip()
            # nuclei emits informational lines on stderr even on success; only
            # bubble a failure when the exit code is non-zero. Many CI runs
            # produce stderr noise that isn't actionable.
            raise ScanFailed(
                f"nuclei exited with code {returncode}: {stderr_text[:500]}"
            )

        findings: list[dict] = []
        stdout_bytes = stdout if isinstance(stdout, (bytes, bytearray)) else (
            stdout or b""
        )
        for line in (stdout_bytes or b"").decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                # Non-JSON line on stdout in JSON mode is unusual; log it
                # but don't fail the whole scan over a single garbled row.
                logger.warning(
                    "Skipping non-JSON nuclei output line: %s", line[:200]
                )
                continue

            info = raw.get("info", {})
            classification = info.get("classification", {})

            findings.append({
                "template_id": raw.get("template-id", raw.get("template_id", "")),
                "name": info.get("name", ""),
                "severity": info.get("severity", "unknown"),
                "url": raw.get("host", raw.get("url", target)),
                "matched_at": raw.get("matched-at", raw.get("matched_at", "")),
                "description": info.get("description", ""),
                "cve_ids": classification.get(
                    "cve-id", classification.get("cve_id", [])
                ) or [],
                "remediation": info.get("remediation", ""),
            })

        logger.info("Nuclei scan of %s completed — %d finding(s)", target, len(findings))
        return findings

    async def check_installed(self) -> bool:
        """Verify the nuclei binary is on PATH and executable.

        ``nuclei -version`` is a static, inert probe — no scanning,
        no network — so we bypass the bwrap sandbox here. The sandbox
        wrapper requires unprivileged user namespaces; many Docker
        defaults (seccomp profile + missing CAP_SYS_ADMIN) reject
        ``bwrap --unshare-user`` and the call exits with rc=1.
        Result: nuclei was installed in the worker image but the
        version check failed, the EASM maintenance task marked itself
        ``disabled`` with the misleading "binary not detected"
        message, and operators thought EASM wasn't shipping.
        """
        import shutil
        real_path = shutil.which(self.binary_path) or self.binary_path
        try:
            proc = await asyncio.create_subprocess_exec(
                real_path, "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=10
                )
            except asyncio.TimeoutError:
                proc.kill()
                try:
                    await proc.communicate()
                except Exception:  # noqa: BLE001
                    pass
                logger.warning("nuclei -version timed out")
                return False
        except FileNotFoundError:
            logger.warning("nuclei binary not found at %r", self.binary_path)
            return False

        rc = proc.returncode or 0
        output = (stdout or stderr or b"").decode(errors="replace").strip()
        if rc == 0:
            logger.info("nuclei version: %s", output.split("\n")[0])
            return True
        logger.error("nuclei -version exited %s: %s", rc, output[:200])
        return False


class _suppress_kill_exceptions:
    """tiny context manager — kill() can race with normal exit."""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return True


__all__ = [
    "NucleiScanner",
    "ScannerError",
    "BinaryNotFound",
    "ScanTimedOut",
    "ScanFailed",
]
