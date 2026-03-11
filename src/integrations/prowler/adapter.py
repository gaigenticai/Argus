"""BaseIntegration-compatible adapter for the local Prowler cloud security scanner."""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone

from src.integrations.base import BaseIntegration
from src.integrations.prowler.client import ProwlerRunner

logger = logging.getLogger(__name__)

_VALID_PROVIDERS = frozenset({"aws", "azure", "gcp"})


class ProwlerIntegration(BaseIntegration):
    """Adapter that exposes ProwlerRunner through the standard integration interface.

    Prowler is a local CLI tool — it has no remote API.  The ``api_url``
    parameter is repurposed as the cloud provider name (``"aws"``,
    ``"azure"``, ``"gcp"``).  ``api_key`` is accepted for interface
    compatibility but ignored; Prowler authenticates using cloud provider
    credentials already configured in the environment (e.g. AWS
    ``~/.aws/credentials``, ``AZURE_*`` env vars, ``gcloud auth``).
    """

    name: str = "prowler"
    display_name: str = "Prowler Cloud Security"
    description: str = "Cloud security posture assessment via Prowler CLI"
    category: str = "cloud_security"

    def __init__(
        self,
        api_url: str = "aws",
        api_key: str | None = None,
        **kwargs,
    ):
        super().__init__(api_url=api_url, api_key=api_key, **kwargs)
        self._runner = ProwlerRunner()
        self._provider = self._resolve_provider(api_url)

    # ------------------------------------------------------------------
    # HTTP session overrides — no network needed for a local binary
    # ------------------------------------------------------------------

    async def _get_session(self):  # type: ignore[override]
        """No HTTP session required for a local subprocess integration."""
        return None

    async def close(self):
        """Nothing to tear down — no open connections."""

    # ------------------------------------------------------------------
    # Required interface
    # ------------------------------------------------------------------

    async def test_connection(self) -> dict:
        """Verify that the ``prowler`` CLI is installed and executable.

        Returns:
            ``{"connected": True, "message": "..."}`` if prowler is available,
            ``{"connected": False, "message": "..."}`` otherwise.
        """
        try:
            installed = await self._runner.check_installed()
        except Exception as exc:
            logger.error("Prowler connection test failed: %s", exc)
            return {
                "connected": False,
                "message": f"Prowler check raised an exception: {exc}",
            }

        if installed:
            return {
                "connected": True,
                "message": (
                    f"Prowler CLI is installed and operational. "
                    f"Configured provider: {self._provider}."
                ),
            }

        return {
            "connected": False,
            "message": "Prowler CLI not found on PATH or not executable.",
        }

    async def sync(self) -> dict:
        """Run a full Prowler scan for the configured cloud provider.

        Returns:
            Summary dict with ``"status"``, ``"provider"``, ``"total_findings"``,
            ``"severity_breakdown"``, ``"findings"``, ``"synced_at"``, and
            ``"elapsed_seconds"`` keys.
        """
        started_at = datetime.now(timezone.utc)

        installed = await self._runner.check_installed()
        if not installed:
            return {
                "status": "error",
                "provider": self._provider,
                "message": "Prowler CLI not found. Cannot run scan.",
                "total_findings": 0,
                "severity_breakdown": {},
                "findings": [],
                "synced_at": started_at.isoformat(),
            }

        try:
            findings = await self._runner.run_scan(provider=self._provider)
        except Exception as exc:
            logger.error("Prowler scan failed for provider '%s': %s", self._provider, exc)
            return {
                "status": "error",
                "provider": self._provider,
                "message": f"Prowler scan raised an exception: {exc}",
                "total_findings": 0,
                "severity_breakdown": {},
                "findings": [],
                "synced_at": started_at.isoformat(),
            }

        finished_at = datetime.now(timezone.utc)
        elapsed = (finished_at - started_at).total_seconds()

        severity_counts = Counter(f["severity"] for f in findings)

        return {
            "status": "ok",
            "provider": self._provider,
            "message": f"Prowler scan completed for {self._provider}.",
            "total_findings": len(findings),
            "severity_breakdown": dict(severity_counts),
            "findings": findings,
            "synced_at": finished_at.isoformat(),
            "elapsed_seconds": round(elapsed, 2),
        }

    # ------------------------------------------------------------------
    # Convenience pass-through
    # ------------------------------------------------------------------

    @property
    def runner(self) -> ProwlerRunner:
        """Direct access to the underlying ProwlerRunner for custom scans."""
        return self._runner

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_provider(api_url: str) -> str:
        """Extract and validate the cloud provider from the ``api_url`` parameter.

        Accepts raw provider names (``"aws"``) as well as URL-like values
        that may have been stored in a config database (e.g. ``"aws/"``).
        Falls back to ``"aws"`` when the value is empty or unrecognised.
        """
        candidate = api_url.strip().rstrip("/").lower()
        if candidate in _VALID_PROVIDERS:
            return candidate
        logger.warning(
            "[prowler] Unrecognised provider '%s', defaulting to 'aws'",
            api_url,
        )
        return "aws"
