"""BaseIntegration-compatible adapter for the local Nuclei scanner."""

from __future__ import annotations


import asyncio
import logging
from datetime import datetime, timezone

from src.integrations.base import BaseIntegration
from src.integrations.nuclei.scanner import NucleiScanner

logger = logging.getLogger(__name__)


class NucleiIntegration(BaseIntegration):
    """Adapter that exposes NucleiScanner through the standard integration interface.

    Nuclei is a local subprocess tool — it has no remote API.  The ``api_url``
    and ``api_key`` parameters are accepted for compatibility with the
    ``_get_client`` factory but are silently ignored.
    """

    name: str = "nuclei"
    display_name: str = "Nuclei Scanner"
    description: str = "Template-based vulnerability scanner by ProjectDiscovery"
    category: str = "scanner"

    def __init__(
        self,
        api_url: str = "",
        api_key: str | None = None,
        *,
        binary_path: str = "nuclei",
        templates_path: str | None = None,
        **kwargs,
    ):
        # BaseIntegration.__init__ stores api_url/api_key and opens no
        # connections, so it's safe to call even though we won't use them.
        super().__init__(api_url=api_url, api_key=api_key, **kwargs)
        self._scanner = NucleiScanner(
            binary_path=binary_path,
            templates_path=templates_path,
        )

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
        """Verify that the nuclei binary is installed and executable.

        Returns:
            ``{"connected": True, "message": "..."}`` if nuclei is available,
            ``{"connected": False, "message": "..."}`` otherwise.
        """
        try:
            installed = await self._scanner.check_installed()
        except Exception as exc:
            logger.error("Nuclei connection test failed: %s", exc)
            return {
                "connected": False,
                "message": f"Nuclei check raised an exception: {exc}",
            }

        if installed:
            return {
                "connected": True,
                "message": (
                    f"Nuclei binary found at '{self._scanner.binary_path}' "
                    "and is operational."
                ),
            }

        return {
            "connected": False,
            "message": (
                f"Nuclei binary not found or not executable at "
                f"'{self._scanner.binary_path}'."
            ),
        }

    async def sync(self) -> dict:
        """Pull the latest nuclei template set.

        Returns:
            Summary dict with ``"status"`` (``"ok"`` | ``"error"``),
            ``"action"``, and ``"synced_at"`` keys.
        """
        started_at = datetime.now(timezone.utc)

        # Ensure the binary is reachable before attempting the update.
        installed = await self._scanner.check_installed()
        if not installed:
            return {
                "status": "error",
                "action": "update_templates",
                "message": (
                    f"Nuclei binary not found at '{self._scanner.binary_path}'. "
                    "Cannot update templates."
                ),
                "synced_at": started_at.isoformat(),
            }

        try:
            await self._scanner.update_templates()
        except Exception as exc:
            logger.error("Nuclei template sync failed: %s", exc)
            return {
                "status": "error",
                "action": "update_templates",
                "message": f"Template update raised an exception: {exc}",
                "synced_at": started_at.isoformat(),
            }

        finished_at = datetime.now(timezone.utc)
        elapsed = (finished_at - started_at).total_seconds()

        return {
            "status": "ok",
            "action": "update_templates",
            "message": "Nuclei templates updated successfully.",
            "synced_at": finished_at.isoformat(),
            "elapsed_seconds": round(elapsed, 2),
        }

    # ------------------------------------------------------------------
    # Convenience pass-through
    # ------------------------------------------------------------------

    @property
    def scanner(self) -> NucleiScanner:
        """Direct access to the underlying NucleiScanner for scan operations."""
        return self._scanner
