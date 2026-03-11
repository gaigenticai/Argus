"""Sigma rule adapter — wraps SigmaConverter as a BaseIntegration-compatible service."""

import logging
from datetime import datetime, timezone

from src.integrations.base import BaseIntegration
from src.integrations.sigma.converter import SigmaConverter, _VALID_LEVELS

logger = logging.getLogger(__name__)


class SigmaAdapter(BaseIntegration):
    """BaseIntegration adapter for the local SigmaConverter engine.

    Unlike most integrations, Sigma rules are loaded from a local directory
    rather than fetched from a remote API.  The ``api_url`` parameter is
    repurposed as the path to the rules directory; ``api_key`` is accepted
    for interface compatibility but ignored.
    """

    name: str = "sigma"
    display_name: str = "Sigma Rules"
    description: str = "Local Sigma detection rule engine for threat matching."
    category: str = "detection"

    def __init__(self, api_url: str, api_key: str | None = None, **kwargs):
        # api_url is treated as the rules directory path.
        # We intentionally skip the BaseIntegration rstrip("/") on the raw
        # value because it is a filesystem path, not a URL — but we still
        # store it via super().__init__ for consistency with the base class
        # interface.
        super().__init__(api_url=api_url, api_key=api_key, **kwargs)
        self._converter = SigmaConverter(rules_dir=api_url)

    # ------------------------------------------------------------------
    # Context manager — no HTTP session to manage, but the protocol
    # must be honoured so callers can use ``async with SigmaAdapter(…)``.
    # ------------------------------------------------------------------

    async def _get_session(self):
        """No-op — Sigma rules are loaded from disk, not over HTTP."""
        return None

    async def close(self):
        """No-op — nothing to tear down for a local engine."""

    # ------------------------------------------------------------------
    # BaseIntegration abstract methods
    # ------------------------------------------------------------------

    async def test_connection(self) -> dict:
        """Verify that the rules directory is accessible and contains rules.

        Returns:
            ``{"connected": True, "message": "Loaded N Sigma rule(s)"}`` on
            success, or ``{"connected": False, "message": "…"}`` when the
            directory is missing or empty.
        """
        try:
            count = self._converter.load_rules()
        except Exception as exc:
            logger.error("[%s] Failed to load Sigma rules: %s", self.name, exc)
            return {
                "connected": False,
                "message": f"Error loading rules: {exc}",
            }

        if count > 0:
            return {
                "connected": True,
                "message": f"Loaded {count} Sigma rule(s)",
            }

        return {
            "connected": False,
            "message": "No Sigma rules found in the configured directory",
        }

    async def sync(self) -> dict:
        """Load rules and return a summary with total count and level breakdown.

        Returns:
            Dict of the form::

                {
                    "synced_at": "2026-03-11T…Z",
                    "total_rules": 42,
                    "levels": {
                        "critical": 3,
                        "high": 10,
                        "medium": 15,
                        "low": 8,
                        "informational": 6,
                    },
                }
        """
        try:
            total = self._converter.load_rules()
        except Exception as exc:
            logger.error("[%s] Sync failed during rule loading: %s", self.name, exc)
            return {
                "synced_at": datetime.now(timezone.utc).isoformat(),
                "total_rules": 0,
                "levels": {},
                "error": str(exc),
            }

        levels: dict[str, int] = {}
        for level in sorted(_VALID_LEVELS):
            count = len(self._converter.get_rules(level=level))
            levels[level] = count

        return {
            "synced_at": datetime.now(timezone.utc).isoformat(),
            "total_rules": total,
            "levels": levels,
        }
