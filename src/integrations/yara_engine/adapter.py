"""BaseIntegration adapter for the local YARA rule engine."""

import logging
from datetime import datetime, timezone

from src.integrations.base import BaseIntegration
from src.integrations.yara_engine.engine import YaraEngine

logger = logging.getLogger(__name__)


class YaraIntegration(BaseIntegration):
    """Wraps :class:`YaraEngine` so it can be managed through the Argus
    integration framework alongside remote integrations.

    ``api_url`` is repurposed as the local rules directory path.
    ``api_key`` is accepted for interface compatibility but ignored.
    """

    name: str = "yara"
    display_name: str = "YARA Engine"
    description: str = "Local YARA rule compilation and matching engine"
    category: str = "detection"

    def __init__(self, api_url: str, api_key: str | None = None, **kwargs):
        super().__init__(api_url=api_url, api_key=api_key, **kwargs)
        # api_url is used as the rules directory path; strip the trailing
        # slash that BaseIntegration applies (harmless for filesystem paths,
        # but keeps it clean).
        self._engine = YaraEngine(rules_dir=self.api_url)

    # ------------------------------------------------------------------
    # Context manager — no HTTP session needed for a local engine
    # ------------------------------------------------------------------

    async def _get_session(self):
        """No-op: YARA engine is local, no HTTP session required."""
        return None

    async def close(self):
        """No-op: nothing to tear down for a local engine."""

    # ------------------------------------------------------------------
    # BaseIntegration interface
    # ------------------------------------------------------------------

    async def test_connection(self) -> dict:
        """Compile rules and report engine health.

        Returns:
            ``{"connected": True, "message": "..."}`` when rules compiled
            successfully (count > 0).
            ``{"connected": False, "message": "..."}`` when no rule files
            were found (engine works, but there is nothing to match against).
        """
        try:
            count = self._engine.compile_rules()
        except Exception as exc:
            logger.error("[%s] compile_rules() raised: %s", self.name, exc)
            return {
                "connected": False,
                "message": f"Rule compilation failed: {exc}",
            }

        if count > 0:
            return {
                "connected": True,
                "message": f"YARA engine ready — {count} rule file(s) compiled.",
            }

        return {
            "connected": False,
            "message": (
                "YARA engine is functional but no rule files were found "
                f"in {self._engine.rules_dir}."
            ),
        }

    async def sync(self) -> dict:
        """Download community rules, compile them, and return a summary.

        Returns:
            Dict with keys ``rule_count``, ``rules_dir``, and ``synced_at``.
        """
        try:
            await self._engine.sync_community_rules()
        except Exception as exc:
            logger.error("[%s] sync_community_rules() failed: %s", self.name, exc)
            return {
                "rule_count": 0,
                "rules_dir": str(self._engine.rules_dir),
                "synced_at": datetime.now(timezone.utc).isoformat(),
                "error": f"Community rule download failed: {exc}",
            }

        try:
            count = self._engine.compile_rules()
        except Exception as exc:
            logger.error("[%s] compile_rules() failed after sync: %s", self.name, exc)
            return {
                "rule_count": 0,
                "rules_dir": str(self._engine.rules_dir),
                "synced_at": datetime.now(timezone.utc).isoformat(),
                "error": f"Rule compilation failed after sync: {exc}",
            }

        return {
            "rule_count": count,
            "rules_dir": str(self._engine.rules_dir),
            "synced_at": datetime.now(timezone.utc).isoformat(),
        }

    @property
    def engine(self) -> YaraEngine:
        """Direct access to the underlying engine for match operations."""
        return self._engine
