"""BaseIntegration-compatible adapter for the Suricata Eve JSON ingestor."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from src.integrations.base import BaseIntegration
from src.integrations.suricata.client import SuricataIngestor

logger = logging.getLogger(__name__)

_TAIL_LINES = 10_000


def _read_tail_lines(path: str, max_lines: int) -> list[str]:
    """Read the last *max_lines* lines from a file efficiently.

    Uses a deque with maxlen so memory usage stays bounded regardless of
    total file size.
    """
    tail: deque[str] = deque(maxlen=max_lines)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            tail.append(line)
    return list(tail)


def _parse_lines(lines: list[str]) -> list[dict]:
    """Parse lines of JSON, skipping any that are malformed or empty."""
    events: list[dict] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            events.append(json.loads(stripped))
        except json.JSONDecodeError:
            logger.debug("[suricata] Skipping malformed JSON line: %.120s", stripped)
    return events


class SuricataAdapter(BaseIntegration):
    """Wraps :class:`SuricataIngestor` so it can be used inside the Argus
    integration framework alongside HTTP-based integrations.

    ``api_url`` is re-purposed as the filesystem path to the Suricata
    ``eve.json`` log file.  ``api_key`` is accepted for interface
    compatibility but ignored.
    """

    name: str = "suricata"
    display_name: str = "Suricata IDS/IPS"
    description: str = "Ingests Suricata Eve JSON logs from the local filesystem."
    category: str = "ids"

    def __init__(self, api_url: str, api_key: str | None = None, **kwargs):
        # Store the raw path before BaseIntegration strips trailing slashes.
        self._eve_path: str = api_url.rstrip("/")
        # BaseIntegration.__init__ sets self.api_url, self.api_key, etc.
        super().__init__(api_url=api_url, api_key=api_key, **kwargs)
        self._ingestor = SuricataIngestor()

    # ------------------------------------------------------------------
    # Context manager — no HTTP session needed for local file access
    # ------------------------------------------------------------------

    async def _get_session(self):  # type: ignore[override]
        """No-op — Suricata reads from the local filesystem."""
        return None

    async def close(self):
        """No resources to release for a local-file integration."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    # ------------------------------------------------------------------
    # Interface
    # ------------------------------------------------------------------

    async def test_connection(self) -> dict:
        """Check whether the configured Eve JSON log file exists and is readable.

        Returns:
            ``{"connected": True, "message": ...}`` when the file is
            accessible, or ``{"connected": False, "message": ...}`` with a
            human-readable reason on failure.
        """
        path = self._eve_path

        try:
            exists = await asyncio.to_thread(os.path.isfile, path)
            if not exists:
                return {
                    "connected": False,
                    "message": f"Eve JSON log not found at {path}",
                }

            readable = await asyncio.to_thread(os.access, path, os.R_OK)
            if not readable:
                return {
                    "connected": False,
                    "message": f"Eve JSON log at {path} exists but is not readable (permission denied)",
                }

            size = (await asyncio.to_thread(os.path.getsize, path))
            return {
                "connected": True,
                "message": (
                    f"Eve JSON log at {path} is accessible "
                    f"({size:,} bytes)"
                ),
            }
        except OSError as exc:
            return {
                "connected": False,
                "message": f"OS error checking {path}: {exc}",
            }

    async def sync(self) -> dict:
        """Read, parse, and extract alerts from the Eve JSON log.

        Reads the last :data:`_TAIL_LINES` lines of the file to keep memory
        and parse time bounded on busy sensors.

        Returns:
            A summary dict::

                {
                    "synced_at": "<ISO-8601 UTC>",
                    "eve_path": "<path>",
                    "total_events": <int>,
                    "alert_count": <int>,
                    "alerts": [<normalised alert dicts>],
                }
        """
        path = self._eve_path
        synced_at = datetime.now(timezone.utc).isoformat()

        # Read last N lines off the main thread.
        try:
            raw_lines = await asyncio.to_thread(_read_tail_lines, path, _TAIL_LINES)
        except FileNotFoundError:
            logger.error("[suricata] Eve JSON log not found: %s", path)
            return {
                "synced_at": synced_at,
                "eve_path": path,
                "total_events": 0,
                "alert_count": 0,
                "alerts": [],
                "error": f"File not found: {path}",
            }
        except OSError as exc:
            logger.error("[suricata] Failed to read %s: %s", path, exc)
            return {
                "synced_at": synced_at,
                "eve_path": path,
                "total_events": 0,
                "alert_count": 0,
                "alerts": [],
                "error": str(exc),
            }

        # Parse JSON lines off the main thread.
        events = await asyncio.to_thread(_parse_lines, raw_lines)
        total_events = len(events)

        # Extract alerts via the existing ingestor (CPU-bound for large logs).
        alerts = await asyncio.to_thread(self._ingestor.parse_eve_json, events)

        logger.info(
            "[suricata] Sync complete — %d event(s), %d alert(s) from %s",
            total_events,
            len(alerts),
            path,
        )

        return {
            "synced_at": synced_at,
            "eve_path": path,
            "total_events": total_events,
            "alert_count": len(alerts),
            "alerts": alerts,
        }
