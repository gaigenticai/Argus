"""Matrix room crawler — monitors public Matrix/Element rooms for threat intelligence.

Matrix is a decentralized encrypted messaging protocol. Threat actors are
migrating from Telegram to Matrix for better operational security. This
crawler uses the Matrix Client-Server API to read public rooms without
authentication.

IMPORTANT: This is designed for DEFENSIVE security monitoring only.
All crawling is passive (read-only). Only public rooms are accessed.
No accounts are created, no messages are sent, no interactions occur.
"""

import logging
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import aiohttp

from src.models.threat import SourceType
from src.core.activity import ActivityType, emit as activity_emit

from .base import BaseCrawler, CrawlResult

logger = logging.getLogger(__name__)


class MatrixCrawler(BaseCrawler):
    """Crawls public Matrix rooms for threat intelligence via the Client-Server API.

    Uses JSON endpoints exclusively — no HTML parsing required.

    Room config format::

        {
            "homeserver_url": "https://matrix.org",
            "room_id": "!abc123:matrix.org",
            "room_alias": "#threats:matrix.org",  # optional, for logging
            "max_messages": 200,                   # per crawl cycle
        }

    Homeserver config for room discovery::

        {
            "homeserver_url": "https://some-homeserver.chat",
            "discover_rooms": true,
            "max_discovered_rooms": 50,
            "room_keyword_filter": ["hack", "leak", "cred", ...],
        }
    """

    name = "matrix_crawler"
    source_type = SourceType.MATRIX

    # Matrix Client-Server API paths
    _API_PUBLIC_ROOMS = "/_matrix/client/v3/publicRooms"
    _API_ROOM_MESSAGES = "/_matrix/client/v3/rooms/{room_id}/messages"
    _API_ROOM_STATE = "/_matrix/client/v3/rooms/{room_id}/state"

    def __init__(
        self,
        room_configs: list[dict] | None = None,
        homeserver_configs: list[dict] | None = None,
        org_keywords: list[str] | None = None,
    ):
        super().__init__()
        self.room_configs = room_configs or []
        self.homeserver_configs = homeserver_configs or []
        self.org_keywords = [kw.lower() for kw in (org_keywords or [])]

    # ------------------------------------------------------------------
    # HTTP helpers (JSON, not HTML — override base _fetch pattern)
    # ------------------------------------------------------------------

    async def _get_json_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session configured for JSON API calls."""
        if self._session is None or self._session.closed:
            from src.config.settings import settings

            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=settings.crawler.timeout),
                headers={
                    "Accept": "application/json",
                    "User-Agent": self._random_ua(),
                },
            )
        return self._session

    async def _fetch_json(
        self,
        url: str,
        params: dict[str, Any] | None = None,
    ) -> dict | None:
        """Fetch a JSON endpoint with retry logic."""
        from src.config.settings import settings

        async with self._semaphore:
            await activity_emit(
                ActivityType.CRAWLER_FETCH,
                self.name,
                f"Fetching {url}",
                {"url": url, "params": params},
            )
            for attempt in range(settings.crawler.max_retries):
                try:
                    session = await self._get_json_session()
                    async with session.get(url, params=params) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        if resp.status == 403:
                            logger.info(
                                f"[{self.name}] Access denied (room may be private): {url}"
                            )
                            return None
                        logger.warning(
                            f"[{self.name}] {url} returned {resp.status} "
                            f"(attempt {attempt + 1})"
                        )
                except Exception as e:
                    logger.error(
                        f"[{self.name}] Error fetching {url}: {e} "
                        f"(attempt {attempt + 1})"
                    )
                    await activity_emit(
                        ActivityType.CRAWLER_ERROR,
                        self.name,
                        f"JSON fetch error: {e}",
                        {"url": url, "attempt": attempt + 1},
                        severity="warning",
                    )

                if attempt < settings.crawler.max_retries - 1:
                    await self._delay()

            return None

    # ------------------------------------------------------------------
    # Main crawl loop
    # ------------------------------------------------------------------

    async def crawl(self) -> AsyncIterator[CrawlResult]:
        # Phase 1: Discover rooms from homeserver directories
        discovered_rooms = await self._discover_rooms()

        # Combine configured rooms + discovered rooms (deduplicate by room_id)
        all_rooms = list(self.room_configs)
        seen_ids = {cfg["room_id"] for cfg in all_rooms if "room_id" in cfg}

        for room in discovered_rooms:
            if room["room_id"] not in seen_ids:
                all_rooms.append(room)
                seen_ids.add(room["room_id"])

        await activity_emit(
            ActivityType.CRAWLER_START,
            self.name,
            f"Starting Matrix crawl — {len(all_rooms)} rooms",
            {"configured": len(self.room_configs), "discovered": len(discovered_rooms)},
        )

        # Phase 2: Crawl each room
        for room_config in all_rooms:
            room_id = room_config.get("room_id", "unknown")
            room_label = room_config.get("room_alias") or room_id
            try:
                async for result in self._crawl_room(room_config):
                    yield result
            except Exception as e:
                logger.error(f"[{self.name}] Failed to crawl room {room_label}: {e}")
                await activity_emit(
                    ActivityType.CRAWLER_ERROR,
                    self.name,
                    f"Room crawl failed: {room_label} — {e}",
                    {"room_id": room_id},
                    severity="error",
                )

        await activity_emit(
            ActivityType.CRAWLER_COMPLETE,
            self.name,
            f"Matrix crawl complete — processed {len(all_rooms)} rooms",
            {"total_rooms": len(all_rooms)},
        )

    # ------------------------------------------------------------------
    # Room discovery
    # ------------------------------------------------------------------

    async def _discover_rooms(self) -> list[dict]:
        """Discover public rooms on configured homeservers."""
        discovered: list[dict] = []

        for hs_config in self.homeserver_configs:
            if not hs_config.get("discover_rooms", False):
                continue

            homeserver = hs_config["homeserver_url"].rstrip("/")
            max_rooms = hs_config.get("max_discovered_rooms", 50)
            keyword_filter = [
                kw.lower() for kw in hs_config.get("room_keyword_filter", [])
            ]

            url = f"{homeserver}{self._API_PUBLIC_ROOMS}"
            params: dict[str, Any] = {"limit": min(max_rooms, 100)}

            rooms_found = 0
            since_token: str | None = None

            while rooms_found < max_rooms:
                if since_token:
                    params["since"] = since_token

                data = await self._fetch_json(url, params=params)
                if not data:
                    break

                chunks = data.get("chunk", [])
                if not chunks:
                    break

                for room in chunks:
                    room_id = room.get("room_id", "")
                    room_name = room.get("name", "")
                    room_topic = room.get("topic", "")
                    room_alias = room.get("canonical_alias", "")
                    combined = f"{room_name} {room_topic} {room_alias}".lower()

                    # Apply keyword filter if configured
                    if keyword_filter and not any(kw in combined for kw in keyword_filter):
                        continue

                    discovered.append({
                        "homeserver_url": homeserver,
                        "room_id": room_id,
                        "room_alias": room_alias or room_name,
                        "max_messages": hs_config.get("max_messages", 200),
                        "_discovered_name": room_name,
                        "_discovered_topic": room_topic,
                        "_member_count": room.get("num_joined_members", 0),
                    })
                    rooms_found += 1
                    if rooms_found >= max_rooms:
                        break

                # Pagination
                since_token = data.get("next_batch")
                if not since_token:
                    break
                await self._delay()

            logger.info(
                f"[{self.name}] Discovered {rooms_found} rooms on {homeserver}"
            )

        return discovered

    # ------------------------------------------------------------------
    # Single room crawl
    # ------------------------------------------------------------------

    async def _crawl_room(self, room_config: dict) -> AsyncIterator[CrawlResult]:
        """Crawl messages from a single Matrix room using pagination."""
        homeserver = room_config["homeserver_url"].rstrip("/")
        room_id = room_config["room_id"]
        room_label = room_config.get("room_alias") or room_id
        max_messages = room_config.get("max_messages", 200)

        url = homeserver + self._API_ROOM_MESSAGES.format(room_id=room_id)
        params: dict[str, Any] = {
            "dir": "b",  # backwards from most recent
            "limit": min(max_messages, 100),
        }

        messages_processed = 0
        from_token: str | None = None

        while messages_processed < max_messages:
            if from_token:
                params["from"] = from_token

            data = await self._fetch_json(url, params=params)
            if not data:
                break

            events = data.get("chunk", [])
            if not events:
                break

            for event in events:
                result = self._parse_message_event(event, room_config)
                if result:
                    messages_processed += 1
                    await activity_emit(
                        ActivityType.CRAWLER_RESULT,
                        self.name,
                        f"Message in {room_label} from {result.author or 'unknown'}",
                        {"room": room_label, "sender": result.author},
                    )
                    yield result

                if messages_processed >= max_messages:
                    break

            # Pagination — Matrix uses 'end' token for backwards pagination
            from_token = data.get("end")
            if not from_token:
                break
            await self._delay()

        logger.info(
            f"[{self.name}] Processed {messages_processed} messages from {room_label}"
        )

    # ------------------------------------------------------------------
    # Message parsing
    # ------------------------------------------------------------------

    def _parse_message_event(
        self, event: dict, room_config: dict,
    ) -> CrawlResult | None:
        """Parse a single Matrix event into a CrawlResult.

        Only processes m.room.message events.
        """
        if event.get("type") != "m.room.message":
            return None

        content = event.get("content", {})
        msg_type = content.get("msgtype", "")
        body = content.get("body", "")

        if not body or len(body.strip()) < 10:
            return None

        sender = event.get("sender", "")
        origin_ts = event.get("origin_server_ts")
        event_id = event.get("event_id", "")

        # Parse timestamp (Matrix uses milliseconds since epoch)
        published_at = None
        if origin_ts:
            try:
                published_at = datetime.fromtimestamp(
                    origin_ts / 1000.0, tz=timezone.utc,
                )
            except (ValueError, TypeError, OSError):
                pass

        room_label = room_config.get("room_alias") or room_config.get("room_id", "")
        homeserver = room_config.get("homeserver_url", "")

        # Detect file attachments (record URL, do not download)
        attachment_url: str | None = None
        if msg_type in ("m.file", "m.image", "m.video", "m.audio"):
            mxc_url = content.get("url", "")
            if mxc_url.startswith("mxc://"):
                # Convert mxc:// to downloadable URL for reference
                mxc_parts = mxc_url[6:].split("/", 1)
                if len(mxc_parts) == 2:
                    attachment_url = (
                        f"{homeserver}/_matrix/media/v3/download/"
                        f"{mxc_parts[0]}/{mxc_parts[1]}"
                    )

        # Keyword matching
        keyword_hits = self._match_keywords(body)

        raw_data: dict[str, Any] = {
            "room_id": room_config.get("room_id", ""),
            "room_alias": room_label,
            "homeserver": homeserver,
            "event_id": event_id,
            "msg_type": msg_type,
            "sender": sender,
        }
        if attachment_url:
            raw_data["attachment_url"] = attachment_url
        if keyword_hits:
            raw_data["keyword_hits"] = keyword_hits
        if room_config.get("_discovered_name"):
            raw_data["room_name"] = room_config["_discovered_name"]
        if room_config.get("_discovered_topic"):
            raw_data["room_topic"] = room_config["_discovered_topic"]
        if room_config.get("_member_count"):
            raw_data["member_count"] = room_config["_member_count"]

        # Build title from room + message type
        if msg_type in ("m.file", "m.image", "m.video", "m.audio"):
            title = f"[{room_label}] File shared: {content.get('body', 'attachment')}"
        else:
            # Use first 80 chars of body as title
            title = f"[{room_label}] {body[:80]}{'...' if len(body) > 80 else ''}"

        return CrawlResult(
            source_type=self.source_type,
            source_url=f"{homeserver}/#/room/{room_config.get('room_id', '')}",
            source_name=f"matrix:{room_label}",
            title=title,
            content=body,
            author=sender,
            published_at=published_at or datetime.now(timezone.utc),
            raw_data=raw_data,
        )

    # ------------------------------------------------------------------
    # Keyword matching
    # ------------------------------------------------------------------

    def _match_keywords(self, text: str) -> list[str]:
        """Return org keywords found in the text."""
        if not self.org_keywords:
            return []
        lower = text.lower()
        return [kw for kw in self.org_keywords if kw in lower]
