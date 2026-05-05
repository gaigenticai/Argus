"""Telegram channel crawler — monitors public threat intel channels.

Uses Telegram's public channel web preview (no API key needed for public channels).
For private channels, a Telegram API key + session would be needed.
"""

from __future__ import annotations


import json
import logging
import re
from datetime import datetime, timezone
from typing import AsyncIterator

from bs4 import BeautifulSoup

from src.models.threat import SourceType
from .base import BaseCrawler, CrawlResult

logger = logging.getLogger(__name__)


class TelegramCrawler(BaseCrawler):
    """Monitors public Telegram channels for threat intelligence.

    Many threat actors, leak channels, and security researchers
    post on public Telegram channels that can be scraped via
    the t.me web preview without needing a Telegram API key.
    """

    name = "telegram_channel"
    source_type = SourceType.TELEGRAM

    TELEGRAM_WEB = "https://t.me/s"  # public channel web view

    def __init__(self, channels: list[str] | None = None):
        super().__init__()
        # Default channels are public security/threat intel channels
        self.channels = channels or []

    async def crawl(self) -> AsyncIterator[CrawlResult]:
        for channel in self.channels:
            try:
                async for result in self._crawl_channel(channel):
                    yield result
            except Exception as e:
                logger.error(f"[{self.name}] Failed to crawl @{channel}: {e}")
            await self._delay()

    async def _crawl_channel(self, channel: str) -> AsyncIterator[CrawlResult]:
        url = f"{self.TELEGRAM_WEB}/{channel}"
        html = await self._fetch(url)
        if not html:
            return

        soup = BeautifulSoup(html, "html.parser")

        # Telegram web preview uses specific class names
        messages = soup.select("div.tgme_widget_message_wrap")

        # When a channel disables its public preview, gets banned, or
        # is age-restricted, t.me/s/<handle> 302s to t.me/<handle> —
        # the (followed) redirect target is the join page, which has
        # no message wraps. Without this check the crawler emits 0
        # results silently. Distinguishing "no preview" from "no
        # messages" lets the operator prune dead handles from their
        # monitor list instead of staring at an empty Telegram pane.
        if not messages:
            join_marker = soup.select_one("a.tgme_action_button_new") or soup.select_one(
                "div.tgme_page_action"
            )
            if join_marker:
                logger.warning(
                    "[%s] channel @%s: t.me/s/ redirected to join page — "
                    "preview disabled, channel may be private/defunct/restricted",
                    self.name, channel,
                )
            else:
                logger.info(
                    "[%s] channel @%s: 0 messages in preview (channel may be "
                    "empty or recently created)",
                    self.name, channel,
                )
            return

        for msg in messages:
            text_el = msg.select_one("div.tgme_widget_message_text")
            if not text_el:
                continue

            content = text_el.get_text(strip=True)
            if not content or len(content) < 20:
                continue

            # Extract message link
            msg_link_el = msg.select_one("a.tgme_widget_message_date")
            msg_url = msg_link_el["href"] if msg_link_el and msg_link_el.get("href") else url

            # Extract timestamp
            time_el = msg.select_one("time")
            published_at = None
            if time_el and time_el.get("datetime"):
                raw_ts = time_el["datetime"]
                try:
                    published_at = datetime.fromisoformat(
                        raw_ts.replace("Z", "+00:00")
                    )
                except ValueError as ts_exc:
                    logger.debug(
                        "telegram.parse: bad message timestamp %r: %s",
                        raw_ts, ts_exc,
                    )

            # Extract author (forwarded from)
            author = channel
            fwd_el = msg.select_one("a.tgme_widget_message_forwarded_from_name")
            if fwd_el:
                author = fwd_el.get_text(strip=True)

            yield CrawlResult(
                source_type=self.source_type,
                source_url=msg_url,
                source_name=f"telegram/@{channel}",
                title=content[:100] + "..." if len(content) > 100 else content,
                content=content,
                author=author,
                published_at=published_at,
                raw_data={
                    "channel": channel,
                    "message_url": msg_url,
                    "has_media": bool(msg.select_one("div.tgme_widget_message_photo")),
                },
            )
