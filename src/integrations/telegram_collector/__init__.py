"""Telethon-based Telegram collector (P3 #3.10).

Two collectors ship in this codebase:

  src/crawlers/telegram_crawler.py   public-web scraping via t.me/s
                                     (no auth, easy, public channels only)
  src/integrations/telegram_collector THIS MODULE — Telethon / MTProto,
                                     covers private channels and
                                     full-fidelity message metadata
                                     (forwards, replies, edits, photos
                                     with captions, document hashes).

Why both: the public scraper is good enough for hacktivist channels
that broadcast to anonymous viewers. The Telethon collector is needed
for private invite-only channels where Iranian / Arabic threat-actor
groups discuss specific target packages — those channels won't render
at t.me/s/<name> at all.

**Legal review gate** — Telethon authentication is real Telegram-user
authentication. Operating it on production traffic in heavily regulated
markets (KSA, UAE) requires a customer-side legal review. The collector
is therefore **opt-in via two env vars**:

  ARGUS_TELEGRAM_ENABLED=true     operator attests legal review done
  ARGUS_TELEGRAM_API_ID=<int>     Telegram API id (from my.telegram.org)
  ARGUS_TELEGRAM_API_HASH=<str>   Telegram API hash (from my.telegram.org)
  ARGUS_TELEGRAM_SESSION_PATH     filesystem path for session DB
                                  (e.g. /var/lib/argus/telegram.session)

Without all three, ``is_configured()`` returns False and every entry
point no-ops with a clear note.

Public surface:
  is_configured()                     all three env vars present
  list_curated_channels()             curated set of public threat
                                       channels (used as the default
                                       monitor list)
  detect_language(text)               returns "ar" | "fa" | "en" |
                                       "unknown" via Unicode-block
                                       heuristics
  process_message(text, channel)      run IOC extraction + language
                                       detection over a message body;
                                       returns a structured record the
                                       pipeline can persist
  fetch_recent_messages(channels, ...) optional Telethon-backed pull
                                        when properly configured

The pipeline is intentionally split from the Telethon transport so the
language + IOC steps are unit-testable without touching MTProto.
"""

from __future__ import annotations

from .channels import (
    CuratedChannel,
    list_curated_channels,
    list_iranian_channels,
    list_arabic_channels,
    list_hacktivist_channels,
)
from .client import (
    TelegramCollectorResult,
    fetch_recent_messages,
    health_check,
    is_configured,
)
from .language import detect_language
from .pipeline import (
    ProcessedMessage,
    process_message,
    process_messages,
)


__all__ = [
    "CuratedChannel",
    "list_curated_channels",
    "list_iranian_channels",
    "list_arabic_channels",
    "list_hacktivist_channels",
    "TelegramCollectorResult",
    "fetch_recent_messages",
    "health_check",
    "is_configured",
    "detect_language",
    "ProcessedMessage",
    "process_message",
    "process_messages",
]
