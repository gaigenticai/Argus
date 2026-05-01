"""Telegram collector (P3 #3.10) — unit + HTTP-route tests.

The Telethon transport is opt-in and authenticates as a real Telegram
user, so the unit tests cover the configurability gate + pure-compute
pipeline (language detection, IOC extraction, categorisation, curated
channel catalog) without ever touching MTProto.

The Telethon-backed ``fetch_recent_messages`` path is exercised with a
hand-rolled fake module installed via ``sys.modules`` so we never
import the real ``telethon`` (it isn't in requirements.txt anyway).
"""

from __future__ import annotations

import sys
import types
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.integrations.telegram_collector import (
    detect_language,
    is_configured,
    list_arabic_channels,
    list_curated_channels,
    list_hacktivist_channels,
    list_iranian_channels,
    process_message,
    process_messages,
)
from src.integrations.telegram_collector import client as client_module
from src.integrations.telegram_collector.channels import CuratedChannel

pytestmark = pytest.mark.asyncio


# ── Curated channel catalog ─────────────────────────────────────────


def test_curated_channels_have_required_fields():
    channels = list_curated_channels()
    assert len(channels) >= 8
    seen_handles: set[str] = set()
    for c in channels:
        assert isinstance(c, CuratedChannel)
        assert c.handle and not c.handle.startswith("@")
        assert c.cluster in {
            "iranian-apt", "arabic-hacktivist",
            "ransomware-leak", "carding", "leaks",
        }
        assert c.language in {"fa", "ar", "en", "mixed"}
        assert c.status in {"active", "defunct", "private"}
        assert c.handle not in seen_handles, f"duplicate handle {c.handle}"
        seen_handles.add(c.handle)


def test_iranian_and_arabic_lists_partition_clusters():
    iranian = list_iranian_channels()
    arabic = list_arabic_channels()
    assert all(c.cluster == "iranian-apt" for c in iranian)
    assert all(c.cluster.startswith("arabic-") or c.cluster in
               {"carding", "leaks"} for c in arabic)
    assert {c.handle for c in iranian} & {c.handle for c in arabic} == set()


def test_hacktivist_list_combines_iranian_and_arabic_clusters():
    out = list_hacktivist_channels()
    assert out, "expected non-empty hacktivist list"
    assert all(
        c.cluster in {"iranian-apt", "arabic-hacktivist"} for c in out
    )


def test_curated_channel_to_dict_round_trip():
    c = list_curated_channels()[0]
    d = c.to_dict()
    assert d["handle"] == c.handle
    assert "rationale" in d
    assert isinstance(d["region_focus"], list)


# ── Language detection ──────────────────────────────────────────────


def test_detect_language_arabic():
    text = "السلام عليكم نحن مجموعة قراصنة عرب نهاجم اليوم"
    assert detect_language(text) == "ar"


def test_detect_language_persian_distinguishing_letter_wins():
    text = "سلام دوستان ما گروه هکر هستیم پایگاه اطلاعاتی"
    assert detect_language(text) == "fa"


def test_detect_language_english_default():
    assert detect_language("hello there this is an english message") == "en"


def test_detect_language_unknown_for_blank_input():
    assert detect_language("") == "unknown"
    assert detect_language("   \n\t") == "unknown"


def test_detect_language_short_arabic_substring_does_not_flip_english():
    """Two Arabic letters in an otherwise English message shouldn't
    flip the verdict — that's a quote, not the message language."""
    text = "We saw one channel say 'مرحبا' but the rest was in English"
    assert detect_language(text) == "en"


# ── Pipeline: language + IOC + categorisation ───────────────────────


def test_process_message_extracts_iocs():
    text = "leaked DB at 1.2.3.4 also see http://evil.example.com/dump"
    pm = process_message(text, channel="@arab_breach_archive",
                          message_id=123)
    assert pm.channel == "@arab_breach_archive"
    assert pm.message_id == 123
    assert pm.language == "en"
    assert any(i["type"] == "ipv4" and i["value"] == "1.2.3.4"
                for i in pm.iocs)
    assert any(i["type"] == "url" for i in pm.iocs)
    assert "leak" in pm.categories


def test_process_message_categorises_hacktivism():
    text = "DDoS attack — site is down for 3 hours, owned by us"
    pm = process_message(text, channel="@anonghost_official")
    assert "hacktivism" in pm.categories


def test_process_message_categorises_arabic_carding():
    text = "بيع بطاقة ائتمان CC fullz GCC bins fresh today"
    pm = process_message(text, channel="@arab_carding_lounge")
    assert "carding" in pm.categories


def test_process_message_flags_victim_callout():
    text = "Today we leaked from victim corp acme-bank.example"
    pm = process_message(text, channel="@test")
    assert pm.has_victim_callout is True


def test_process_message_no_victim_callout():
    pm = process_message("just chatting about the weather",
                          channel="@test")
    assert pm.has_victim_callout is False


def test_process_message_to_dict_drops_raw():
    pm = process_message("hello", channel="@test",
                          raw={"secret": "do not leak"})
    d = pm.to_dict()
    assert "raw" not in d
    assert d["channel"] == "@test"


def test_process_messages_batch():
    out = process_messages([
        {"text": "hi 1.2.3.4", "channel": "@a", "message_id": 1},
        {"text": "السلام عليكم", "channel": "@b", "message_id": 2},
        "not-a-dict-skipped",  # type: ignore[list-item]
    ])
    assert len(out) == 2
    assert out[0].language == "en"
    assert out[1].language == "ar"


# ── Configurability gate ────────────────────────────────────────────


def test_is_configured_requires_legal_acknowledgment(monkeypatch):
    """Three env vars present but ARGUS_TELEGRAM_ENABLED unset must
    leave the collector disabled — the legal-review gate is mandatory."""
    monkeypatch.delenv("ARGUS_TELEGRAM_ENABLED", raising=False)
    monkeypatch.setenv("ARGUS_TELEGRAM_API_ID", "12345")
    monkeypatch.setenv("ARGUS_TELEGRAM_API_HASH", "deadbeef")
    monkeypatch.setenv("ARGUS_TELEGRAM_SESSION_PATH", "/tmp/x.session")
    assert is_configured() is False


def test_is_configured_requires_all_credentials(monkeypatch):
    monkeypatch.setenv("ARGUS_TELEGRAM_ENABLED", "true")
    for k in ("ARGUS_TELEGRAM_API_ID", "ARGUS_TELEGRAM_API_HASH",
              "ARGUS_TELEGRAM_SESSION_PATH"):
        monkeypatch.delenv(k, raising=False)
    assert is_configured() is False


def test_is_configured_rejects_non_integer_api_id(monkeypatch):
    monkeypatch.setenv("ARGUS_TELEGRAM_ENABLED", "true")
    monkeypatch.setenv("ARGUS_TELEGRAM_API_ID", "abc-not-int")
    monkeypatch.setenv("ARGUS_TELEGRAM_API_HASH", "deadbeef")
    monkeypatch.setenv("ARGUS_TELEGRAM_SESSION_PATH", "/tmp/x.session")
    assert is_configured() is False


def test_is_configured_happy_path(monkeypatch):
    monkeypatch.setenv("ARGUS_TELEGRAM_ENABLED", "true")
    monkeypatch.setenv("ARGUS_TELEGRAM_API_ID", "12345")
    monkeypatch.setenv("ARGUS_TELEGRAM_API_HASH", "deadbeef")
    monkeypatch.setenv("ARGUS_TELEGRAM_SESSION_PATH", "/tmp/x.session")
    assert is_configured() is True


# ── Telethon transport (opt-in) ─────────────────────────────────────


async def test_fetch_recent_messages_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_TELEGRAM_ENABLED", raising=False)
    r = await client_module.fetch_recent_messages(["@anyone"])
    assert r.success is False
    assert "ARGUS_TELEGRAM_ENABLED" in (r.note or "")


async def test_fetch_recent_messages_telethon_missing(monkeypatch):
    """When config is set but telethon isn't installed (the default in
    requirements.txt — opt-in pip), we surface a clear error and don't
    silently skip the run."""
    monkeypatch.setenv("ARGUS_TELEGRAM_ENABLED", "true")
    monkeypatch.setenv("ARGUS_TELEGRAM_API_ID", "12345")
    monkeypatch.setenv("ARGUS_TELEGRAM_API_HASH", "deadbeef")
    monkeypatch.setenv("ARGUS_TELEGRAM_SESSION_PATH", "/tmp/x.session")
    # Force the import to fail.
    monkeypatch.setitem(sys.modules, "telethon", None)
    r = await client_module.fetch_recent_messages(["@whoever"])
    assert r.success is False
    assert "telethon not installed" in (r.error or "")


async def test_fetch_recent_messages_with_fake_telethon(monkeypatch):
    """Inject a hand-rolled telethon module so the fetch path runs end
    to end without needing the real package. Verifies the message-shape
    serialiser the pipeline downstream consumes."""
    monkeypatch.setenv("ARGUS_TELEGRAM_ENABLED", "true")
    monkeypatch.setenv("ARGUS_TELEGRAM_API_ID", "12345")
    monkeypatch.setenv("ARGUS_TELEGRAM_API_HASH", "deadbeef")
    monkeypatch.setenv("ARGUS_TELEGRAM_SESSION_PATH", "/tmp/x.session")

    class _FakeMsg:
        def __init__(self, mid, text):
            self.id = mid
            self.message = text
            self.sender_id = 9999
            self.fwd_from = None
            self.media = None
            self.reply_to = None
            from datetime import datetime, timezone
            self.date = datetime(2026, 5, 1, 8, tzinfo=timezone.utc)

    class _FakeClient:
        def __init__(self, *a, **kw):
            self._msgs = {
                "@cyberav3ngers": [
                    _FakeMsg(1, "Owned victim corp at 1.2.3.4"),
                    _FakeMsg(2, "Persian text: سلام دوستان"),
                ],
            }

        async def connect(self):
            return None

        async def is_user_authorized(self):
            return True

        def iter_messages(self, handle, *, limit, min_id):
            msgs = self._msgs.get(handle, [])

            class _AsyncIter:
                def __init__(self, msgs):
                    self._iter = iter(msgs)

                def __aiter__(self):
                    return self

                async def __anext__(self):
                    try:
                        return next(self._iter)
                    except StopIteration:
                        raise StopAsyncIteration

            return _AsyncIter(msgs)

        async def disconnect(self):
            return None

    fake_telethon = types.ModuleType("telethon")
    fake_telethon.TelegramClient = _FakeClient
    fake_errors = types.ModuleType("telethon.errors")
    fake_errors.ChannelPrivateError = type("ChannelPrivateError", (Exception,), {})
    fake_errors.FloodWaitError = type(
        "FloodWaitError", (Exception,),
        {"__init__": lambda self, msg="", *, seconds=0:
            (Exception.__init__(self, msg), setattr(self, "seconds", seconds))}
    )
    fake_errors.UsernameInvalidError = type(
        "UsernameInvalidError", (Exception,), {})
    fake_errors.UsernameNotOccupiedError = type(
        "UsernameNotOccupiedError", (Exception,), {})
    monkeypatch.setitem(sys.modules, "telethon", fake_telethon)
    monkeypatch.setitem(sys.modules, "telethon.errors", fake_errors)

    r = await client_module.fetch_recent_messages(
        ["@cyberav3ngers"], limit_per_channel=10,
    )
    assert r.success is True
    assert len(r.messages) == 2
    assert r.messages[0]["channel"] == "@cyberav3ngers"
    assert r.messages[0]["text"].startswith("Owned")
    assert r.messages[0]["posted_at"].startswith("2026-05-01")


async def test_health_check_unconfigured(monkeypatch):
    monkeypatch.delenv("ARGUS_TELEGRAM_ENABLED", raising=False)
    r = await client_module.health_check()
    assert r.success is False


# ── HTTP routes ─────────────────────────────────────────────────────


async def test_route_availability(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/telegram/availability",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    body = r.json()
    assert body["curated_total"] >= 8
    assert isinstance(body["configured"], bool)


async def test_route_channels_returns_curated_catalog(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/telegram/channels",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    chs = r.json()["channels"]
    assert any(c["cluster"] == "iranian-apt" for c in chs)
    assert any(c["cluster"] == "arabic-hacktivist" for c in chs)


async def test_route_channels_filter_by_cluster(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/telegram/channels?cluster=iranian-apt",
        headers=analyst_user["headers"],
    )
    assert r.status_code == 200
    chs = r.json()["channels"]
    assert chs and all(c["cluster"] == "iranian-apt" for c in chs)


async def test_route_analyze_extracts_iocs(client, analyst_user):
    r = await client.post(
        "/api/v1/intel/telegram/analyze",
        headers=analyst_user["headers"],
        json={"text": "Leak from victim corp 1.2.3.4 evil.com",
              "channel": "@arab_breach_archive"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["language"] == "en"
    assert any(i["type"] == "ipv4" for i in body["iocs"])
    assert "leak" in body["categories"]
    assert body["has_victim_callout"] is True


async def test_route_fetch_requires_admin(client, analyst_user):
    """Telegram fetch issues a real MTProto auth — analysts can't trigger
    it."""
    r = await client.post(
        "/api/v1/intel/telegram/fetch",
        headers=analyst_user["headers"],
        json={"channels": ["@whatever"]},
    )
    assert r.status_code in (401, 403)


async def test_route_health_requires_admin(client, analyst_user):
    r = await client.get(
        "/api/v1/intel/telegram/health",
        headers=analyst_user["headers"],
    )
    assert r.status_code in (401, 403)


async def test_route_requires_auth(client):
    r = await client.get("/api/v1/intel/telegram/availability")
    assert r.status_code in (401, 403)
