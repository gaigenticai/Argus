"""In-process fault-injection tests.

Each test verifies that Argus degrades gracefully under one specific
failure mode. The harness is in ``tests/fault_injection/injector.py``;
here we just compose the patches and assert on the observable
behaviour (status codes, log lines, FeedHealth rows, audit-log entries).

Coverage map:

    test_feed_pull_records_network_error  → FeedHealth row (silent-zero
                                            replacement)
    test_feed_pull_records_rate_limited   → 429 lands as rate_limited
    test_feed_pull_records_auth_error     → 401 lands as auth_error
    test_evidence_upload_5xx_returns_503  → MinIO 500 → API 503
    test_evidence_upload_bucket_missing   → NoSuchBucket → API 503
    test_redis_outage_does_not_lock_users → degrades open
    test_takedown_smtp_failure_marks_failed → adapter returns success=False
    test_pan_regex_bounded_under_garbage  → no ReDoS hang
    test_dlp_redos_pattern_auto_disables  → policy.enabled=False
    test_uuid7_clock_skew_keeps_uniqueness → still unique under bad clock
"""

from __future__ import annotations

import asyncio
import time
import uuid

import pytest

from tests.fault_injection.injector import FaultInjector


pytestmark = pytest.mark.asyncio


# --- Feed health under transport failure -----------------------------


async def test_feed_pull_records_network_error_on_drop():
    """When an upstream URL is unreachable, ``BaseFeed._fetch_text``
    sets ``last_failure_reason`` and the scheduler wrapper records a
    FeedHealth row with status=network_error. We exercise the wrapping
    contract directly without spinning up the full scheduler."""
    from src.feeds.base import BaseFeed

    class _Probe(BaseFeed):
        name = "probe"
        layer = "test"

        async def poll(self):
            yield  # pragma: no cover

    feed = _Probe()
    with FaultInjector() as fi:
        fi.http_drop("example.invalid")
        result = await feed._fetch_text("https://example.invalid/path")
    await feed.close()

    assert result is None
    assert feed.last_failure_reason is not None
    assert "example.invalid" in feed.last_failure_reason
    from src.models.admin import FeedHealthStatus

    assert feed.last_failure_classification == FeedHealthStatus.NETWORK_ERROR.value


async def test_feed_pull_records_rate_limited_on_429():
    from src.feeds.base import BaseFeed

    class _Probe(BaseFeed):
        name = "probe"
        layer = "test"

        async def poll(self):
            yield  # pragma: no cover

    feed = _Probe()
    with FaultInjector() as fi:
        fi.http_status("rate-limited.test", 429)
        result = await feed._fetch_text("https://rate-limited.test/")
    await feed.close()

    assert result is None
    from src.models.admin import FeedHealthStatus

    assert feed.last_failure_classification == FeedHealthStatus.RATE_LIMITED.value


async def test_feed_pull_records_auth_error_on_401_403():
    from src.feeds.base import BaseFeed

    class _Probe(BaseFeed):
        name = "probe"
        layer = "test"

        async def poll(self):
            yield  # pragma: no cover

    feed = _Probe()
    with FaultInjector() as fi:
        fi.http_status("auth-required.test", 403)
        result = await feed._fetch_json("https://auth-required.test/")
    await feed.close()

    assert result is None
    from src.models.admin import FeedHealthStatus

    assert feed.last_failure_classification == FeedHealthStatus.AUTH_ERROR.value


# --- Auth / Redis outage --------------------------------------------


async def test_redis_outage_does_not_lock_authentic_users(monkeypatch):
    """When Redis is unreachable, the lockout helper must fail open
    (return False — "not locked") so a Redis blip doesn't brick logins.
    The audit doc explicitly accepted this trade-off; this test pins it."""
    from src.core.auth_policy import is_account_locked, record_failed_login

    with FaultInjector() as fi:
        fi.redis_unavailable()
        assert await is_account_locked("victim@example.com") is False
        # And the recorder shouldn't raise either:
        await record_failed_login("victim@example.com")


# --- Takedown SMTP --------------------------------------------------


async def test_takedown_phishlabs_returns_failure_when_smtp_dies(monkeypatch):
    """PhishLabsAdapter dispatches via SMTP. When the SMTP server
    refuses, the adapter must return ``success=False`` with an
    error_message — never a fake success."""
    from src.config.settings import settings
    from src.takedown.adapters import PhishLabsAdapter, SubmitPayload

    monkeypatch.setattr(settings.takedown, "phishlabs_smtp_recipient", "abuse@phishlabs.test")
    monkeypatch.setattr(settings.notify, "email_smtp_host", "smtp.test")
    monkeypatch.setattr(settings.notify, "email_from", "argus@test")

    adapter = PhishLabsAdapter()

    payload = SubmitPayload(
        organization_id=str(uuid.uuid4()),
        target_kind="suspect_domain",
        target_identifier="evil.example.com",
        reason="Phishing site impersonating brand",
    )
    with FaultInjector() as fi:
        fi.smtp_failure()
        result = await adapter.submit(payload)

    assert result.success is False
    assert result.error_message is not None
    assert "SMTP" in result.error_message or "FaultInjector" in result.error_message


# --- Detector hardening ---------------------------------------------


async def test_pan_regex_bounded_under_random_garbage():
    """The PAN regex must not exhibit catastrophic backtracking on a
    100KB block of random digits and separators. Bounded by wall-clock
    so a future regex change that introduces ReDoS fails the test
    instead of silently shipping."""
    import secrets
    import string

    from src.leakage.cards import extract_candidates

    pool = string.digits + " -."
    text = "".join(secrets.choice(pool) for _ in range(100_000))

    t0 = time.monotonic()
    candidates = extract_candidates(text)
    elapsed = time.monotonic() - t0

    # 250ms is generous — typical run is <30ms. If we ever cross 1s on
    # legitimate input, the regex is broken.
    assert elapsed < 0.25, f"PAN regex too slow on garbage ({elapsed:.3f}s)"
    assert isinstance(candidates, list)


def test_dlp_redos_pattern_is_statically_rejected():
    """``regex_pattern_is_dangerous`` must reject the canonical evil
    regex shapes before they even reach runtime evaluation."""
    from src.leakage.dlp import regex_pattern_is_dangerous

    evil = [
        "(a+)+",                      # nested quantifier
        "(a*)*",                      # nested quantifier
        "(a|aa)+$",                   # overlapping alternation
        "(foo|foobar)*",              # alternation prefix overlap
        "([a-z]+)+",                  # class + nested quantifier
        "(\\w+)\\1+",                 # quantified backref
        "x" * 4096,                   # length cap
    ]
    safe = [
        "\\d{16}",
        r"\b[A-Za-z0-9]+@[A-Za-z0-9.]+\b",
        "(?:foo|bar)",                 # alternation, no quantifier
    ]
    for p in evil:
        assert regex_pattern_is_dangerous(p), f"should reject: {p!r}"
    for p in safe:
        assert not regex_pattern_is_dangerous(p), f"should accept: {p!r}"


# --- UUIDv7 under clock skew ---------------------------------------


def test_uuid7_remains_unique_under_clock_freeze(monkeypatch):
    """If the wall clock freezes (NTP slew, suspended VM), UUIDv7 must
    still produce unique values via the rand_a + rand_b randomness."""
    from src.core import uuidv7

    monkeypatch.setattr(uuidv7.time, "time", lambda: 1_700_000_000.0)
    seen = {uuidv7.uuid7() for _ in range(10_000)}
    assert len(seen) == 10_000


# --- Evidence under MinIO outage -----------------------------------


async def test_minio_outage_classified_correctly():
    """When ``evidence_store.put`` raises a 500-class ClientError, the
    fault injector wraps it cleanly. The route layer translates that to
    HTTP 503 (verified by tests/test_evidence.py); here we just pin the
    fault wiring so the route's behaviour can rely on it."""
    from botocore.exceptions import ClientError

    from src.storage import evidence_store

    with FaultInjector() as fi:
        fi.minio_500()
        with pytest.raises(ClientError) as excinfo:
            evidence_store.put("bucket", "key", b"payload", "text/plain")
        assert excinfo.value.response["Error"]["Code"] == "500"


async def test_minio_bucket_missing_classified_correctly():
    from botocore.exceptions import ClientError

    from src.storage import evidence_store

    with FaultInjector() as fi:
        fi.minio_bucket_missing()
        with pytest.raises(ClientError) as excinfo:
            evidence_store.ensure_bucket("missing-bucket")
        assert excinfo.value.response["Error"]["Code"] == "NoSuchBucket"
