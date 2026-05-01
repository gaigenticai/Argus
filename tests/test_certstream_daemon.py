"""Audit B3 — CertStream daemon smoke test.

The daemon's job is three things:

1. Pull domain payloads from a CertStream WebSocket iterator.
2. Buffer them with bounded size.
3. Periodically flush the buffer through ``ingest_candidates`` for
   every org that has active brand terms.

We exercise (1)+(2) and (3) separately so a slow CI database doesn't
make the orchestration test flaky. (3) is the production-critical
path; (1)+(2) is mostly bookkeeping.
"""

from __future__ import annotations

from typing import AsyncIterator

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from src.models.brand import (
    BrandTerm,
    BrandTermKind,
    SuspectDomain,
    SuspectDomainSource,
)
from src.workers import certstream_daemon

pytestmark = pytest.mark.asyncio


def _ct_message(*domains: str) -> dict:
    return {
        "message_type": "certificate_update",
        "data": {"leaf_cert": {"all_domains": list(domains)}},
    }


async def _seed_brand_term(test_engine, organization_id, value: str) -> None:
    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        s.add(
            BrandTerm(
                organization_id=organization_id,
                kind=BrandTermKind.APEX_DOMAIN.value,
                value=value.lower(),
                keywords=[],
                is_active=True,
            )
        )
        await s.commit()


async def test_certstream_buffer_drops_oldest_when_full():
    """Bounded deque must drop the oldest entries when capacity is hit
    and tick the dropped counter — overflow under heavy CT bursts is
    expected behaviour, not a bug."""
    buf = certstream_daemon._DomainBuffer(capacity=3)
    buf.add_many(["a.com", "b.com", "c.com", "d.com", "e.com"])
    assert len(buf) == 3
    assert buf.dropped == 2
    drained = buf.drain()
    assert drained == ["c.com", "d.com", "e.com"]
    assert len(buf) == 0


async def test_certstream_extracts_domains_from_messages():
    """Compose the iterator + buffer + parse step *without* the DB
    flush. Pure-Python check that fake messages → buffer correctly."""
    payloads = [
        _ct_message("ignored.com"),                 # certificate_update
        {"message_type": "heartbeat"},              # not a CT update
        _ct_message("a.example", "b.example"),
    ]

    buf = certstream_daemon._DomainBuffer(capacity=100)

    for msg in payloads:
        domains = certstream_daemon.domains_from_certstream_message(msg)
        if domains:
            buf.add_many(domains)

    drained = buf.drain()
    assert drained == ["ignored.com", "a.example", "b.example"]


async def test_certstream_flush_persists_matches(test_engine, organization):
    """End-to-end flush — direct call into ``_flush_buffer`` with a
    pre-loaded buffer. Bypasses the consumer + timer so the test is
    deterministic regardless of how many other orgs exist in the
    shared test DB.

    This is the production-critical path: domains in → matches out
    via the brand-term filter → suspect_domain rows tagged
    ``source=certstream``.
    """
    org_id = organization["id"]
    await _seed_brand_term(test_engine, org_id, "argus.com")

    buf = certstream_daemon._DomainBuffer(capacity=100)
    buf.add_many(
        [
            "argus.com",                # exact, ignored
            "arguss.com",               # typosquat → match
            "totally-unrelated.io",     # no match
            "argus-secure-login.io",    # name-style match
        ]
    )

    await certstream_daemon._flush_buffer(buf)

    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as s:
        rows = (
            await s.execute(
                select(SuspectDomain).where(
                    SuspectDomain.organization_id == org_id,
                    SuspectDomain.source == SuspectDomainSource.CERTSTREAM.value,
                )
            )
        ).scalars().all()

    domains = {r.domain for r in rows}
    assert "arguss.com" in domains, (
        f"expected typosquat 'arguss.com' to land; got {domains}"
    )
    assert "totally-unrelated.io" not in domains


async def test_certstream_consumer_drains_iterator(monkeypatch):
    """The consumer task should pull every message from the iterator
    into the buffer before the iterator is exhausted."""
    payloads = [
        _ct_message("foo.example"),
        _ct_message("bar.example", "baz.example"),
    ]

    async def fake_iter(*_args, **_kwargs) -> AsyncIterator[dict]:
        for p in payloads:
            yield p

    from src.brand import feed as brand_feed
    monkeypatch.setattr(brand_feed, "certstream_iter_messages", fake_iter)

    buf = certstream_daemon._DomainBuffer(capacity=100)
    await certstream_daemon._consume_once(buf)

    drained = buf.drain()
    assert set(drained) == {"foo.example", "bar.example", "baz.example"}
