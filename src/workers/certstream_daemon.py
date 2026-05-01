"""CertStream daemon — Audit B3.

Long-running consumer for the public Certificate Transparency WebSocket
feed at ``wss://certstream.calidog.io/``. Streams freshly-issued
certificate domains, buffers them, and every flush window runs the batch
through :func:`src.brand.feed.ingest_candidates` for every active
organization. Matches that exceed the brand-term similarity threshold
land in ``suspect_domains`` exactly the same way the typo-squat scanner
does — single source of truth.

Off by default. Enable per deploy via ``ARGUS_WORKER_CERTSTREAM_ENABLED=1``.
The daemon owns its own reconnect / backoff loop because CT-log feeds
drop frequently; reconnect is silent up to a per-attempt cap then
emits WARNING so an operator notices a wedged feed.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections import deque
from typing import Iterable

from sqlalchemy import select

from src.brand import feed as brand_feed  # lazy resolve so tests can patch
from src.brand.feed import (
    domains_from_certstream_message,
    ingest_candidates,
)
from src.models.brand import BrandTerm, SuspectDomainSource
from src.storage import database as _db


_logger = logging.getLogger("argus.worker.certstream")


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


CERTSTREAM_URL = os.environ.get(
    "ARGUS_WORKER_CERTSTREAM_URL", "wss://certstream.calidog.io/"
)
# Flush whichever fires first — buffer-size keeps memory bounded under
# heavy CT bursts; flush-interval guarantees no domain sits more than N
# seconds before being checked against brand terms.
CERTSTREAM_FLUSH_DOMAINS = _int_env("ARGUS_WORKER_CERTSTREAM_FLUSH_DOMAINS", 500)
CERTSTREAM_FLUSH_SECONDS = _int_env("ARGUS_WORKER_CERTSTREAM_FLUSH_SECONDS", 30)
# Reconnect backoff: 1s, 2s, 4s, … capped at 60s. Resets on a clean
# message-receive so a brief WebSocket hiccup doesn't stall scaling
# back to fast retries when the feed comes back.
CERTSTREAM_BACKOFF_INITIAL = 1.0
CERTSTREAM_BACKOFF_MAX = 60.0


class _DomainBuffer:
    """Bounded deque of domains pending the next flush.

    Bound is hard — once full, oldest entries are dropped silently and a
    counter ticks. CT-log volume can spike to thousands of certs per
    second; we'd rather miss a window than OOM the worker.
    """

    def __init__(self, capacity: int) -> None:
        self._buf: deque[str] = deque(maxlen=capacity)
        self.dropped = 0

    def add_many(self, domains: Iterable[str]) -> None:
        for d in domains:
            if d:
                if len(self._buf) == self._buf.maxlen:
                    self.dropped += 1
                self._buf.append(d.lower())

    def drain(self) -> list[str]:
        out = list(self._buf)
        self._buf.clear()
        return out

    def __len__(self) -> int:
        return len(self._buf)


async def _flush_buffer(buffer: _DomainBuffer) -> None:
    """Run the buffered batch through ingest_candidates for every org.

    Each organization runs in its own session so a single org's failure
    can't poison the rest. The buffer is drained *before* the DB work so
    new messages keep accumulating in parallel.
    """
    if _db.async_session_factory is None:
        return
    batch = buffer.drain()
    if not batch:
        return

    # Only flush against orgs that actually have at least one active
    # brand-term — every other org would just produce IngestReport(0)
    # and the SELECT/COMMIT round-trip is the dominant cost. This keeps
    # the daemon's per-flush DB load proportional to "orgs that care",
    # not "orgs that exist".
    async with _db.async_session_factory() as session:
        org_ids = (
            await session.execute(
                select(BrandTerm.organization_id)
                .where(BrandTerm.is_active == True)  # noqa: E712
                .distinct()
            )
        ).scalars().all()

    if not org_ids:
        return

    total_created = 0
    total_seen = 0
    for org_id in org_ids:
        async with _db.async_session_factory() as session:
            try:
                report = await ingest_candidates(
                    session,
                    org_id,
                    batch,
                    source=SuspectDomainSource.CERTSTREAM,
                )
                await session.commit()
                total_created += report.suspects_created
                total_seen += report.suspects_seen_again
            except Exception:  # noqa: BLE001 — keep the daemon alive
                await session.rollback()
                _logger.exception(
                    "certstream ingest failed for org %s", org_id
                )

    if total_created or total_seen:
        _logger.info(
            "certstream flush: %d candidates, %d new, %d seen-again "
            "across %d org(s)",
            len(batch), total_created, total_seen, len(org_ids),
        )


async def _consume_once(buffer: _DomainBuffer) -> None:
    """Open one WebSocket and forward domains into the buffer.

    Returns when the socket closes; the outer loop reconnects.
    Resolves ``brand_feed.certstream_iter_messages`` at call time so
    tests can monkeypatch the underlying iterator without touching this
    module.
    """
    async for msg in brand_feed.certstream_iter_messages(CERTSTREAM_URL):
        domains = domains_from_certstream_message(msg)
        if domains:
            buffer.add_many(domains)


async def _flusher(buffer: _DomainBuffer, stop: asyncio.Event) -> None:
    """Periodic flush + size-trigger flush.

    Runs in parallel with the WebSocket consumer; both share the buffer.
    """
    while not stop.is_set():
        try:
            await asyncio.wait_for(
                stop.wait(), timeout=CERTSTREAM_FLUSH_SECONDS
            )
        except asyncio.TimeoutError:
            pass
        await _flush_buffer(buffer)
    await _flush_buffer(buffer)


async def _consumer(buffer: _DomainBuffer, stop: asyncio.Event) -> None:
    backoff = CERTSTREAM_BACKOFF_INITIAL
    while not stop.is_set():
        try:
            _logger.info("certstream connecting to %s", CERTSTREAM_URL)
            await _consume_once(buffer)
            backoff = CERTSTREAM_BACKOFF_INITIAL
            if not stop.is_set():
                _logger.warning(
                    "certstream feed closed cleanly — reconnecting"
                )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            _logger.exception("certstream consume failed; backing off")

        try:
            await asyncio.wait_for(stop.wait(), timeout=backoff)
        except asyncio.TimeoutError:
            backoff = min(CERTSTREAM_BACKOFF_MAX, backoff * 2)


async def run(stop: asyncio.Event | None = None) -> None:
    """Run the daemon until ``stop`` is set (or forever).

    Drives a size-bounded buffer plus a flusher task plus a reconnecting
    consumer task. Returns once the stop event fires AND both inner
    tasks settle, which is how the worker-runner-side cancellation
    contract works for the other loops.
    """
    stop = stop or asyncio.Event()
    buffer = _DomainBuffer(capacity=max(CERTSTREAM_FLUSH_DOMAINS * 4, 2000))
    consumer = asyncio.create_task(_consumer(buffer, stop))
    flusher = asyncio.create_task(_flusher(buffer, stop))
    try:
        await stop.wait()
    finally:
        for t in (consumer, flusher):
            t.cancel()
        await asyncio.gather(consumer, flusher, return_exceptions=True)
        if buffer.dropped:
            _logger.warning(
                "certstream daemon shutdown — dropped %d domains during "
                "lifetime of buffer overflow",
                buffer.dropped,
            )


__all__ = ["run"]
