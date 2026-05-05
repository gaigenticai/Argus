"""Async LLM agent queue — fire-and-forget Bridge tasks.

Producers call :func:`enqueue` to schedule a Bridge-LLM job. The
worker tick (:func:`process_one`) picks the oldest queued row, runs
the registered handler for its kind, and writes the structured
result back. Idempotent on (kind, dedup_key).

Why not call Bridge inline?
    Inline calls block the API request and can take 30-120s. They
    also make the request fail when Bridge is restarting. By queuing,
    we get retry-with-backoff, observability via /agent-activity, and
    cost-tracking for free.

A handler is::

    async def handle(db, task) -> dict:
        # do work, return structured payload to persist as result
        ...

Register via :func:`register_handler` at module import time. Every
governance agent (evidence summariser, leakage classifier, DMARC
RCA, channel renderer, DSAR responder, etc.) plugs in this way.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.agent_task import AgentTask

_logger = logging.getLogger(__name__)


# ----------------------------------------------------------- Registry

Handler = Callable[[AsyncSession, AgentTask], Awaitable[dict[str, Any]]]
_HANDLERS: dict[str, Handler] = {}


def register_handler(kind: str, fn: Handler) -> None:
    """Bind a handler coroutine to a task kind.

    Calling twice with the same kind overrides — useful for tests.
    Module imports are the canonical place to call this.
    """
    _HANDLERS[kind] = fn


def registered_kinds() -> list[str]:
    return sorted(_HANDLERS.keys())


# ----------------------------------------------------------- Producer


async def enqueue(
    db: AsyncSession,
    *,
    kind: str,
    payload: dict[str, Any],
    organization_id: uuid.UUID | None = None,
    dedup_key: str | None = None,
    priority: int = 5,
    not_before: datetime | None = None,
) -> AgentTask:
    """Idempotently queue an agent task.

    If a row with (kind, dedup_key) already exists, return it without
    creating a duplicate. dedup_key defaults to a stable SHA-256 over
    the payload — pass a custom value when the same payload should be
    re-runnable.
    """
    if kind not in _HANDLERS:
        # Producers can enqueue before the worker module imports the
        # handler — log a soft warning, don't reject. The dispatcher
        # checks the registry again at run time.
        _logger.debug("[agent-queue] enqueue for unregistered kind %s", kind)

    if dedup_key is None:
        h = hashlib.sha256(repr(sorted(payload.items())).encode("utf-8")).hexdigest()[:32]
        dedup_key = f"auto:{h}"

    stmt = (
        pg_insert(AgentTask)
        .values(
            kind=kind,
            organization_id=organization_id,
            dedup_key=dedup_key,
            status="queued",
            priority=priority,
            payload=payload,
            not_before=not_before,
        )
        .on_conflict_do_nothing(
            index_elements=["kind", "dedup_key"]
        )
        .returning(AgentTask)
    )
    result = await db.execute(stmt)
    row = result.scalar_one_or_none()
    if row is not None:
        await db.commit()
        return row
    # Already exists — fetch and return.
    existing = await db.execute(
        select(AgentTask).where(
            AgentTask.kind == kind,
            AgentTask.dedup_key == dedup_key,
        )
    )
    return existing.scalar_one()


# ----------------------------------------------------------- Dispatcher


async def process_one(db: AsyncSession) -> bool:
    """Atomically claim the next queued task and run its handler.

    Returns True if a task was processed, False if the queue is empty.
    Caller should loop while True for a tick batch. We use
    ``SELECT ... FOR UPDATE SKIP LOCKED`` so multiple worker
    processes can drain in parallel without colliding.
    """
    now = datetime.now(timezone.utc)

    claim_stmt = (
        select(AgentTask)
        .where(AgentTask.status == "queued")
        .where((AgentTask.not_before.is_(None)) | (AgentTask.not_before <= now))
        .order_by(AgentTask.priority.asc(), AgentTask.created_at.asc())
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    result = await db.execute(claim_stmt)
    task = result.scalar_one_or_none()
    if task is None:
        await db.commit()
        return False

    handler = _HANDLERS.get(task.kind)
    if handler is None:
        # Mark as error; we don't want to spin on it.
        task.status = "error"
        task.error_message = f"no handler registered for kind={task.kind}"
        task.finished_at = now
        await db.commit()
        return True

    task.status = "running"
    task.started_at = now
    task.attempts = (task.attempts or 0) + 1
    await db.commit()
    await db.refresh(task)

    started = time.perf_counter()
    try:
        out = await asyncio.wait_for(handler(db, task), timeout=240)
        task.result = out or {}
        task.status = "ok"
        task.error_message = None
    except asyncio.TimeoutError:
        task.status = "queued" if task.attempts < task.max_attempts else "dead"
        task.error_message = "handler timeout (>240s)"
        task.not_before = now + timedelta(seconds=60 * task.attempts)
    except Exception as exc:  # noqa: BLE001 — must catch all to keep dispatcher alive
        _logger.exception("[agent-queue] handler %s raised", task.kind)
        task.status = (
            "queued" if task.attempts < task.max_attempts else "dead"
        )
        task.error_message = str(exc)[:8000]
        task.not_before = now + timedelta(seconds=60 * task.attempts)
    finally:
        task.finished_at = datetime.now(timezone.utc)
        task.duration_ms = int((time.perf_counter() - started) * 1000)
        await db.commit()
    return True


# ----------------------------------------------------------- Bridge wrapper


async def call_bridge(system: str, user: str) -> tuple[str, str | None]:
    """Single-shot call into the Bridge LLM. Returns (text, model_id).

    Uses a per-call connection because handler concurrency is low
    (a few jobs/sec at most) and keeping a long-lived bridge
    connection in the worker means the failure modes are harder to
    reason about.
    """
    from src.llm.bridge_client import BridgeLLM

    bridge = BridgeLLM()
    await bridge.connect()
    try:
        text = await bridge.call(system=system, user=user)
        return text, bridge.last_model_id
    finally:
        await bridge.close()


__all__ = [
    "register_handler",
    "registered_kinds",
    "enqueue",
    "process_one",
    "call_bridge",
]
