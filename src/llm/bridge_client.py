"""Redis-bridge LLM client (caller side of ``bridge/bridge.py``).

Ported from gaigenticOS ``brain.inference.bridge_llm``. Exposes a single
``call(system, user) -> str`` coroutine that drops a task on the
``ai_tasks`` queue and waits for the worker's reply on
``ai_results:<task_id>`` with a deadline.

Why a Redis RPC instead of a direct HTTP call?

* Reuses the operator's installed Claude Code subscription. No
  Anthropic API key, no per-call billing for dev / demo deploys.
* Decouples the agent layer from the inference backend. The same
  envelope works whether the worker shells out to ``claude``, queues
  to a Gemma vLLM, or a future Llama backend.
* Survives the worker restarting mid-task (the task sits queued).

Usage::

    from src.llm.bridge_client import BridgeLLM
    bridge = BridgeLLM()
    await bridge.connect()
    text = await bridge.call(system="You are a triage analyst.", user="...")
    last_model = bridge.last_model_id  # "claude-sonnet-4-6" etc.
    await bridge.close()

The client is safe to share across coroutines as long as each caller
captures :pyattr:`last_model_id` immediately after awaiting :meth:`call`
(it's a single-writer attribute, not per-task).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Optional

import redis.asyncio as redis

from src.config.settings import settings


log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_S = 240

# Adversarial audit D-21 — hard cap on bridge response size. A
# misbehaving (or compromised) bridge worker could otherwise blast a
# multi-GB JSON envelope into the API process and OOM it. 4 MiB is
# generous for a Claude/Gemma reply (largest expected ≈ 200KB).
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class BridgeError(RuntimeError):
    """Bridge worker reported a non-OK envelope (claude exit, transport, etc)."""


class BridgeNotConnected(RuntimeError):
    """``call`` was invoked before ``connect``."""


class BridgeLLM:
    """One Redis connection per process; ``call`` is concurrent-safe."""

    def __init__(
        self,
        *,
        redis_url: Optional[str] = None,
        timeout_s: int = DEFAULT_TIMEOUT_S,
    ) -> None:
        self._redis_url = redis_url or _build_redis_url()
        self._redis: Optional[redis.Redis] = None
        self._timeout_s = timeout_s
        # Populated by each successful .call() from the worker payload's
        # ``model`` field. Single-writer; downstream code that needs
        # per-call provenance must read this immediately after
        # ``await bridge.call(...)`` and stage it locally.
        self.last_model_id: Optional[str] = None
        # Per-call token usage when the worker emits it. The host
        # ``claude`` CLI's stream-json output carries
        # ``usage.input_tokens`` / ``usage.output_tokens`` which the
        # bridge worker can copy into the response envelope as
        # ``usage_in`` / ``usage_out``. Decay to None when missing so
        # the dashboard distinguishes "not surfaced" from "zero".
        self.last_input_tokens: Optional[int] = None
        self.last_output_tokens: Optional[int] = None

    async def connect(self) -> None:
        # 3s was too tight under load — when the API container's
        # asyncio thread pool is saturated by many concurrent calls
        # (FeedHealth poll, organization lookups, alert stats, etc.),
        # the bridge client's first ``getaddrinfo`` for ``redis`` can
        # take longer than 3s to even reach the resolver, and the
        # socket-connect deadline fires before the connect attempt
        # actually starts. The ping itself is fast once the socket
        # is open. 15s gives plenty of headroom without making a
        # genuinely-down redis appear hung.
        self._redis = redis.from_url(
            self._redis_url,
            decode_responses=True,
            socket_connect_timeout=15,
            socket_timeout=15,
            retry_on_timeout=True,
        )
        # Retry the ping once on initial transient timeout — the next
        # attempt usually succeeds because the resolver cached the
        # name and the executor pool freed up.
        for attempt in range(2):
            try:
                await self._redis.ping()
                break
            except (redis.TimeoutError, asyncio.TimeoutError):
                if attempt == 1:
                    raise
                log.warning(
                    "argus-bridge-llm: redis ping timed out, retrying once"
                )
                await asyncio.sleep(0.5)
        log.info("argus-bridge-llm: redis online (url=%s)", _redact(self._redis_url))

    async def close(self) -> None:
        if self._redis is not None:
            try:
                await self._redis.aclose()
            except Exception:  # noqa: BLE001
                pass
            self._redis = None

    async def call(self, system: str, user: str) -> str:
        """Dispatch one inference request; block until the worker
        answers or our deadline expires.

        Raises :class:`BridgeError` on a worker-reported failure, and
        :class:`asyncio.TimeoutError` when the deadline passes without
        an answer (worker dead, queue starved, claude hung).
        """
        if self._redis is None:
            raise BridgeNotConnected(
                "BridgeLLM not connected — call .connect() first"
            )
        task_id = str(uuid.uuid4())
        results_queue = f"ai_results:{task_id}"
        envelope = {
            "task_id": task_id,
            "prompt": user,
            "system": system,
            "timeout": self._timeout_s,
            "results_queue": results_queue,
        }
        await self._redis.rpush("ai_tasks", json.dumps(envelope))

        # Worker timeout is honoured server-side; we add a small grace
        # so claude stragglers don't race a TimeoutError on the caller.
        # Adversarial audit D-21 — wrap the whole receive loop in
        # ``asyncio.wait_for`` so a slow-read attack on the Redis socket
        # can't extend us past the deadline indefinitely.
        async def _wait_for_result() -> str:
            deadline = time.monotonic() + self._timeout_s + 5
            while time.monotonic() < deadline:
                got = await self._redis.blpop([results_queue], timeout=5)
                if got is None:
                    continue
                _q, raw = got
                if isinstance(raw, str) and len(raw.encode("utf-8", "ignore")) > _MAX_RESPONSE_BYTES:
                    raise BridgeError(
                        f"argus-bridge: response exceeds {_MAX_RESPONSE_BYTES} bytes"
                    )
                if isinstance(raw, (bytes, bytearray)) and len(raw) > _MAX_RESPONSE_BYTES:
                    raise BridgeError(
                        f"argus-bridge: response exceeds {_MAX_RESPONSE_BYTES} bytes"
                    )
                payload = json.loads(raw)
                if not payload.get("ok"):
                    raise BridgeError(
                        f"argus-bridge: {payload.get('error') or 'unknown error'}"
                    )
                self.last_model_id = payload.get("model") or None
                # Token counts — accept either flat ``usage_in/out`` or
                # a nested ``usage: {...}``. The bridge worker decides
                # which shape based on what the host CLI gives it; we
                # tolerate both so a worker upgrade isn't required for
                # the columns to populate.
                _ui = payload.get("usage_in")
                _uo = payload.get("usage_out")
                _u = payload.get("usage") if isinstance(payload.get("usage"), dict) else None
                if _u:
                    _ui = _ui if isinstance(_ui, int) else _u.get("input_tokens")
                    _uo = _uo if isinstance(_uo, int) else _u.get("output_tokens")
                self.last_input_tokens = _ui if isinstance(_ui, int) else None
                self.last_output_tokens = _uo if isinstance(_uo, int) else None
                # Newer claude envelopes carry the assistant text under
                # ``result``; fall back to raw stdout for older ones.
                text = payload.get("result")
                if isinstance(text, str) and text:
                    return text
                stdout = payload.get("stdout") or ""
                if isinstance(stdout, str) and len(stdout.encode("utf-8", "ignore")) > _MAX_RESPONSE_BYTES:
                    raise BridgeError(
                        f"argus-bridge: stdout exceeds {_MAX_RESPONSE_BYTES} bytes"
                    )
                try:
                    env = json.loads(stdout)
                    if isinstance(env, dict) and isinstance(env.get("result"), str):
                        return env["result"]
                except json.JSONDecodeError:
                    pass
                return stdout
            raise asyncio.TimeoutError(
                f"argus-bridge: no result in {self._timeout_s + 5}s "
                f"(task_id={task_id})"
            )

        return await asyncio.wait_for(
            _wait_for_result(), timeout=self._timeout_s + 30
        )


# ---------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------


def _build_redis_url() -> str:
    """Compose ``redis://`` URL from settings.

    Settings already decode the redis password from the env (and the
    /run/secrets/* file convention if used). Falling through to
    ``redis://redis:6379/0`` keeps the in-compose path working without
    extra config.
    """
    host = settings.redis.host
    port = settings.redis.port
    pw = getattr(settings.redis, "password", None) or ""
    auth = f":{pw}@" if pw else ""
    return f"redis://{auth}{host}:{port}/0"


def _redact(url: str) -> str:
    """Redact the password segment of a redis URL for logs."""
    if "@" not in url:
        return url
    head, tail = url.split("@", 1)
    if "//" not in head:
        return url
    scheme, creds = head.split("//", 1)
    if ":" not in creds:
        return url
    user, _ = creds.split(":", 1)
    return f"{scheme}//{user}:***@{tail}"
