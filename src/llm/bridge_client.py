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

DEFAULT_TIMEOUT_S = 120

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

    async def connect(self) -> None:
        self._redis = redis.from_url(
            self._redis_url,
            decode_responses=True,
            socket_connect_timeout=3,
        )
        await self._redis.ping()
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
