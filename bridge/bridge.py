"""Argus inference bridge — Redis-driven worker that shells out to ``claude -p``.

Ported from gaigenticOS (M13.6). Reuses the operator's installed Claude
Code CLI subscription as the inference backend so dev / demo
deployments don't need an Anthropic API key.

Lifecycle::

    caller (BridgeLLM)                bridge worker (this file)
    ──────────────────                ─────────────────────────
    build task envelope
        │
        rpush ai_tasks  ───────────►  blpop ai_tasks
                                      spawn `claude -p --output-format json`
                                      capture stdout / stderr / rc
                                      rpush ai_results:<task_id>
    blpop ai_results:<id> ◄───────────┘
    parse, return content

Two run shapes, selected by ``start.sh``:

  A. **Host-native** (default on macOS / Apple Silicon).
     ``scripts/bridge_host.sh start`` spawns this script as a python
     process on the operator's host, finds ``claude`` via PATH, and
     dials Redis on localhost. Required because the v2.x Claude CLI is
     a Mach-O arm64 binary that cannot exec inside a Linux container
     even with a bind mount.

  B. **In-container** (Linux host only).
     The compose ``bridge`` profile builds and launches this same
     script in a tiny python image, with ``CLAUDE_CLI_PATH`` pointing
     at a Linux-arch claude binary mounted from the host.

The Redis envelope is identical in both shapes so brain-side callers
(``src/llm/bridge_client.BridgeLLM``) don't know or care which mode is
active.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import signal
from pathlib import Path

import redis.asyncio as redis


log = logging.getLogger("argus.bridge")

READY_MARKER = Path(os.environ.get("BRIDGE_READY_MARKER", "/tmp/argus-bridge.ready"))
TASKS_QUEUE = "ai_tasks"
RESULTS_QUEUE_PREFIX = "ai_results"


def _resolve_claude_cli() -> Path | None:
    """Return a working path to the ``claude`` CLI, or None.

    Priority:
      1. ``CLAUDE_CLI_PATH`` env (explicit override; in-container mode
         mounts the binary at this path).
      2. ``shutil.which('claude')`` — host-native mode finds it on PATH
         (typically ``~/.local/bin/claude`` on macOS / Linux).
    """
    explicit = os.environ.get("CLAUDE_CLI_PATH")
    if explicit:
        p = Path(explicit)
        return p if p.exists() else None
    found = shutil.which("claude")
    return Path(found) if found else None


async def run() -> None:
    redis_host = os.environ.get("ARGUS_REDIS_HOST") or os.environ.get("REDIS_HOST", "127.0.0.1")
    redis_port = int(os.environ.get("ARGUS_REDIS_PORT") or os.environ.get("REDIS_PORT", "6379"))
    redis_password = os.environ.get("ARGUS_REDIS_PASSWORD") or os.environ.get("REDIS_PASSWORD", "")

    log.info(
        "argus-bridge: connecting redis=%s:%s mode=%s",
        redis_host, redis_port, os.environ.get("BRIDGE_MODE", "auto"),
    )
    redis_client = redis.Redis(
        host=redis_host,
        port=redis_port,
        password=redis_password or None,
        decode_responses=False,
    )
    await redis_client.ping()

    claude_path = _resolve_claude_cli()
    if claude_path is None:
        log.warning(
            "argus-bridge: claude CLI not resolvable (neither CLAUDE_CLI_PATH "
            "nor PATH found it) — bridge will idle and return errors per task."
        )
    else:
        log.info("argus-bridge: claude CLI resolved at %s", claude_path)

    try:
        READY_MARKER.touch()
    except OSError:
        # Read-only /tmp on some hosts is fine; readiness via redis ping
        # already succeeded above.
        log.debug("argus-bridge: ready-marker %s unwritable; continuing", READY_MARKER)
    log.info(
        "argus-bridge: ready (tasks=%s results=%s:<task_id> claude=%s)",
        TASKS_QUEUE, RESULTS_QUEUE_PREFIX, claude_path,
    )

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_event.set)

    try:
        while not stop_event.is_set():
            # blpop returns None on timeout; loop again so we honour
            # shutdown signals promptly without leaving a permanent
            # blocking call.
            got = await redis_client.blpop([TASKS_QUEUE], timeout=5)
            if got is None:
                continue
            _queue, payload_bytes = got
            try:
                task = json.loads(payload_bytes)
            except json.JSONDecodeError:
                log.warning("argus-bridge: dropping malformed task: %r", payload_bytes[:200])
                continue
            await _handle_task(task, redis_client, claude_path)
    finally:
        log.info("argus-bridge: shutdown")
        await redis_client.aclose()


async def _handle_task(
    task: dict,
    redis_client: redis.Redis,
    claude_path: Path | None,
) -> None:
    """Run ``claude -p`` once and push the JSON envelope to the per-task
    results queue.

    Expected task shape (built by ``BridgeLLM.call``)::

        {
          "task_id":       "<uuid>",
          "prompt":        "<str>",
          "system":        "<str, optional>",   # appended via --append-system-prompt
          "timeout":       <int seconds, default 120>,
          "results_queue": "<str, optional>",   # default ai_results:<task_id>
        }
    """
    task_id = task.get("task_id", "?")
    prompt = task.get("prompt", "")
    system = task.get("system")
    timeout = int(task.get("timeout", 120))
    results_queue = task.get("results_queue") or f"{RESULTS_QUEUE_PREFIX}:{task_id}"

    async def push_result(payload: dict) -> None:
        await redis_client.rpush(results_queue, json.dumps(payload).encode("utf-8"))

    if claude_path is None or not claude_path.exists():
        await push_result({
            "task_id": task_id,
            "ok": False,
            "error": (
                "argus-bridge: claude CLI not available — install Claude Code "
                "and re-run via './start.sh --reconfigure' (host-native), or "
                "set CLAUDE_CLI_PATH in the container env (Linux)."
            ),
        })
        return

    try:
        args = [str(claude_path), "-p", "--output-format", "json"]
        if system:
            args += ["--append-system-prompt", system]
        args.append(prompt)

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            await push_result({
                "task_id": task_id,
                "ok": False,
                "error": f"timeout after {timeout}s",
            })
            return

        if proc.returncode != 0:
            await push_result({
                "task_id": task_id,
                "ok": False,
                "error": (
                    f"claude exit {proc.returncode}: "
                    f"{stderr_bytes.decode(errors='replace')[:500]}"
                ),
            })
            return

        stdout_str = stdout_bytes.decode()
        # Claude's --output-format json wraps the assistant text in an
        # envelope: {"type": "result", "model": "...", "result": "<text>",
        # "session_id": "...", ...}. Older surfaces used "model_id".
        # Surface the model id alongside the text so callers can record
        # provenance for audit.
        model_id: str | None = None
        result_text: str = stdout_str  # fall back to the full body
        try:
            env = json.loads(stdout_str)
            if isinstance(env, dict):
                model_id = env.get("model") or env.get("model_id") or None
                # Newer envelopes carry the assistant text under "result".
                if isinstance(env.get("result"), str):
                    result_text = env["result"]
        except json.JSONDecodeError:
            pass
        await push_result({
            "task_id": task_id,
            "ok": True,
            "stdout": stdout_str,
            "result": result_text,
            "model": model_id,
        })
    except Exception as exc:  # noqa: BLE001 — worker must never crash
        log.exception("argus-bridge: task %s failed", task_id)
        await push_result({"task_id": task_id, "ok": False, "error": str(exc)})


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
    )
    asyncio.run(run())
