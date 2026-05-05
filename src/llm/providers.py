"""LLM provider backends — Ollama, OpenAI-compatible, Anthropic, Redis-bridge.

Every provider implements ``BaseLLMProvider.call(system_prompt, user_prompt) -> str``
and raises either ``LLMNotConfigured`` or ``LLMTransportError`` on failure.

Use ``get_provider(settings.llm)`` to get the configured provider; it performs
the ``is_configured`` guard and raises ``LLMNotConfigured`` early so callers
don't have to duplicate that check.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions (canonical home — triage_agent re-exports for backward compat)
# ---------------------------------------------------------------------------


class LLMNotConfigured(RuntimeError):
    """LLM provider lacks the credentials needed to dispatch a request."""


class LLMTransportError(RuntimeError):
    """LLM provider returned a non-success HTTP code or malformed body."""


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class BaseLLMProvider(ABC):
    """Common base for every LLM transport.

    Subclasses must implement ``call`` and SHOULD populate
    ``last_input_tokens`` / ``last_output_tokens`` from the response
    body when the upstream API exposes them. ``last_model_id`` is the
    canonical name the provider used (sometimes a router rewrites the
    requested model — e.g. the bridge maps to whichever Claude CLI
    profile is active). Callers that want per-call accounting read
    these attributes immediately after ``await provider.call(...)``.
    None means the provider didn't surface a value for that field.
    """

    last_input_tokens: int | None = None
    last_output_tokens: int | None = None
    last_model_id: str | None = None

    @abstractmethod
    async def call(self, system_prompt: str, user_prompt: str) -> str:
        """Send a two-turn conversation and return the assistant's text."""


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------


class OllamaProvider(BaseLLMProvider):
    def __init__(self, base_url: str, model: str, timeout_s: float) -> None:
        self._base_url = base_url
        self._model = model
        self._timeout_s = timeout_s

    async def call(self, system_prompt: str, user_prompt: str) -> str:
        import aiohttp

        timeout = aiohttp.ClientTimeout(total=self._timeout_s)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                f"{self._base_url.rstrip('/')}/api/chat",
                json={
                    "model": self._model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "stream": False,
                    "format": "json",
                },
            ) as resp:
                if resp.status >= 400:
                    body = (await resp.text())[:500]
                    raise LLMTransportError(f"Ollama HTTP {resp.status}: {body}")
                data = await resp.json()
                if "message" not in data or "content" not in data["message"]:
                    raise LLMTransportError(
                        f"Ollama response missing message.content: keys={list(data.keys())}"
                    )
                # Ollama exposes counts as ``prompt_eval_count`` (in)
                # and ``eval_count`` (out) on /api/chat. Older versions
                # may omit them — decay to None so the dashboard shows
                # "—" rather than zero.
                self.last_input_tokens = (
                    data.get("prompt_eval_count")
                    if isinstance(data.get("prompt_eval_count"), int)
                    else None
                )
                self.last_output_tokens = (
                    data.get("eval_count")
                    if isinstance(data.get("eval_count"), int)
                    else None
                )
                self.last_model_id = data.get("model") or self._model
                return data["message"]["content"]


# ---------------------------------------------------------------------------
# OpenAI-compatible (OpenAI, Azure OpenAI, vLLM, etc.)
# ---------------------------------------------------------------------------


class OpenAIProvider(BaseLLMProvider):
    def __init__(
        self, base_url: str, api_key: str, model: str, timeout_s: float
    ) -> None:
        self._base_url = base_url
        self._api_key = api_key
        self._model = model
        self._timeout_s = timeout_s

    async def call(self, system_prompt: str, user_prompt: str) -> str:
        import aiohttp

        base = self._base_url.rstrip("/")
        if base.endswith("/v4") or base.endswith("/v1"):
            url = f"{base}/chat/completions"
        else:
            url = f"{base}/v1/chat/completions"

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        timeout = aiohttp.ClientTimeout(total=self._timeout_s)
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.post(
                url,
                json={
                    "model": self._model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "response_format": {"type": "json_object"},
                },
            ) as resp:
                if resp.status >= 400:
                    body = (await resp.text())[:500]
                    raise LLMTransportError(
                        f"OpenAI-compatible HTTP {resp.status}: {body}"
                    )
                data = await resp.json()
                # Some routers wrap the OpenAI body in ``{"data": {...}}``
                # — peel both shapes consistently before reading content
                # and usage so token counting works whichever the
                # upstream returns.
                payload = data
                if (
                    "choices" not in data
                    and "data" in data
                    and isinstance(data["data"], dict)
                    and data["data"].get("choices")
                ):
                    payload = data["data"]
                if "choices" not in payload or not payload["choices"]:
                    raise LLMTransportError(
                        f"OpenAI-compatible response missing choices: keys={list(data.keys())}"
                    )
                # OpenAI returns ``usage: {prompt_tokens, completion_tokens, total_tokens}``.
                # Map onto the same Anthropic-style names the rest of
                # Argus uses so the agent code stays provider-agnostic.
                usage = payload.get("usage") or {}
                self.last_input_tokens = (
                    usage.get("prompt_tokens")
                    if isinstance(usage.get("prompt_tokens"), int)
                    else None
                )
                self.last_output_tokens = (
                    usage.get("completion_tokens")
                    if isinstance(usage.get("completion_tokens"), int)
                    else None
                )
                self.last_model_id = payload.get("model") or self._model
                return payload["choices"][0]["message"]["content"]


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------


class AnthropicProvider(BaseLLMProvider):
    def __init__(
        self, base_url: str, api_key: str, model: str, timeout_s: float
    ) -> None:
        self._base_url = base_url
        self._api_key = api_key
        self._model = model
        self._timeout_s = timeout_s

    async def call(self, system_prompt: str, user_prompt: str) -> str:
        import aiohttp

        headers = {
            "x-api-key": self._api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        timeout = aiohttp.ClientTimeout(total=self._timeout_s)
        url = self._base_url.rstrip("/")
        if not url.endswith("/v1/messages"):
            url = url + "/v1/messages" if not url.endswith("/v1") else url + "/messages"
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.post(
                url,
                json={
                    "model": self._model,
                    "max_tokens": 1024,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_prompt}],
                },
            ) as resp:
                if resp.status >= 400:
                    body = (await resp.text())[:500]
                    raise LLMTransportError(
                        f"Anthropic HTTP {resp.status}: {body}"
                    )
                data = await resp.json()
                if not data.get("content"):
                    raise LLMTransportError(
                        f"Anthropic response missing content: keys={list(data.keys())}"
                    )
                # Anthropic returns ``usage: {input_tokens, output_tokens}``
                # on every Messages API response. Stash for the caller —
                # missing fields decay to None rather than 0 so the
                # dashboard can distinguish "not surfaced" from "zero".
                usage = data.get("usage") or {}
                self.last_input_tokens = (
                    usage.get("input_tokens") if isinstance(usage.get("input_tokens"), int) else None
                )
                self.last_output_tokens = (
                    usage.get("output_tokens") if isinstance(usage.get("output_tokens"), int) else None
                )
                self.last_model_id = data.get("model") or self._model
                return data["content"][0]["text"]


# ---------------------------------------------------------------------------
# Bridge (Redis → host claude CLI)
# ---------------------------------------------------------------------------


class BridgeProvider(BaseLLMProvider):
    """Dispatches to the Redis-bridge worker that wraps the host's ``claude`` CLI.

    ``_singleton`` is a class-level ``BridgeLLM`` instance shared across all
    agents in this worker process — connection is established lazily on first
    call and reused thereafter. External code that needs to read
    ``last_model_id`` should access ``BridgeProvider._singleton`` directly.
    """

    _singleton = None  # BridgeLLM | None

    def __init__(self, timeout_s: float) -> None:
        self._timeout_s = timeout_s

    async def call(self, system_prompt: str, user_prompt: str) -> str:
        from src.llm.bridge_client import BridgeError, BridgeLLM

        cls = type(self)
        if cls._singleton is None:
            singleton = BridgeLLM(timeout_s=self._timeout_s)
            try:
                await singleton.connect()
            except Exception:
                # Don't poison the class slot with a half-initialised
                # singleton — a transient redis-unreachable on first
                # call would otherwise sticky-fail every subsequent
                # call without going through connect() again.
                cls._singleton = None
                raise
            cls._singleton = singleton
        try:
            text = await cls._singleton.call(system_prompt, user_prompt)
        except BridgeError as e:
            raise LLMTransportError(str(e)) from e
        # Mirror the singleton's per-call provenance onto the provider
        # instance so the agent can read it through the same interface
        # as Anthropic/OpenAI/Ollama. Bridge worker may not always
        # surface tokens — None is the honest answer when missing.
        self.last_model_id = cls._singleton.last_model_id
        self.last_input_tokens = cls._singleton.last_input_tokens
        self.last_output_tokens = cls._singleton.last_output_tokens
        return text


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def get_provider(llm_settings) -> BaseLLMProvider:
    """Return the correct ``BaseLLMProvider`` for the current configuration.

    Raises ``LLMNotConfigured`` when ``llm_settings.is_configured`` is False
    or the provider name is unrecognised. Call this once per LLM dispatch;
    it is cheap — no I/O.
    """
    if not llm_settings.is_configured:
        provider = llm_settings.provider
        needs_key = provider in ("openai", "anthropic")
        raise LLMNotConfigured(
            f"LLM provider {provider!r} requires base_url"
            + (" and api_key" if needs_key else "")
            + " to be set; agents will not dispatch without credentials."
        )

    provider = llm_settings.provider
    model = llm_settings.model
    base_url = llm_settings.base_url
    api_key = llm_settings.api_key or ""
    timeout_s = llm_settings.request_timeout_seconds

    if provider == "ollama":
        return OllamaProvider(base_url=base_url, model=model, timeout_s=timeout_s)
    if provider == "openai":
        return OpenAIProvider(
            base_url=base_url, api_key=api_key, model=model, timeout_s=timeout_s
        )
    if provider == "anthropic":
        return AnthropicProvider(
            base_url=base_url, api_key=api_key, model=model, timeout_s=timeout_s
        )
    if provider == "bridge":
        return BridgeProvider(timeout_s=timeout_s)

    raise LLMNotConfigured(f"Unknown LLM provider: {provider!r}")
