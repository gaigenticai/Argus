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
                if "choices" in data and data["choices"]:
                    return data["choices"][0]["message"]["content"]
                if (
                    "data" in data
                    and isinstance(data["data"], dict)
                    and data["data"].get("choices")
                ):
                    return data["data"]["choices"][0]["message"]["content"]
                raise LLMTransportError(
                    f"OpenAI-compatible response missing choices: keys={list(data.keys())}"
                )


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
            cls._singleton = BridgeLLM(timeout_s=self._timeout_s)
            await cls._singleton.connect()
        try:
            return await cls._singleton.call(system_prompt, user_prompt)
        except BridgeError as e:
            raise LLMTransportError(str(e)) from e


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
