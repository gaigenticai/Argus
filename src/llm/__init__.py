"""LLM client adapters used by the agent layer.

Public surface:

    from src.llm import get_provider, LLMNotConfigured, LLMTransportError
    from src.llm.providers import BridgeProvider   # for last_model_id access
"""

from src.llm.providers import (  # noqa: F401
    LLMNotConfigured,
    LLMTransportError,
    get_provider,
)
