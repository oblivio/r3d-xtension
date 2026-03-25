"""Provider-routing LLM client.

Routes to OpenAI, Azure OpenAI, or Google Gemini based on the model-string
prefix (``gpt-*`` / ``azure/…`` / ``gemini/…``).  Uses the ``openai`` SDK for
all three — Gemini is reached through its OpenAI-compatible endpoint.
"""

from __future__ import annotations

from openai import AsyncAzureOpenAI, AsyncOpenAI

from core.config import (
    AZURE_API_BASE,
    AZURE_API_KEY,
    AZURE_API_VERSION,
    GEMINI_API_KEY,
    OPENAI_API_KEY,
)

_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"

_clients: dict[str, AsyncOpenAI] = {}


def _get_client(provider: str) -> AsyncOpenAI:
    if provider not in _clients:
        if provider == "azure":
            _clients[provider] = AsyncAzureOpenAI(
                api_key=AZURE_API_KEY,
                azure_endpoint=AZURE_API_BASE,
                api_version=AZURE_API_VERSION,
            )
        elif provider == "gemini":
            _clients[provider] = AsyncOpenAI(
                api_key=GEMINI_API_KEY,
                base_url=_GEMINI_BASE_URL,
            )
        else:
            _clients[provider] = AsyncOpenAI(api_key=OPENAI_API_KEY)
    return _clients[provider]


def _parse_model(model: str) -> tuple[str, str]:
    """Return ``(provider, bare_model)`` from a prefixed model string."""
    if model.startswith("azure/"):
        return "azure", model.removeprefix("azure/")
    if model.startswith("gemini/"):
        return "gemini", model.removeprefix("gemini/")
    return "openai", model


async def acompletion(**kwargs):
    """Drop-in async replacement for ``litellm.acompletion``."""
    model: str = kwargs.pop("model")
    provider, bare_model = _parse_model(model)
    client = _get_client(provider)
    return await client.chat.completions.create(model=bare_model, **kwargs)
