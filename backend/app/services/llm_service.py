"""Centralized, backend-only OpenRouter integration.

OpenRouter exposes an OpenAI-compatible chat-completions API. This module owns
provider HTTP calls, retry policy, response extraction, and error redaction so
features never implement their own provider integrations.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from app.core.config import Settings, get_settings


class LLMServiceError(RuntimeError):
    """A safe, user-facing provider failure without secrets or raw payloads."""


class LLMConfigurationError(LLMServiceError):
    pass


class LLMProviderError(LLMServiceError):
    pass


class LLMService:
    def __init__(self, settings: Settings | None = None, client_factory: Any = httpx.AsyncClient) -> None:
        self.settings = settings or get_settings()
        self.client_factory = client_factory

    @property
    def endpoint(self) -> str:
        return f"{self.settings.openrouter_base_url.rstrip('/')}/chat/completions"

    def _headers(self) -> dict[str, str]:
        key = self.settings.openrouter_api_key
        if not key or not key.get_secret_value().strip():
            raise LLMConfigurationError("AI analysis is not configured. Deterministic analysis remains available.")
        headers = {
            "Authorization": f"Bearer {key.get_secret_value()}",
            "Content-Type": "application/json",
        }
        if self.settings.openrouter_site_url:
            headers["HTTP-Referer"] = self.settings.openrouter_site_url
        if self.settings.openrouter_app_name:
            headers["X-Title"] = self.settings.openrouter_app_name
        return headers

    async def complete_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        if not self.settings.openrouter_model:
            raise LLMConfigurationError("No OpenRouter model is configured. Deterministic analysis remains available.")
        payload = {
            "model": self.settings.openrouter_model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": messages,
        }
        headers = self._headers()
        last_error: Exception | None = None
        for attempt in range(2):
            try:
                async with self.client_factory(timeout=self.settings.llm_request_timeout_seconds, follow_redirects=False) as client:
                    response = await client.post(self.endpoint, headers=headers, json=payload)
                if response.status_code == 429:
                    last_error = LLMProviderError("The OpenRouter rate limit was reached. Try again shortly.")
                    if attempt == 0:
                        continue
                    raise last_error
                if response.status_code in {400, 401, 403, 404}:
                    raise LLMProviderError("The configured OpenRouter model or credentials are unavailable.")
                if response.status_code >= 500:
                    last_error = LLMProviderError("The OpenRouter provider is temporarily unavailable.")
                    if attempt == 0:
                        continue
                    raise last_error
                if not response.is_success:
                    raise LLMProviderError("The OpenRouter request failed.")
                try:
                    outer = response.json()
                    content = outer["choices"][0]["message"]["content"]
                    parsed = json.loads(content) if isinstance(content, str) else content
                except (ValueError, KeyError, IndexError, TypeError) as error:
                    raise LLMProviderError("OpenRouter returned an invalid structured response.") from error
                if not isinstance(parsed, dict):
                    raise LLMProviderError("OpenRouter returned an invalid structured response.")
                return parsed
            except LLMProviderError:
                raise
            except (httpx.TimeoutException, httpx.NetworkError, httpx.ProtocolError) as error:
                last_error = LLMProviderError("OpenRouter could not be reached. Deterministic analysis remains available.")
                if attempt == 1:
                    raise last_error from error
        raise last_error or LLMProviderError("OpenRouter analysis failed.")


async def complete_json(messages: list[dict[str, str]], settings: Settings | None = None) -> dict[str, Any]:
    return await LLMService(settings).complete_json(messages)
