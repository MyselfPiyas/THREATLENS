import anyio
import httpx
import pytest

from app.core.config import Settings
from app.services.llm_service import LLMConfigurationError, LLMProviderError, LLMService


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {"choices": [{"message": {"content": '{"ok": true}'}}]}
        self.is_success = 200 <= status_code < 300

    def json(self) -> dict:
        return self._payload


class FakeClient:
    response = FakeResponse()
    calls: list[dict] = []

    def __init__(self, *args, **kwargs):
        self.calls.append(kwargs)

    async def __aenter__(self): return self
    async def __aexit__(self, *args): return None

    async def post(self, url, headers, json):
        self.calls.append({"url": url, "headers": headers, "json": json})
        return self.response


def settings(**overrides):
    values = {"openrouter_api_key": "test-key", "openrouter_base_url": "https://openrouter.test/api/v1", "openrouter_model": "test-model"}
    values.update(overrides)
    return Settings(**values)


def test_success_uses_configured_openrouter_model_and_headers():
    FakeClient.response = FakeResponse()
    FakeClient.calls = []
    result = anyio.run(LLMService(settings(openrouter_site_url="https://threatlens.test"), client_factory=FakeClient).complete_json, [{"role": "user", "content": "x"}])
    assert result == {"ok": True}
    request = FakeClient.calls[-1]
    assert request["url"].endswith("/chat/completions")
    assert request["json"]["model"] == "test-model"
    assert request["headers"]["HTTP-Referer"] == "https://threatlens.test"
    assert request["headers"]["X-Title"] == "THREATLENS"


def test_missing_key_is_controlled_error():
    with pytest.raises(LLMConfigurationError):
        anyio.run(LLMService(settings(openrouter_api_key=None)).complete_json, [])


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
def test_provider_errors_are_redacted_and_controlled(status):
    FakeClient.response = FakeResponse(status)
    with pytest.raises(LLMProviderError):
        anyio.run(LLMService(settings(), client_factory=FakeClient).complete_json, [])


def test_timeout_is_controlled_error():
    class TimeoutClient(FakeClient):
        async def post(self, *args, **kwargs): raise httpx.ReadTimeout("timeout")
    with pytest.raises(LLMProviderError):
        anyio.run(LLMService(settings(), client_factory=TimeoutClient).complete_json, [])


@pytest.mark.parametrize("payload", [
    {"choices": [{"message": {"content": "not-json"}}]},
    {"choices": []},
    {"unexpected": True},
])
def test_invalid_provider_shape_is_rejected(payload):
    FakeClient.response = FakeResponse(payload=payload)
    with pytest.raises(LLMProviderError):
        anyio.run(LLMService(settings(), client_factory=FakeClient).complete_json, [])
