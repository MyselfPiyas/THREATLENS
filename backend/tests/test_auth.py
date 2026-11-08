import asyncio
from uuid import UUID

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.core.config import Settings
from app.services import auth as auth_service
from app.services import ownership as ownership_service
from app.services.auth import AuthenticatedPrincipal


USER_ID = UUID("28499fd4-a8a2-4f82-b9b5-27cfb29df4cb")
SCAN_ID = UUID("bc02b6aa-f06e-4fc0-9907-a09155abceaf")


class FakeResponse:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> object:
        return self._payload


class FakeAsyncClient:
    response: FakeResponse
    last_request: tuple[str, dict[str, str], dict[str, str]] | None = None

    def __init__(self, **_: object) -> None:
        pass

    async def __aenter__(self) -> "FakeAsyncClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str],
        params: dict[str, str] | None = None,
    ) -> FakeResponse:
        self.last_request = (url, headers, params or {})
        return self.response


def configured_settings() -> Settings:
    return Settings(
        supabase_url="https://threatlens-test.supabase.co",
        supabase_publishable_key="sb_publishable_test",
    )


def test_supabase_url_allows_https_and_loopback_but_rejects_remote_http() -> None:
    assert Settings(supabase_url="https://threatlens-test.supabase.co").supabase_url == "https://threatlens-test.supabase.co"
    assert Settings(supabase_url="http://127.0.0.1:54321").supabase_url == "http://127.0.0.1:54321"
    with pytest.raises(ValidationError):
        Settings(supabase_url="http://untrusted.example")


def test_auth_me_requires_a_bearer_token() -> None:
    from fastapi.testclient import TestClient

    from app.main import app

    response = TestClient(app).get("/api/v1/auth/me")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_auth_me_does_not_echo_token_when_supabase_is_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fastapi.testclient import TestClient

    from app.main import app

    monkeypatch.setattr(auth_service, "get_settings", lambda: Settings(_env_file=None))

    response = TestClient(app).get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer do-not-echo-this-token"},
    )

    assert response.status_code == 503
    assert "do-not-echo-this-token" not in response.text


def test_backend_admin_key_is_separate_from_the_publishable_key() -> None:
    settings = Settings(
        supabase_url="https://threatlens-test.supabase.co",
        supabase_publishable_key="sb_publishable_test",
        supabase_secret_key="sb_secret_test",
    )

    assert settings.supabase_key_value == "sb_publishable_test"
    assert settings.supabase_admin_key_value == "sb_secret_test"
    assert "sb_secret_test" not in repr(settings)


def test_resolve_access_token_checks_supabase_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client = FakeAsyncClient()
    fake_client.response = FakeResponse(200, {"id": str(USER_ID), "email": "analyst@example.com"})
    monkeypatch.setattr(auth_service.httpx, "AsyncClient", lambda **kwargs: fake_client)

    principal = asyncio.run(auth_service.resolve_access_token("user-access-token", configured_settings()))

    assert principal.user_id == USER_ID
    assert principal.email == "analyst@example.com"
    assert principal.access_token == "user-access-token"
    assert fake_client.last_request == (
        "https://threatlens-test.supabase.co/auth/v1/user",
        {"apikey": "sb_publishable_test", "Authorization": "Bearer user-access-token"},
        {},
    )
    assert "user-access-token" not in repr(principal)


def test_resolve_access_token_rejects_invalid_user_token(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client = FakeAsyncClient()
    fake_client.response = FakeResponse(401, {"message": "invalid"})
    monkeypatch.setattr(auth_service.httpx, "AsyncClient", lambda **kwargs: fake_client)

    with pytest.raises(HTTPException) as error:
        asyncio.run(auth_service.resolve_access_token("expired-token", configured_settings()))

    assert error.value.status_code == 401


def test_scan_owner_check_uses_user_jwt_and_rls(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client = FakeAsyncClient()
    fake_client.response = FakeResponse(200, [{"id": str(SCAN_ID)}])
    monkeypatch.setattr(ownership_service.httpx, "AsyncClient", lambda **kwargs: fake_client)
    principal = AuthenticatedPrincipal(USER_ID, "analyst@example.com", "user-access-token")

    result = asyncio.run(
        ownership_service.ensure_scan_owner(SCAN_ID, principal, configured_settings())
    )

    assert result == SCAN_ID
    assert fake_client.last_request == (
        "https://threatlens-test.supabase.co/rest/v1/scans",
        {"apikey": "sb_publishable_test", "Authorization": "Bearer user-access-token"},
        {"id": f"eq.{SCAN_ID}", "user_id": f"eq.{USER_ID}", "select": "id", "limit": "1"},
    )


def test_scan_owner_check_hides_scans_owned_by_other_users(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client = FakeAsyncClient()
    fake_client.response = FakeResponse(200, [])
    monkeypatch.setattr(ownership_service.httpx, "AsyncClient", lambda **kwargs: fake_client)
    principal = AuthenticatedPrincipal(USER_ID, "analyst@example.com", "user-access-token")

    with pytest.raises(HTTPException) as error:
        asyncio.run(
            ownership_service.ensure_scan_owner(SCAN_ID, principal, configured_settings())
        )

    assert error.value.status_code == 404
