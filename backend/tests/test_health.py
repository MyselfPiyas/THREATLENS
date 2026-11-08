from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from app.core.config import Settings
from app.main import app, handle_unexpected_error, handle_validation_error

client = TestClient(app)


def test_health_returns_api_status() -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["service"] == "threatlens-api"


def test_unversioned_health_route_returns_api_status() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["service"] == "threatlens-api"


def test_health_reports_supabase_configuration_without_exposing_credentials() -> None:
    response = client.get("/api/v1/health")
    payload = response.json()

    assert isinstance(payload["supabase_configured"], bool)
    assert isinstance(payload["scan_persistence_configured"], bool)
    assert "anon_key" not in payload
    assert "service_role" not in response.text


@pytest.mark.parametrize("origin", ["http://localhost:3000", "http://127.0.0.1:3000"])
def test_cors_allows_configured_local_frontend(origin: str) -> None:
    response = client.options(
        "/api/v1/health",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == origin


def test_cors_origins_are_normalized_and_wildcards_are_rejected() -> None:
    settings = Settings(frontend_allowed_origins="http://localhost:3000/,https://EXAMPLE.com")

    assert settings.cors_origins == ["http://localhost:3000", "https://example.com"]
    with pytest.raises(ValidationError):
        Settings(frontend_allowed_origins="*")


def test_validation_errors_do_not_echo_input_values() -> None:
    test_app = FastAPI()
    test_app.add_exception_handler(RequestValidationError, handle_validation_error)

    @test_app.get("/coerce")
    async def coerce(count: int) -> dict[str, int]:
        return {"count": count}

    response = TestClient(test_app).get("/coerce?count=do-not-echo-this")

    assert response.status_code == 422
    assert "do-not-echo-this" not in response.text
    assert "input" not in response.text


def test_unexpected_errors_do_not_expose_exception_details() -> None:
    test_app = FastAPI()
    test_app.add_exception_handler(Exception, handle_unexpected_error)

    @test_app.get("/failure")
    async def failure() -> None:
        raise RuntimeError("do-not-return-this-secret")

    response = TestClient(test_app, raise_server_exceptions=False).get("/failure")

    assert response.status_code == 500
    assert response.json() == {"detail": "An unexpected error occurred."}
    assert "do-not-return-this-secret" not in response.text
    assert "Traceback" not in response.text

