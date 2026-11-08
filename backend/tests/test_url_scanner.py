import asyncio

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.core.config import Settings
from app.schemas.scans import UrlScanRequest
from app.scanners import url_validation
from app.scanners.url_validation import UnsafeTarget, normalize_url
from app.scanners import url_scanner
from app.services.scan_store import ScanStore


def run_without_io(coroutine):
    """Drive test coroutines whose mocked awaits complete synchronously."""
    while True:
        try:
            yielded = coroutine.send(None)
        except StopIteration as result:
            return result.value
        if yielded is not None:
            raise AssertionError("The mocked test coroutine unexpectedly yielded an async I/O operation.")


@pytest.mark.parametrize(
    "value",
    [
        "javascript:alert(1)",
        "ftp://example.com/file",
        "http://127.0.0.1/",
        "http://10.1.2.3/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0/",
        "http://192.0.2.1/",
        "http://224.0.0.1/",
        "http://240.0.0.1/",
        "http://255.255.255.255/",
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
        "http://[ff02::1]/",
        "http://[2001:db8::1]/",
        "http://user:pass@example.com/",
        "https://example.com/?access_token=private",
        "https://example.com/?client_secret=private",
        "https://localhost/",
        "http://example.com:8080/",
    ],
)
def test_normalize_rejects_unsafe_urls(value: str) -> None:
    with pytest.raises(UnsafeTarget):
        normalize_url(value)


def test_normalize_canonicalizes_scheme_hostname_and_unicode_path() -> None:
    assert normalize_url("HTTPS://Example.COM/café") == "https://example.com/caf%C3%A9"


@pytest.mark.parametrize("value", ["", "example.com", "https://", "https://example.com/" + "a" * 2050])
def test_normalize_rejects_empty_protocolless_malformed_and_oversized_urls(value: str) -> None:
    with pytest.raises(UnsafeTarget):
        normalize_url(value)


def test_dns_answer_set_rejects_public_and_private_mixture(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeLoop:
        async def getaddrinfo(self, host: str, port: None, *, type: int):
            return [
                (0, 1, 6, "", ("93.184.216.34", 0)),
                (0, 1, 6, "", ("10.0.0.4", 0)),
            ]

    async def immediate_wait_for(awaitable, timeout: float):
        return await awaitable

    monkeypatch.setattr(url_validation.asyncio, "get_running_loop", lambda: FakeLoop())
    monkeypatch.setattr(url_validation.asyncio, "wait_for", immediate_wait_for)
    with pytest.raises(UnsafeTarget):
        run_without_io(url_validation.resolve_public_addresses("example.com"))


def test_http_connection_uses_the_validated_ip_and_original_tls_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    connection: dict[str, object] = {}

    class FakeLoop:
        def time(self) -> float:
            return 0.0

    class FakeReader:
        lines = [b"HTTP/1.1 200 OK\r\n", b"Content-Type: text/html\r\n", b"\r\n"]

        async def readline(self) -> bytes:
            return self.lines.pop(0)

    class FakeWriter:
        request = b""

        def write(self, request: bytes) -> None:
            self.request = request

        async def drain(self) -> None:
            return None

        def close(self) -> None:
            return None

        async def wait_closed(self) -> None:
            return None

    async def open_connection(address: str, port: int, **kwargs):
        connection.update(address=address, port=port, **kwargs)
        writer = FakeWriter()
        connection["writer"] = writer
        return FakeReader(), writer

    async def immediate_wait_for(awaitable, timeout: float):
        return await awaitable

    monkeypatch.setattr(url_scanner.asyncio, "get_running_loop", lambda: FakeLoop())
    monkeypatch.setattr(url_scanner.asyncio, "open_connection", open_connection)
    monkeypatch.setattr(url_scanner.asyncio, "wait_for", immediate_wait_for)

    status, headers = run_without_io(url_scanner._request_response_headers(
        "https://example.com/path", ["93.184.216.34"], configured_settings()
    ))

    assert status == 200
    assert headers["content-type"] == "text/html"
    assert connection["address"] == "93.184.216.34"
    assert connection["address"] != "example.com"
    assert connection["server_hostname"] == "example.com"
    assert b"Host: example.com\r\n" in connection["writer"].request


def test_url_request_rejects_extra_fields_and_unsafe_destination() -> None:
    with pytest.raises(ValidationError):
        UrlScanRequest(url="http://192.168.0.1", extra="unexpected")
    with pytest.raises(ValidationError):
        UrlScanRequest(url="http://192.168.0.1")


def configured_settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)


def run_scan(monkeypatch: pytest.MonkeyPatch, url: str, *, indicator: dict | None = None, settings: Settings | None = None):
    async def public_addresses(host: str, timeout: float | None = None) -> list[str]:
        return ["93.184.216.34"]

    async def response_headers(url: str, addresses: list[str], settings: Settings) -> tuple[int, dict[str, str]]:
        assert addresses == ["93.184.216.34"]
        return 200, {"content-type": "text/html", "content-length": "256"}

    async def reputation(url: str, hostname: str, settings: Settings | None) -> dict | None:
        return indicator

    monkeypatch.setattr(url_scanner, "resolve_public_addresses", public_addresses)
    monkeypatch.setattr(url_scanner, "_request_response_headers", response_headers)
    events: list[tuple[str, str, dict]] = []

    async def event_sink(kind: str, title: str, description: str, data: dict) -> None:
        events.append((kind, title, data))

    outcome = run_without_io(url_scanner.inspect_url(
        url, event_sink=event_sink, settings=settings or configured_settings(), reputation_lookup=reputation
    ))
    return outcome, events


def test_weak_url_patterns_never_confirm_malicious(monkeypatch: pytest.MonkeyPatch) -> None:
    outcome, events = run_scan(monkeypatch, "http://xn--signin-example.com/login")

    assert outcome.risk_level in {"SUSPICIOUS", "HIGH_RISK"}
    assert outcome.risk_level != "CONFIRMED_MALICIOUS"
    assert outcome.findings
    event_types = [event[0] for event in events]
    assert event_types.index("dns_inspected") < event_types.index("redirect_chain_inspected")
    assert event_types.index("redirect_chain_inspected") < event_types.index("reputation_queried")
    assert event_types[-1] == "risk_classified"


def test_https_scan_records_tls_handshake_without_claiming_certificate_details(monkeypatch: pytest.MonkeyPatch) -> None:
    _, events = run_scan(monkeypatch, "https://example.com")
    tls_event = next(event for event in events if event[0] == "tls_inspected")

    assert tls_event[2] == {
        "host": "example.com",
        "handshake": "completed",
        "certificate_details_collected": False,
    }


def test_http_scan_does_not_report_tls_inspection(monkeypatch: pytest.MonkeyPatch) -> None:
    _, events = run_scan(monkeypatch, "http://example.com")
    assert all(event[0] != "tls_inspected" for event in events)


def test_only_high_confidence_exact_trusted_match_confirms(monkeypatch: pytest.MonkeyPatch) -> None:
    outcome, _ = run_scan(monkeypatch, "https://example.com", indicator={
        "indicator_type": "domain", "source": "openphish", "threat_category": "phishing",
        "confidence": 0.97, "first_seen": None, "last_seen": None,
    })

    assert outcome.risk_level == "CONFIRMED_MALICIOUS"
    assert outcome.findings[0].source == "openphish"


def test_threat_feed_matches_must_be_exact_and_from_an_allowlisted_source(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        status_code = 200
        def json(self):
            return [{
                "indicator_type": "domain", "indicator_value": "example.com", "source": "untrusted-feed",
                "threat_category": "phishing", "confidence": 0.99,
            }]

    class Client:
        def __init__(self, **kwargs):
            self.params = []
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def get(self, url: str, *, headers: dict, params: dict):
            self.params.append(params)
            return Response()

    monkeypatch.setattr(url_scanner.httpx, "AsyncClient", Client)
    result = run_without_io(url_scanner.lookup_trusted_indicator(
        "https://example.com/", "example.com",
        configured_settings(supabase_url="https://project.supabase.co", supabase_secret_key="backend-secret"),
    ))
    assert result is None


def test_reputation_failure_is_inconclusive_not_a_negative_match(monkeypatch: pytest.MonkeyPatch) -> None:
    async def public_addresses(host: str, timeout: float | None = None) -> list[str]:
        return ["93.184.216.34"]

    async def response_headers(url: str, addresses: list[str], settings: Settings) -> tuple[int, dict[str, str]]:
        return 200, {"content-type": "text/html"}

    async def unavailable(url: str, hostname: str, settings: Settings | None) -> None:
        raise url_scanner.ReputationLookupUnavailable("test provider unavailable")

    monkeypatch.setattr(url_scanner, "resolve_public_addresses", public_addresses)
    monkeypatch.setattr(url_scanner, "_request_response_headers", response_headers)
    events = []

    async def event_sink(kind: str, title: str, description: str, data: dict) -> None:
        events.append((kind, description, data))

    outcome = run_without_io(url_scanner.inspect_url(
        "https://example.com", event_sink=event_sink,
        settings=configured_settings(), reputation_lookup=unavailable,
    ))
    reputation_event = next(event for event in events if event[0] == "reputation_queried")

    assert outcome.risk_level == "INCONCLUSIVE"
    assert reputation_event[2]["lookup_complete"] is False
    assert reputation_event[2]["match_found"] is None


def test_scoring_weights_are_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    outcome, _ = run_scan(
        monkeypatch, "http://signin.demo-site.net/login",
        settings=configured_settings(url_scan_weight_http=45),
    )

    assert outcome.risk_score == 55
    assert outcome.risk_level == "SUSPICIOUS"


def test_unsafe_redirect_is_blocked_before_following(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    async def public_addresses(host: str, timeout: float | None = None) -> list[str]:
        return ["93.184.216.34"]

    async def redirect_response(url: str, addresses: list[str], settings: Settings) -> tuple[int, dict[str, str]]:
        nonlocal calls
        calls += 1
        return 302, {"location": "http://127.0.0.1/admin"}

    monkeypatch.setattr(url_scanner, "resolve_public_addresses", public_addresses)
    monkeypatch.setattr(url_scanner, "_request_response_headers", redirect_response)

    async def no_reputation(url: str, hostname: str, settings: Settings | None) -> None:
        return None

    async def event_sink(*args: object) -> None:
        return None

    outcome = run_without_io(url_scanner.inspect_url(
        "https://example.com", event_sink=event_sink,
        settings=configured_settings(), reputation_lookup=no_reputation,
    ))

    assert calls == 1
    assert outcome.risk_level == "HIGH_RISK"
    assert any(finding.title == "Unsafe redirect destination blocked" for finding in outcome.findings)


def test_redirect_loop_is_reported_and_stopped_before_repeating_request(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    async def public_addresses(host: str, timeout: float | None = None) -> list[str]:
        return ["93.184.216.34"]

    async def redirect_response(url: str, addresses: list[str], settings: Settings) -> tuple[int, dict[str, str]]:
        calls.append(url)
        if url.endswith("/start"):
            return 302, {"location": "/next"}
        return 302, {"location": "/start"}

    async def no_reputation(url: str, hostname: str, settings: Settings | None) -> None:
        return None

    events: list[str] = []

    async def event_sink(kind: str, title: str, description: str, data: dict) -> None:
        events.append(kind)

    monkeypatch.setattr(url_scanner, "resolve_public_addresses", public_addresses)
    monkeypatch.setattr(url_scanner, "_request_response_headers", redirect_response)
    outcome = run_without_io(url_scanner.inspect_url(
        "https://example.com/start", event_sink=event_sink,
        settings=configured_settings(), reputation_lookup=no_reputation,
    ))

    assert len(calls) == 2
    assert events.count("redirect_loop_detected") == 1
    assert any(finding.title == "Redirect loop detected" for finding in outcome.findings)


def test_http_timeout_is_recorded_as_incomplete_and_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    async def public_addresses(host: str, timeout: float | None = None) -> list[str]:
        return ["93.184.216.34"]

    async def timed_out(url: str, addresses: list[str], settings: Settings) -> tuple[int, dict[str, str]]:
        raise asyncio.TimeoutError()

    async def no_reputation(url: str, hostname: str, settings: Settings | None) -> None:
        return None

    events: list[tuple[str, dict]] = []

    async def event_sink(kind: str, title: str, description: str, data: dict) -> None:
        events.append((kind, data))

    monkeypatch.setattr(url_scanner, "resolve_public_addresses", public_addresses)
    monkeypatch.setattr(url_scanner, "_request_response_headers", timed_out)
    outcome = run_without_io(url_scanner.inspect_url(
        "https://example.com", event_sink=event_sink,
        settings=configured_settings(), reputation_lookup=no_reputation,
    ))

    failed_stage = next(data for kind, data in events if kind == "network_stage_failed")
    redirect_status = next(data for kind, data in events if kind == "redirect_chain_inspected")
    assert outcome.risk_level == "INCONCLUSIVE"
    assert failed_stage["stage"] == "http"
    assert redirect_status["complete"] is False


def test_scan_writes_require_backend_only_key() -> None:
    store = ScanStore(configured_settings(supabase_url="https://project.example.supabase.co"))
    with pytest.raises(HTTPException) as error:
        run_without_io(store.require_write_access())
    assert error.value.status_code == 503
    assert "SUPABASE_SECRET_KEY" in error.value.detail


def test_admin_rest_headers_support_new_secret_and_legacy_service_role_keys() -> None:
    new_key = ScanStore(configured_settings(supabase_secret_key="sb_secret_test"))
    assert new_key._admin_headers()["apikey"] == "sb_secret_test"
    assert "Authorization" not in new_key._admin_headers()

    legacy = ScanStore(configured_settings(supabase_service_role_key="eyJ.legacy.jwt"))
    assert legacy._admin_headers()["Authorization"] == "Bearer eyJ.legacy.jwt"


def test_scan_api_routes_require_bearer_authentication() -> None:
    from fastapi.testclient import TestClient
    from app.main import app

    scan_id = "bc02b6aa-f06e-4fc0-9907-a09155abceaf"
    with TestClient(app) as client:
        paths = [
            ("POST", "/api/v1/scans/url"),
            ("GET", "/api/v1/scans"),
            ("GET", f"/api/v1/scans/{scan_id}"),
            ("GET", f"/api/v1/scans/{scan_id}/findings"),
            ("GET", f"/api/v1/scans/{scan_id}/events"),
            ("GET", f"/api/v1/scans/{scan_id}/status"),
        ]
        for method, path in paths:
            response = client.request(method, path, json={"url": "https://example.com"} if method == "POST" else None)
            assert response.status_code == 401
            assert response.headers["www-authenticate"] == "Bearer"


def test_url_scan_submission_fails_closed_without_admin_storage_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from uuid import UUID
    from fastapi.testclient import TestClient
    from app.api.dependencies import get_current_principal
    from app.main import app
    from app.services.auth import AuthenticatedPrincipal

    principal = AuthenticatedPrincipal(UUID("28499fd4-a8a2-4f82-b9b5-27cfb29df4cb"), None, "unit-test-token")
    store = ScanStore(configured_settings(supabase_url="https://project.supabase.co"))
    monkeypatch.setattr("app.api.scans.ScanStore", lambda: store)
    app.dependency_overrides[get_current_principal] = lambda: principal
    try:
        with TestClient(app) as client:
            response = client.post("/api/v1/scans/url", json={"url": "https://example.com"})
        assert response.status_code == 503
        assert "SUPABASE_SECRET_KEY" in response.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_current_principal, None)


def test_url_scan_submission_creates_owned_queued_job(monkeypatch: pytest.MonkeyPatch) -> None:
    from uuid import UUID
    from fastapi.testclient import TestClient
    from app.api.dependencies import get_current_principal
    from app.main import app
    from app.services.auth import AuthenticatedPrincipal
    from app.services.scan_queue import scan_queue

    principal = AuthenticatedPrincipal(UUID("28499fd4-a8a2-4f82-b9b5-27cfb29df4cb"), None, "unit-test-token")
    created: list[tuple[str, object]] = []

    class FakeStore:
        async def require_write_access(self):
            return None
        async def create_scan(self, scan_id, user_id, url):
            created.append(("scan", (scan_id, user_id, url)))
        async def add_event(self, scan_id, event_type, title, description, event_data):
            created.append(("event", (scan_id, event_type)))

    queued = []
    monkeypatch.setattr("app.api.scans.ScanStore", FakeStore)
    monkeypatch.setattr(scan_queue, "enqueue", lambda job: queued.append(job) or True)
    app.dependency_overrides[get_current_principal] = lambda: principal
    try:
        with TestClient(app) as client:
            response = client.post("/api/v1/scans/url", json={"url": "HTTPS://Example.COM/path"})
        assert response.status_code == 202
        assert response.json()["status"] == "queued"
        assert len(queued) == 1
        assert queued[0].user_id == principal.user_id
        assert queued[0].url == "https://example.com/path"
        assert [item[0] for item in created] == ["scan", "event"]
    finally:
        app.dependency_overrides.pop(get_current_principal, None)
