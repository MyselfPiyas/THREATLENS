import pytest
import asyncio
import ssl

from app.core.config import Settings
from app.services import tls_analysis


def test_http_tls_analysis_is_explicitly_unavailable() -> None:
    result = __import__("asyncio").run(tls_analysis.analyze_tls("http://example.com"))
    assert result["available"] is False
    assert "only applies to HTTPS" in result["reason"]


def test_invalid_tls_handshake_fails_closed_without_certificate_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    async def addresses(hostname: str, timeout_seconds: float | None = None) -> list[str]:
        return ["93.184.216.34"]

    async def failed_probe(hostname: str, resolved: list[str], settings: Settings) -> dict:
        raise ssl.SSLCertVerificationError("hostname mismatch")

    monkeypatch.setattr(tls_analysis, "resolve_public_addresses", addresses)
    monkeypatch.setattr(tls_analysis, "_tls_probe", failed_probe)
    result = asyncio.run(tls_analysis.analyze_tls("https://example.com"))
    assert result["available"] is False
    assert result["certificate"] is None
    assert result["error_type"] == "SSLCertVerificationError"


def test_certificate_transparency_result_is_source_attributed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        status_code = 200
        content = b"[]"

        def json(self):
            return [{"name_value": "example.com\nwww.example.com", "not_before": "2026-01-01"}]

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, *args, **kwargs):
            return Response()

    monkeypatch.setattr(tls_analysis.httpx, "AsyncClient", lambda **kwargs: Client())
    result = asyncio.run(tls_analysis.certificate_transparency_lookup("example.com"))
    assert result["available"] is True
    assert result["source"] == "crt.sh"
    assert result["domain_match"] is True


def test_chain_decoder_reports_runtime_limitation() -> None:
    class NoChain:
        pass

    result = tls_analysis._peer_chain(NoChain())
    assert result["available"] is False


def test_security_headers_are_checked_without_fetching_a_body(monkeypatch: pytest.MonkeyPatch) -> None:
    async def addresses(hostname: str, timeout_seconds: float | None = None) -> list[str]:
        return ["93.184.216.34"]

    async def response(url: str, resolved: list[str], settings: Settings) -> tuple[int, dict[str, str]]:
        return 200, {"strict-transport-security": "max-age=31536000", "x-content-type-options": "nosniff"}

    monkeypatch.setattr(tls_analysis, "resolve_public_addresses", addresses)
    monkeypatch.setattr(tls_analysis, "_request_response_headers", response)
    result = __import__("asyncio").run(tls_analysis.analyze_security_headers("https://example.com"))
    assert result["http_status"] == 200
    assert result["headers"]["HSTS"] == "present"
    assert result["headers"]["X-Content-Type-Options"] == "present"
    assert "Content-Security-Policy" in result["missing"]
    assert result["mixed_content"]["available"] is False
    assert any(item["status"] == "missing" for item in result["findings"])
    assert all("remediation" in item for item in result["findings"])
