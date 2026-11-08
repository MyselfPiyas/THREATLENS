from uuid import uuid4

from fastapi.testclient import TestClient

from app.api.dependencies import get_current_principal
from app.main import app
from app.services.auth import AuthenticatedPrincipal
from app.api.passports import _make_pdf
from app.services.passport_service import report_hash


def test_passport_routes_require_authentication():
    with TestClient(app) as client:
        assert client.get("/api/v1/passports").status_code == 401
        assert client.post("/api/v1/passports", json={"scan_id": str(uuid4())}).status_code == 401


def test_owner_verify_rehashes_persisted_snapshot(monkeypatch):
    user_id, passport_id, scan_id = uuid4(), uuid4(), uuid4()
    report = {"passport_id": str(passport_id), "scan_id": str(scan_id), "report_version": "1.0", "generated_at": "2026-01-01T00:00:00Z", "target": "https://example.com", "risk_level": "INCONCLUSIVE", "risk_score": 0, "findings": [], "events": []}
    digest = report_hash(report)
    row = {"id": str(passport_id), "scan_id": str(scan_id), "user_id": str(user_id), "report_hash": digest, "report_version": "1.0", "canonical_report": report, "hash_algorithm": "SHA-256", "verification_status": "OFFCHAIN_VERIFIED", "verification_at": None, "public_sharing_enabled": False, "public_token": None, "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}
    updates = []

    class FakeStore:
        async def read_own_rows(self, principal, table, params):
            assert principal.user_id == user_id
            return [row]

        async def update_passport(self, item_id, values):
            updates.append((item_id, values))

    monkeypatch.setattr("app.api.passports.ScanStore", FakeStore)
    app.dependency_overrides[get_current_principal] = lambda: AuthenticatedPrincipal(user_id, None, "test-token")
    try:
        with TestClient(app) as client:
            response = client.post(f"/api/v1/passports/{passport_id}/verify")
    finally:
        app.dependency_overrides.pop(get_current_principal, None)
    assert response.status_code == 200
    payload = response.json()
    assert payload["integrity_match"] is True
    assert payload["passport"]["verification_status"] == "OFFCHAIN_VERIFIED"
    assert updates and updates[0][1]["verification_status"] == "OFFCHAIN_VERIFIED"


def test_public_share_verification_returns_no_scan_or_owner_data(monkeypatch):
    passport_id = uuid4()
    report = {"passport_id": str(passport_id), "scan_id": str(uuid4()), "target": "private-target", "risk_level": "INCONCLUSIVE", "risk_score": 0, "findings": [], "events": []}
    token = "a" * 43
    row = {"id": str(passport_id), "report_hash": report_hash(report), "report_version": "1.0", "hash_algorithm": "SHA-256", "canonical_report": report, "verification_status": "OFFCHAIN_VERIFIED", "created_at": "2026-01-01T00:00:00Z", "public_sharing_enabled": True}

    class FakeStore:
        async def admin_rows(self, table, params):
            assert params["public_token"] == f"eq.{token}"
            assert params["public_sharing_enabled"] == "eq.true"
            return [row]

    monkeypatch.setattr("app.api.passports.ScanStore", FakeStore)
    with TestClient(app) as client:
        response = client.get(f"/api/v1/public/passports/{token}/verify")
    assert response.status_code == 200
    payload = response.json()
    assert payload["integrity_match"] is True
    assert "scan_id" not in payload and "user_id" not in payload and "canonical_report" not in payload
    assert "private-target" not in response.text


def test_public_link_is_not_enabled_for_tampered_stored_report(monkeypatch):
    user_id, passport_id = uuid4(), uuid4()
    report = {"passport_id": str(passport_id), "target": "tampered"}
    row = {"id": str(passport_id), "scan_id": str(uuid4()), "user_id": str(user_id), "report_hash": "0" * 64, "canonical_report": report}
    updates = []

    class FakeStore:
        async def read_own_rows(self, principal, table, params):
            return [row]

        async def update_passport(self, item_id, values):
            updates.append(values)

    monkeypatch.setattr("app.api.passports.ScanStore", FakeStore)
    app.dependency_overrides[get_current_principal] = lambda: AuthenticatedPrincipal(user_id, None, "test-token")
    try:
        with TestClient(app) as client:
            response = client.post(f"/api/v1/passports/{passport_id}/share")
    finally:
        app.dependency_overrides.pop(get_current_principal, None)
    assert response.status_code == 409
    assert not updates


def test_pdf_export_sanitizes_untrusted_newlines():
    pdf = _make_pdf({"target": "safe.example\n) Tj\n1 0 0 rg", "findings": []}, "a" * 64)
    assert pdf.startswith(b"%PDF-1.4")
    assert b"\n) Tj\n1 0 0 rg" not in pdf


def test_failed_scan_cannot_create_official_passport(monkeypatch):
    user_id, scan_id = uuid4(), uuid4()

    class FakeStore:
        async def read_own_rows(self, principal, table, params):
            if table == "trust_passports":
                return []
            if table == "scans":
                return [{
                    "id": str(scan_id), "user_id": str(user_id), "scan_type": "url",
                    "target": "https://example.com", "normalized_target": "https://example.com/",
                    "status": "failed", "risk_level": "INCONCLUSIVE", "risk_score": 0,
                    "summary": "The bounded inspection failed before completion.",
                    "started_at": "2026-01-01T00:00:00Z", "completed_at": "2026-01-01T00:00:01Z",
                }]
            return []

    monkeypatch.setattr("app.api.passports.ScanStore", FakeStore)
    app.dependency_overrides[get_current_principal] = lambda: AuthenticatedPrincipal(user_id, None, "test-token")
    try:
        with TestClient(app) as client:
            response = client.post("/api/v1/passports", json={"scan_id": str(scan_id)})
    finally:
        app.dependency_overrides.pop(get_current_principal, None)
    assert response.status_code == 409


def test_passport_status_is_owner_scoped(monkeypatch):
    user_id, passport_id = uuid4(), uuid4()
    row = {
        "id": str(passport_id), "scan_id": str(uuid4()), "user_id": str(user_id),
        "report_hash": "a" * 64, "report_version": "1.0", "hash_algorithm": "SHA-256",
        "verification_status": "OFFCHAIN_VERIFIED", "verification_at": None,
        "public_sharing_enabled": False, "public_token": None,
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
    }

    class FakeStore:
        async def read_own_rows(self, principal, table, params):
            assert principal.user_id == user_id
            assert params["id"] == f"eq.{passport_id}"
            return [row]

    monkeypatch.setattr("app.api.passports.ScanStore", FakeStore)
    app.dependency_overrides[get_current_principal] = lambda: AuthenticatedPrincipal(user_id, None, "test-token")
    try:
        with TestClient(app) as client:
            response = client.get(f"/api/v1/passports/{passport_id}/status")
    finally:
        app.dependency_overrides.pop(get_current_principal, None)
    assert response.status_code == 200
    assert response.json()["verification_status"] == "OFFCHAIN_VERIFIED"
