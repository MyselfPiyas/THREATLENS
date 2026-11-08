from fastapi.testclient import TestClient

from app.main import app


def test_analysis_endpoints_require_authentication() -> None:
    client = TestClient(app)
    assert client.post("/api/v1/analyze/message", json={"content": "hello"}).status_code == 401
    assert client.get("/api/v1/analyze/message/00000000-0000-0000-0000-000000000001").status_code == 401
    assert client.post("/api/v1/analyze/qr", files={"file": ("qr.png", b"x", "image/png")}).status_code == 401
    assert client.get("/api/v1/analyze/qr/00000000-0000-0000-0000-000000000001").status_code == 401
