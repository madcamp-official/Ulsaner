"""플랫폼 FastAPI 스캐폴드 스모크 테스트."""

from fastapi.testclient import TestClient
from ulsaner_platform.app import app

client = TestClient(app)


def test_health_returns_ok():
    resp = client.get("/health")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
