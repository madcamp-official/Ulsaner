"""오케스트레이터 v1-a+v1-b 통합 테스트 (실제 Docker 필요).

fixture 번들을 실제로 빌드 → 동적 포트로 실행 → 발급된 URL 로 접속해
IDOR 익스플로잇이 되는지 확인하고 정리한다. 오늘 손으로 검증한 경로를 코드로 자동화.

실행: pytest -m integration   (Docker/Colima 데몬 필요)
"""

import json
import time
from pathlib import Path

import httpx
import pytest

from orchestrator.runner import deploy_bundle, stop_container

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "platform" / "fixtures" / "easy-idor-01"


def _wait_until_up(url: str, timeout: float = 45.0) -> None:
    """앱이 응답할 때까지 대기(연결되면 401이든 뭐든 '떴다'로 간주)."""
    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            httpx.get(f"{url}/notes/42", timeout=2)
            return
        except httpx.HTTPError as exc:  # 연결 거부 등
            last_err = exc
            time.sleep(1)
    raise RuntimeError(f"컨테이너 앱이 시간 내에 뜨지 않음: {last_err}")


def test_deploy_fixture_and_exploit_over_mapped_port():
    manifest = json.loads((FIXTURE / "manifest.json").read_text(encoding="utf-8"))
    container_port = manifest["entry"]["port"]
    flag = manifest["flag"]

    inst = deploy_bundle(FIXTURE, "ulsaner-orch-itest:latest", container_port=container_port)
    try:
        assert inst.container_id
        assert inst.url.startswith("http://127.0.0.1:")
        _wait_until_up(inst.url)

        # 미인증은 막힘
        unauth = httpx.get(f"{inst.url}/notes/42", timeout=5)
        assert unauth.status_code == 401

        # alice 토큰으로 bob(피해자) 노트 조회 → IDOR → flag 도달
        exploit = httpx.get(
            f"{inst.url}/notes/42",
            headers={"Authorization": "Bearer alice-token"},
            timeout=5,
        )
        assert exploit.status_code == 200
        assert flag in exploit.json()["content"]
    finally:
        stop_container(inst.container_id)
