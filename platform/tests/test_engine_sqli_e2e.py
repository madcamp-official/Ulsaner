"""실번들 E2E — 엔진 easy/sqli 번들을 플랫폼이 배포·채점하는 전체 루프.

idor 와 동일한 경로를 sqli 로 검증한다(2번째 취약점 종류 = 일반성). 검색 엔드포인트의
SQL 인젝션(UNION)으로 비공개 노트의 랜덤 flag 를 빼내 제출한다.

실행: pytest -m integration   (Docker/Colima 데몬 + 엔진 의존성 필요, 수십 초 소요)
"""

import json
import re
import time
from pathlib import Path

import httpx
import pytest
from ulsaner_platform.service import ChallengeNotFound, ChallengeService
from ulsaner_platform.sources import engine_source

pytestmark = pytest.mark.integration


def _wait_until_up(url: str, path: str, timeout: float = 45.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            httpx.get(f"{url}{path}", timeout=2)
            return
        except httpx.HTTPError:
            time.sleep(1)
    raise RuntimeError("컨테이너 앱이 시간 내에 뜨지 않음")


def test_engine_sqli_full_loop_random_flag():
    service = ChallengeService()
    bundle_dir, cleanup = engine_source("sqli", "easy")()  # 실 sqli 번들 생성(랜덤 flag)
    try:
        manifest = json.loads((bundle_dir / "manifest.json").read_text())
        real_flag = manifest["flag"]
        assert manifest["vuln_type"] == "sqli"
        assert re.fullmatch(r"FLAG\{[^}]+\}", real_flag)

        exploit = json.loads((bundle_dir / "exploits" / "reference.json").read_text())
        # 보안: exploits/ 는 빌드 컨텍스트(app/) 밖 → 이미지에 안 실린다.
        assert not (bundle_dir / "app" / "exploits").exists()

        # 1) 스핀업(실배포)
        view = service.spin_up(bundle_dir, cleanup=cleanup)
        challenge_id, url = view["challenge_id"], view["url"]
        assert "flag" not in view and "_internal" not in view

        # 2) SQL 인젝션: 레퍼런스 페이로드(UNION)로 비공개 노트 flag 유출
        _wait_until_up(url, exploit["path"])
        resp = httpx.request(
            exploit["method"], f"{url}{exploit['path']}", headers=exploit.get("headers", {}), timeout=5
        )
        match = re.search(r"FLAG\{[^}]+\}", resp.text)
        assert match, "SQLi 로 flag 를 얻지 못함"
        assert match.group(0) == real_flag

        # 보안: exploits/reference.json 은 실행 URL 로 도달 불가
        assert httpx.get(f"{url}/exploits/reference.json", timeout=5).status_code == 404

        # 3) 제출 → 채점 통과 → teardown → 재제출 404
        assert service.submit_flag(challenge_id, real_flag).correct is True
        with pytest.raises(ChallengeNotFound):
            service.submit_flag(challenge_id, real_flag)
    finally:
        for cid in service.active_ids():
            service.teardown(cid)
        cleanup()

    assert not Path(bundle_dir).exists()
