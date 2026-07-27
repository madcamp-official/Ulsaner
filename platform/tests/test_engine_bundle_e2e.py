"""실번들 E2E (⭐) — 엔진이 생성한 진짜 번들을 플랫폼이 배포·채점하는 전체 루프.

fixture(고정 flag)가 아니라 engine.bundle.generate_bundle 이 만든 실번들을 쓴다.
시드가 매번 랜덤이라 인스턴스마다 flag 가 다르다 — thesis("정답을 미리 찾아볼 수 없다")의
실현. 검증하는 계약:
  1) 엔진이 랜덤 flag 번들을 생성하고 플랫폼이 그 app/ 만 배포한다.
  2) 배포된 인스턴스가 실제로 IDOR 로 뚫려 그 랜덤 flag 를 얻는다.
  3) 얻은 flag 를 제출하면 채점 통과 + 정답 시 teardown.
  4) 보안: exploits/(평문 flag·공격자 토큰)는 빌드 컨텍스트에도, 실행 URL 에도 도달 불가.

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

FIXTURE_FLAG = "FLAG{idor_bob_private_2f9c}"  # fixture 고정값 — 실번들은 이것과 달라야 한다.


def _wait_until_up(url: str, path: str, headers: dict, timeout: float = 45.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            httpx.request("GET", f"{url}{path}", headers=headers, timeout=2)
            return
        except httpx.HTTPError:
            time.sleep(1)
    raise RuntimeError("컨테이너 앱이 시간 내에 뜨지 않음")


def test_engine_bundle_full_loop_random_flag():
    service = ChallengeService()
    bundle_dir, cleanup = engine_source("idor", "easy")()  # 실번들 생성(랜덤 flag)
    view = None
    try:
        manifest = json.loads((bundle_dir / "manifest.json").read_text())
        real_flag = manifest["flag"]
        # thesis: 매 인스턴스 랜덤 → fixture 의 고정 flag 와 다르고 FLAG{...} 형식.
        assert real_flag != FIXTURE_FLAG
        assert re.fullmatch(r"FLAG\{[^}]+\}", real_flag)

        # 레퍼런스 익스플로잇(경로/헤더)은 번들 안 exploits/ 에만 있고 배포엔 안 실린다.
        exploit = json.loads((bundle_dir / "exploits" / "reference.json").read_text())
        # 보안: 빌드 컨텍스트(app/)에는 exploits/ 가 없어야 한다(이미지에 안 실림).
        assert not (bundle_dir / "app" / "exploits").exists()

        # 1) 스핀업(실배포) — app/ 만 빌드된다.
        view = service.spin_up(bundle_dir, cleanup=cleanup)
        challenge_id, url = view["challenge_id"], view["url"]
        assert "flag" not in view and "_internal" not in view

        # 2) 익스플로잇: 레퍼런스 경로/헤더로 실행 인스턴스를 찔러 랜덤 flag 획득.
        _wait_until_up(url, exploit["path"], exploit.get("headers", {}))
        resp = httpx.request(
            exploit["method"],
            f"{url}{exploit['path']}",
            headers=exploit.get("headers", {}),
            timeout=5,
        )
        match = re.search(r"FLAG\{[^}]+\}", resp.text)
        assert match, "익스플로잇으로 flag 를 얻지 못함"
        assert match.group(0) == real_flag  # 획득한 flag == manifest 의 랜덤 flag

        # 보안: exploits/reference.json 은 실행 URL 로 도달 불가(정적 노출 안 됨).
        leaked = httpx.get(f"{url}/exploits/reference.json", timeout=5)
        assert leaked.status_code == 404

        # 3) 제출 → 채점 통과 → teardown → 재제출 404
        assert service.submit_flag(challenge_id, real_flag) is True
        with pytest.raises(ChallengeNotFound):
            service.submit_flag(challenge_id, real_flag)
    finally:
        for cid in service.active_ids():
            service.teardown(cid)
        cleanup()  # 임시 번들 정리(멱등)

    # teardown 이 임시 번들 디렉토리를 지웠는지 확인.
    assert not Path(bundle_dir).exists()
