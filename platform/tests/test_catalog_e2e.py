"""새 카탈로그 조합 실배포 E2E — 방금 배선한 슬롯(hard_sqli·xss·tickets_app)이
플랫폼 경로(engine_source → generate_bundle → ChallengeService.spin_up → 실컨테이너)로
끝까지 도는지 검증한다.

기존 test_engine_bundle_e2e.py(idor/notes)와 같은 계약을, 새로 노출한 조합마다 돌린다:
  1) engine_source(...)() 가 랜덤 flag 실번들을 생성(엔진 자가검증 게이트 통과).
  2) 플랫폼이 app/ 만 실배포 → 레퍼런스 익스플로잇 경로/헤더로 실행 인스턴스를 찔러
     랜덤 flag 획득(획득값 == manifest flag).
  3) 제출 → 채점 통과 → teardown → 재제출 404.
  4) 보안: exploits/ 는 빌드 컨텍스트·실행 URL 어디에도 도달 불가.

주의(XSS): XSS의 레퍼런스 익스플로잇은 flag 를 페이로드에 스스로 실어 반사를 증명하므로
이 테스트(reference.json 사용)는 통과한다. 하지만 이는 '자가검증이 된다'는 뜻이지
'flag 를 모르는 사람이 인터랙티브로 풀 수 있다'는 뜻이 아니다(카탈로그 노출 여부는 별도 결정).

실행: pytest -m integration platform/tests/test_catalog_e2e.py  (Docker/Colima 필요, 수 분 소요)
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

FLAG_RE = re.compile(r"FLAG\{[^}]+\}")


# (테스트 id, engine_source 위치인자, engine_source 키워드인자)
NEW_CATALOG_CASES = [
    ("hard_sqli-hard", ("hard_sqli", "hard"), {}),
    ("xss-easy", ("xss", "easy"), {}),
    ("tickets-idor-easy", ("idor", "easy"), {"template": "tickets"}),
    ("tickets-idor-hard", ("idor", "hard"), {"template": "tickets"}),
    ("tickets-sqli-easy", ("sqli", "easy"), {"template": "tickets"}),
]


def _wait_until_up(url: str, path: str, headers: dict, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            httpx.request("GET", f"{url}{path}", headers=headers, timeout=2)
            return
        except httpx.HTTPError:
            time.sleep(1)
    raise RuntimeError("컨테이너 앱이 시간 내에 뜨지 않음")


@pytest.mark.parametrize(
    "label,args,kwargs", NEW_CATALOG_CASES, ids=[c[0] for c in NEW_CATALOG_CASES]
)
def test_new_catalog_entry_full_loop(label, args, kwargs):
    service = ChallengeService()
    # 1) 실번들 생성(엔진 자가검증 게이트: Docker 빌드+레퍼런스 익스플로잇 통과해야 반환).
    bundle_dir, cleanup = engine_source(*args, **kwargs)()
    try:
        manifest = json.loads((bundle_dir / "manifest.json").read_text())
        real_flag = manifest["flag"]
        assert FLAG_RE.fullmatch(real_flag), f"{label}: manifest flag 형식 이상"

        exploit = json.loads((bundle_dir / "exploits" / "reference.json").read_text())
        # 보안: 빌드 컨텍스트(app/)에 exploits/ 가 섞이면 안 된다(이미지에 안 실림).
        assert not (bundle_dir / "app" / "exploits").exists()

        # 2) 실배포(app/ 만 빌드) → 학생 뷰엔 flag/_internal 없음.
        view = service.spin_up(bundle_dir, name=label, cleanup=cleanup)
        challenge_id, url = view["challenge_id"], view["url"]
        assert "flag" not in view and "_internal" not in view

        # 3) 레퍼런스 익스플로잇으로 실행 인스턴스에서 랜덤 flag 획득.
        headers = exploit.get("headers", {})
        _wait_until_up(url, exploit["path"], headers)
        resp = httpx.request(
            exploit["method"], f"{url}{exploit['path']}", headers=headers, timeout=5
        )
        match = FLAG_RE.search(resp.text)
        assert match, f"{label}: 익스플로잇으로 flag 를 얻지 못함 (status={resp.status_code})"
        assert match.group(0) == real_flag, f"{label}: 획득 flag != manifest flag"

        # 보안: exploits/reference.json 은 실행 URL 로 도달 불가.
        assert httpx.get(f"{url}/exploits/reference.json", timeout=5).status_code == 404

        # 4) 제출 → 채점 통과 → teardown → 재제출 404.
        assert service.submit_flag(challenge_id, real_flag).correct is True
        with pytest.raises(ChallengeNotFound):
            service.submit_flag(challenge_id, real_flag)
    finally:
        for cid in service.active_ids():
            service.teardown(cid)
        cleanup()

    assert not Path(bundle_dir).exists()  # teardown 이 임시 번들 정리
