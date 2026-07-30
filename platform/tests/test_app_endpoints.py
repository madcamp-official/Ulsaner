"""플랫폼 FastAPI 엔드포인트 테스트 — 검증 서비스를 HTTP 로 노출.

create_app 에 가짜 배포기를 주입한 ChallengeService 를 넣어 Docker 없이 HTTP 레이어를 검증.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from fastapi.testclient import TestClient
from ulsaner_platform.app import Challenge, create_app
from ulsaner_platform.service import ChallengeService
from ulsaner_platform.sources import fixture_source

from orchestrator.runner import Instance

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "platform" / "fixtures" / "easy-idor-01"
FLAG = "FLAG{idor_bob_private_2f9c}"


def make_client(vibecutter_result_path: Path | None = None) -> TestClient:
    svc = ChallengeService(
        deploy_fn=lambda bundle_dir, *, tag, container_port: Instance(
            container_id=f"cont-{tag}", host_port=55000, url="http://127.0.0.1:55000"
        ),
        stop_fn=lambda container_id: None,
        clock=lambda: 1000.0,
    )
    challenges = [
        Challenge(
            name="easy-idor-01",
            vuln_type="idor",
            tier="easy",
            task_prompt="다른 사용자의 비공개 노트를 읽어 flag 를 획득하세요.",
            provision=fixture_source(FIXTURE),
        )
    ]
    # 기본은 None(비활성) — 리포지토리에 결과 파일이 있어도 테스트가 흔들리지 않게.
    return TestClient(
        create_app(
            service=svc, challenges=challenges, vibecutter_result_path=vibecutter_result_path
        )
    )


class _DummyChallengeHandler(BaseHTTPRequestHandler):
    """실제 챌린지 컨테이너 대역 — 경로별로 다른 본문을 돌려줘 프록시 전달을 구분한다."""

    def _reply(self):
        body = f"root:{self.path}" if self.path == "/" else f"path:{self.path}"
        payload = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802 — http.server 관례
        self._reply()

    def log_message(self, *args):  # 테스트 출력 조용히
        pass


def make_proxy_client() -> tuple[TestClient, ThreadingHTTPServer]:
    """/play, /notes/search 등 캐치올 프록시를 검증하기 위해, 진짜 더미 HTTP 서버를
    백그라운드 스레드로 띄우고 그 실제 포트를 가리키는 가짜 Instance 로 서비스를 구성한다.
    """
    dummy = ThreadingHTTPServer(("127.0.0.1", 0), _DummyChallengeHandler)
    threading.Thread(target=dummy.serve_forever, daemon=True).start()
    port = dummy.server_address[1]

    svc = ChallengeService(
        deploy_fn=lambda bundle_dir, *, tag, container_port: Instance(
            container_id=f"cont-{tag}", host_port=port, url=f"http://127.0.0.1:{port}"
        ),
        stop_fn=lambda container_id: None,
        clock=lambda: 1000.0,
        public_base_url="https://ulsaner.example.test",
    )
    challenges = [
        Challenge(
            name="easy-idor-01", vuln_type="idor", tier="easy",
            task_prompt="다른 사용자의 비공개 노트를 읽어 flag 를 획득하세요.",
            provision=fixture_source(FIXTURE),
        )
    ]
    client = TestClient(create_app(service=svc, challenges=challenges, vibecutter_result_path=None))
    return client, dummy


def test_spin_up_sets_active_instance_cookie():
    client = make_client()
    resp = client.post("/challenges", json={"name": "easy-idor-01"})
    assert resp.cookies.get("ulsaner_instance") == resp.json()["challenge_id"]


def test_teardown_clears_active_instance_cookie():
    client = make_client()
    cid = client.post("/challenges", json={"name": "easy-idor-01"}).json()["challenge_id"]
    assert client.cookies.get("ulsaner_instance") == cid

    client.delete(f"/challenges/{cid}")
    assert client.cookies.get("ulsaner_instance") is None


def test_proxy_forwards_play_and_absolute_paths_to_active_instance():
    client, dummy = make_proxy_client()
    try:
        resp = client.post("/challenges", json={"name": "easy-idor-01"})
        assert resp.json()["url"] == "https://ulsaner.example.test/play"

        # /play → 챌린지 앱의 루트(/)로 전달됨
        play = client.get("/play")
        assert play.status_code == 200
        assert play.text == "root:/"

        # 절대경로 fetch(/notes/search?q=...)도 동일 경로로 그대로 전달됨
        search = client.get("/notes/search?q=x")
        assert search.status_code == 200
        assert search.text == "path:/notes/search?q=x"
    finally:
        dummy.shutdown()


def test_proxy_returns_404_without_active_instance_cookie():
    client = make_client()  # 스핀업 안 함 → 쿠키 없음
    assert client.get("/some/unmatched/path").status_code == 404


def test_proxy_returns_404_for_stale_or_unknown_instance_cookie():
    client = make_client()
    client.cookies.set("ulsaner_instance", "no-such-challenge-id")
    assert client.get("/play").status_code == 404


def test_health_still_ok():
    assert make_client().get("/health").json() == {"status": "ok"}


def test_list_challenges_includes_metadata():
    # 카드에 보여줄 정보(취약점 종류·난이도·과제)를 배포 없이 제공. flag 는 절대 미노출.
    resp = make_client().get("/challenges")
    assert resp.status_code == 200
    items = resp.json()["available"]
    item = next(c for c in items if c["name"] == "easy-idor-01")
    assert item["vuln_type"] == "idor"
    assert item["tier"] == "easy"
    assert item["task_prompt"]
    assert "flag" not in item


def test_default_catalog_includes_sqli_challenge():
    # 기본 카탈로그(DEFAULT_CHALLENGES)에 엔진 sqli 챌린지가 노출된다(idor 외 2번째 종류).
    client = TestClient(create_app(vibecutter_result_path=None))
    items = client.get("/challenges").json()["available"]
    sqli = next(c for c in items if c["name"] == "easy-sqli-live")
    assert sqli["vuln_type"] == "sqli"
    assert sqli["tier"] == "easy"


def test_root_serves_dc_design():
    # 주 UI = Claude Design 핸드오프 재현본(다크 테크니컬).
    resp = make_client().get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "VITE" in resp.text
    assert "취약점 주입 훈련 엔진" in resp.text  # dc 디자인 마커


def test_alt_design_routes_removed():
    # UI 를 index_dc 하나로 정착하며 비교용 대안 라우트(/a, /v2)를 제거했다.
    client = make_client()
    assert client.get("/a").status_code == 404
    assert client.get("/v2").status_code == 404


def test_delete_challenge_tears_down():
    client = make_client()
    cid = client.post("/challenges", json={"name": "easy-idor-01"}).json()["challenge_id"]

    resp = client.delete(f"/challenges/{cid}")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}

    # 종료 후엔 제출 불가(404)
    assert client.post(f"/challenges/{cid}/submit", json={"flag": FLAG}).status_code == 404


def test_spin_up_returns_url_and_prompt_without_flag():
    resp = make_client().post("/challenges", json={"name": "easy-idor-01"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["challenge_id"]
    assert body["url"] == "http://127.0.0.1:55000"
    assert body["entry"]["task_prompt"]
    assert "flag" not in body and "_internal" not in body


def test_spin_up_unknown_challenge_is_404():
    resp = make_client().post("/challenges", json={"name": "nope"})
    assert resp.status_code == 404


def test_spin_up_at_capacity_returns_503():
    # 동시 상한 도달 시 새 스핀업은 503 으로 거절한다.
    svc = ChallengeService(
        deploy_fn=lambda bundle_dir, *, tag, container_port: Instance(
            container_id=f"cont-{tag}", host_port=55000, url="http://127.0.0.1:55000"
        ),
        stop_fn=lambda container_id: None,
        clock=lambda: 1000.0,
        max_active=1,
    )
    challenges = [
        Challenge(
            name="easy-idor-01",
            vuln_type="idor",
            tier="easy",
            task_prompt="다른 사용자의 비공개 노트를 읽어 flag 를 획득하세요.",
            provision=fixture_source(FIXTURE),
        )
    ]
    client = TestClient(create_app(service=svc, challenges=challenges))

    assert client.post("/challenges", json={"name": "easy-idor-01"}).status_code == 200
    resp = client.post("/challenges", json={"name": "easy-idor-01"})
    assert resp.status_code == 503


def test_submit_correct_then_wrong_flow():
    client = make_client()
    cid = client.post("/challenges", json={"name": "easy-idor-01"}).json()["challenge_id"]

    wrong = client.post(f"/challenges/{cid}/submit", json={"flag": "FLAG{x}"})
    assert wrong.json() == {"correct": False}

    right = client.post(f"/challenges/{cid}/submit", json={"flag": FLAG})
    body = right.json()
    assert body["correct"] is True
    assert body["reveal"] and body["reveal"]["solution_summary"]  # 정답 시 해설 동반

    # 정답 후엔 teardown 되어 다시 제출 불가
    again = client.post(f"/challenges/{cid}/submit", json={"flag": FLAG})
    assert again.status_code == 404


def test_stats_counts_attempts():
    client = make_client()
    cid = client.post("/challenges", json={"name": "easy-idor-01"}).json()["challenge_id"]
    client.post(f"/challenges/{cid}/submit", json={"flag": "FLAG{x}"})
    client.post(f"/challenges/{cid}/submit", json={"flag": FLAG})

    stats = client.get("/stats").json()
    assert stats["attempts"] == 2
    assert stats["solved"] == 1


def test_stats_breakdown_by_tier_and_vuln():
    client = make_client()
    cid = client.post("/challenges", json={"name": "easy-idor-01"}).json()["challenge_id"]
    client.post(f"/challenges/{cid}/submit", json={"flag": "FLAG{wrong}"})  # 오답
    client.post(f"/challenges/{cid}/submit", json={"flag": FLAG})  # 정답 → teardown

    stats = client.get("/stats").json()
    assert stats["attempts"] == 2
    assert stats["solved"] == 1
    assert stats["success_rate"] == 0.5
    assert stats["by_tier"]["easy"] == {"attempts": 2, "solved": 1}
    assert stats["by_vuln"]["idor"] == {"attempts": 2, "solved": 1}
    # VibeCutter 벤치마크는 아직 미실행 → 자리표시자 None
    assert stats["vibecutter"] is None


def test_stats_empty_is_zero_rate():
    stats = make_client().get("/stats").json()
    assert stats == {
        "attempts": 0, "solved": 0, "success_rate": 0.0,
        "by_tier": {}, "by_vuln": {}, "by_challenge": {},
        "vibecutter": None, "vibecutter_detail": None,
    }


def test_stats_counts_solves_per_challenge():
    # 챌린지 슬롯별 성공 횟수를 기록한다(한 번 풀어도 클리어가 아니라 누적 카운트).
    client = make_client()
    for _ in range(2):  # easy-idor-01 을 두 번 풀기
        cid = client.post("/challenges", json={"name": "easy-idor-01"}).json()["challenge_id"]
        client.post(f"/challenges/{cid}/submit", json={"flag": "FLAG{nope}"})  # 오답 1
        client.post(f"/challenges/{cid}/submit", json={"flag": FLAG})  # 정답 → teardown
    by_ch = client.get("/stats").json()["by_challenge"]
    assert by_ch["easy-idor-01"] == {"attempts": 4, "solved": 2}


def test_stats_reports_vibecutter_when_result_file_present(tmp_path):
    # 서윤이 run_benchmark 결과를 이 형식으로 떨구면 /stats 가 그대로 읽어 노출한다.
    result = tmp_path / "vibecutter_result.json"
    result.write_text(
        json.dumps(
            {"seeds": [1, 2, 3, 4], "results": [True, False, False, False], "success_rate": 0.25}
        ),
        encoding="utf-8",
    )
    stats = make_client(vibecutter_result_path=result).get("/stats").json()
    assert stats["vibecutter"] == 0.25
    assert stats["vibecutter_detail"] == {"instances": 4, "solved": 1}


def test_stats_reports_vibecutter_rich_fields(tmp_path):
    # 멀티클래스 하네스 형식이면 /stats 가 클래스별·stock·exploitable 확장 필드를 노출한다.
    result = tmp_path / "vibecutter_result.json"
    result.write_text(
        json.dumps(
            {
                "seeds": [1, 2, 3],
                "results": [True, False, False],
                "success_rate": 0.3333,
                "success_rate_stock": 0.0,
                "success_rate_by_class": {"idor-easy": 1.0, "idor-hard": 0.0, "sqli-easy": 0.0},
                "detail": [
                    {"exploitable": True},
                    {"exploitable": True},
                    {"exploitable": True},
                ],
            }
        ),
        encoding="utf-8",
    )
    det = make_client(vibecutter_result_path=result).get("/stats").json()["vibecutter_detail"]
    assert det["instances"] == 3 and det["solved"] == 1
    assert det["stock_rate"] == 0.0
    assert det["by_class"] == {"idor-easy": 1.0, "idor-hard": 0.0, "sqli-easy": 0.0}
    assert det["exploitable"] == 3  # 자동도구가 놓쳐도 3개 전부 실제 취약


def test_stats_vibecutter_none_when_file_missing(tmp_path):
    # 결과 파일이 아직 없으면 '벤치마크 대기'(None)로 남는다.
    stats = make_client(vibecutter_result_path=tmp_path / "nope.json").get("/stats").json()
    assert stats["vibecutter"] is None
    assert stats["vibecutter_detail"] is None


def test_dashboard_page_serves():
    resp = make_client().get("/dashboard")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "VibeCutter" in resp.text
