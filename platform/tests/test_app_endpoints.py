"""플랫폼 FastAPI 엔드포인트 테스트 — 검증 서비스를 HTTP 로 노출.

create_app 에 가짜 배포기를 주입한 ChallengeService 를 넣어 Docker 없이 HTTP 레이어를 검증.
"""

from pathlib import Path

from fastapi.testclient import TestClient
from ulsaner_platform.app import create_app
from ulsaner_platform.service import ChallengeService

from orchestrator.runner import Instance

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "platform" / "fixtures" / "easy-idor-01"
FLAG = "FLAG{idor_bob_private_2f9c}"


def make_client() -> TestClient:
    svc = ChallengeService(
        deploy_fn=lambda bundle_dir, *, tag, container_port: Instance(
            container_id=f"cont-{tag}", host_port=55000, url="http://127.0.0.1:55000"
        ),
        stop_fn=lambda container_id: None,
        clock=lambda: 1000.0,
    )
    return TestClient(create_app(service=svc, bundles={"easy-idor-01": FIXTURE}))


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


def test_root_serves_dc_design():
    # 주 UI = Claude Design 핸드오프 재현본(다크 테크니컬).
    resp = make_client().get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Ulsaner" in resp.text
    assert "취약점 주입 훈련 엔진" in resp.text  # dc 디자인 마커


def test_a_serves_educational_design():
    resp = make_client().get("/a")
    assert resp.status_code == 200
    assert "매번 새로 생성되는 웹 취약점 훈련장" in resp.text  # 디자인 A 마커


def test_v2_serves_alt_design():
    resp = make_client().get("/v2")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "console" in resp.text  # 다크 콘솔 디자인 마커


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


def test_submit_correct_then_wrong_flow():
    client = make_client()
    cid = client.post("/challenges", json={"name": "easy-idor-01"}).json()["challenge_id"]

    wrong = client.post(f"/challenges/{cid}/submit", json={"flag": "FLAG{x}"})
    assert wrong.json() == {"correct": False}

    right = client.post(f"/challenges/{cid}/submit", json={"flag": FLAG})
    assert right.json() == {"correct": True}

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
