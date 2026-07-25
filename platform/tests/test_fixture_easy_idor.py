"""fixture 번들 easy-idor-01 검증.

이 fixture 는 손으로 만든 취약 앱으로, 플랫폼(Part B)이 엔진 없이 선개발하는 기준 번들이다.
검증하는 계약: (1) manifest 가 스키마에 부합, (2) 앱이 실제로 IDOR 로 뚫린다(반드시 풀림),
(3) 익스플로잇으로 도달한 flag 가 manifest 의 flag 와 일치.
"""

import importlib.util
from pathlib import Path

from fastapi.testclient import TestClient
from ulsaner_platform.manifest import load_bundle_manifest

REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE = REPO_ROOT / "platform" / "fixtures" / "easy-idor-01"

ATTACKER = {"Authorization": "Bearer alice-token"}  # 공격자 alice(id=1)
VICTIM_NOTE_ID = 42  # bob(id=2) 의 비공개 노트 (flag 심긴 곳)


def load_fixture_app():
    spec = importlib.util.spec_from_file_location(
        "fixture_easy_idor_main", BUNDLE / "app" / "main.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


def test_fixture_manifest_conforms_to_contract():
    m = load_bundle_manifest(BUNDLE)
    assert m.vuln_type == "idor"
    assert m.tier == "easy"
    assert m.port == 8000


def test_unauthenticated_request_is_rejected():
    # IDOR 는 인증은 됐지만 인가가 없는 것 — 미인증은 여전히 막혀야 한다.
    client = TestClient(load_fixture_app())
    resp = client.get(f"/notes/{VICTIM_NOTE_ID}")
    assert resp.status_code == 401


def test_owner_can_read_own_note():
    # 정상 동작: 소유자는 자기 노트를 읽는다.
    client = TestClient(load_fixture_app())
    resp = client.get("/notes/1", headers=ATTACKER)  # note 1 = alice 소유
    assert resp.status_code == 200
    assert resp.json()["owner_id"] == 1


def test_attacker_reads_victim_note_via_idor():
    # 취약점: 소유권 체크 부재로 alice 가 bob 의 비공개 노트를 읽는다.
    client = TestClient(load_fixture_app())
    resp = client.get(f"/notes/{VICTIM_NOTE_ID}", headers=ATTACKER)
    assert resp.status_code == 200
    assert resp.json()["owner_id"] == 2  # bob 소유인데 alice 로 조회됨


def test_planted_flag_matches_manifest():
    m = load_bundle_manifest(BUNDLE)
    client = TestClient(load_fixture_app())
    resp = client.get(f"/notes/{VICTIM_NOTE_ID}", headers=ATTACKER)
    assert m.flag in resp.json()["content"]
    assert m.check_flag(m.flag)


def test_root_serves_landing_page():
    # 접속 URL 을 그냥 열면 404 대신 안내 페이지(인증 힌트 포함, 취약점은 비노출).
    client = TestClient(load_fixture_app())
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "alice-token" in resp.text
    assert "FLAG{idor" not in resp.text  # flag 는 노출 금지
