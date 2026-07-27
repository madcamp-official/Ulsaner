"""검증 서비스(ChallengeService) 유닛 테스트.

이 서비스는 manifest 로더 + 오케스트레이터를 조립한다:
스핀업(배포) → 학생에게 URL+과제 발급 → flag 제출 판정 → 로깅 → TTL/teardown.

Docker 를 실제로 안 띄우려고 배포/정리 함수와 시계(clock)를 주입받게 설계했다.
manifest 는 진짜 fixture 를 읽어(load_bundle_manifest) 계약대로 동작하는지 본다.
"""

from pathlib import Path

import pytest
from ulsaner_platform.service import (
    CapacityError,
    ChallengeNotFound,
    ChallengeService,
)

from orchestrator.runner import Instance

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "platform" / "fixtures" / "easy-idor-01"
FLAG = "FLAG{idor_bob_private_2f9c}"  # fixture 의 정답


class FakeDeployer:
    """deploy_bundle 대역 — Docker 없이 가짜 Instance 를 돌려준다."""

    def __init__(self):
        self.calls = []

    def __call__(self, bundle_dir, *, tag, container_port):
        self.calls.append({"bundle_dir": Path(bundle_dir), "tag": tag, "container_port": container_port})
        return Instance(container_id=f"cont-{tag}", host_port=55000, url="http://127.0.0.1:55000")


class FakeStopper:
    def __init__(self):
        self.stopped = []

    def __call__(self, container_id):
        self.stopped.append(container_id)


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


def make_service(ttl_seconds=1800):
    return ChallengeService(
        deploy_fn=FakeDeployer(),
        stop_fn=FakeStopper(),
        clock=FakeClock(),
        ttl_seconds=ttl_seconds,
    )


# --- 스핀업 ---------------------------------------------------------------

def test_spin_up_returns_student_view_without_secrets():
    svc = make_service()
    view = svc.spin_up(FIXTURE)

    assert "challenge_id" in view
    assert view["url"] == "http://127.0.0.1:55000"
    assert view["vuln_type"] == "idor"
    assert view["entry"]["task_prompt"]  # 과제 프롬프트 노출
    # 비밀은 절대 노출 금지
    assert "flag" not in view
    assert "_internal" not in view


def test_spin_up_deploys_with_manifest_port():
    deployer = FakeDeployer()
    svc = ChallengeService(deploy_fn=deployer, stop_fn=FakeStopper(), clock=FakeClock())
    svc.spin_up(FIXTURE)
    assert deployer.calls[0]["container_port"] == 8000  # fixture manifest.entry.port


# --- flag 판정 ------------------------------------------------------------

def test_submit_correct_flag_returns_true():
    svc = make_service()
    view = svc.spin_up(FIXTURE)
    assert svc.submit_flag(view["challenge_id"], FLAG) is True


def test_submit_wrong_flag_returns_false():
    svc = make_service()
    view = svc.spin_up(FIXTURE)
    assert svc.submit_flag(view["challenge_id"], "FLAG{nope}") is False


def test_submit_to_unknown_challenge_raises():
    svc = make_service()
    with pytest.raises(ChallengeNotFound):
        svc.submit_flag("does-not-exist", FLAG)


# --- teardown / 로깅 / TTL -------------------------------------------------

def test_solving_tears_down_the_instance():
    stopper = FakeStopper()
    svc = ChallengeService(deploy_fn=FakeDeployer(), stop_fn=stopper, clock=FakeClock())
    view = svc.spin_up(FIXTURE)

    svc.submit_flag(view["challenge_id"], FLAG)  # 정답 → teardown

    assert len(stopper.stopped) == 1  # 컨테이너가 정리됨
    # 푼 챌린지에 다시 제출은 거부
    with pytest.raises(ChallengeNotFound):
        svc.submit_flag(view["challenge_id"], FLAG)


def test_attempt_records_challenge_name_for_per_slot_stats():
    svc = make_service()
    view = svc.spin_up(FIXTURE, name="easy-idor-01")
    svc.submit_flag(view["challenge_id"], "FLAG{nope}")
    svc.submit_flag(view["challenge_id"], FLAG)
    log = svc.attempt_log()
    assert [a.challenge_name for a in log] == ["easy-idor-01", "easy-idor-01"]


def test_attempts_are_logged_for_stats():
    svc = make_service()
    view = svc.spin_up(FIXTURE)
    svc.submit_flag(view["challenge_id"], "FLAG{wrong1}")
    svc.submit_flag(view["challenge_id"], "FLAG{wrong2}")
    svc.submit_flag(view["challenge_id"], FLAG)

    log = svc.attempt_log()
    assert len(log) == 3
    assert [a.correct for a in log] == [False, False, True]


def test_sweep_expired_tears_down_old_instances_only():
    deployer = FakeDeployer()
    stopper = FakeStopper()
    clock = FakeClock(now=1000.0)
    svc = ChallengeService(deploy_fn=deployer, stop_fn=stopper, clock=clock, ttl_seconds=600)

    old = svc.spin_up(FIXTURE)  # created at t=1000
    clock.now = 1500.0
    fresh = svc.spin_up(FIXTURE)  # created at t=1500
    clock.now = 1700.0  # old 은 700s 경과(>600 만료), fresh 는 200s

    expired = svc.sweep_expired()

    assert old["challenge_id"] in expired
    assert fresh["challenge_id"] not in expired
    assert stopper.stopped == [f"cont-ulsaner-{old['challenge_id'][:12]}"]


# --- 견고화: 동시 상한 -----------------------------------------------------

def test_spin_up_rejects_when_at_capacity():
    svc = ChallengeService(
        deploy_fn=FakeDeployer(), stop_fn=FakeStopper(), clock=FakeClock(), max_active=1
    )
    svc.spin_up(FIXTURE)  # 1개 → 상한 도달
    with pytest.raises(CapacityError):
        svc.spin_up(FIXTURE)


def test_capacity_frees_after_teardown():
    svc = ChallengeService(
        deploy_fn=FakeDeployer(), stop_fn=FakeStopper(), clock=FakeClock(), max_active=1
    )
    view = svc.spin_up(FIXTURE)
    svc.teardown(view["challenge_id"])  # 자리 반납
    svc.spin_up(FIXTURE)  # 다시 스핀업 가능(예외 없음)
    assert len(svc.active_ids()) == 1


def test_expired_instance_frees_capacity_on_spin_up():
    # 상한이 꽉 차도, 스핀업 시 만료분을 먼저 회수하면 자리가 난다.
    clock = FakeClock(now=1000.0)
    svc = ChallengeService(
        deploy_fn=FakeDeployer(), stop_fn=FakeStopper(),
        clock=clock, ttl_seconds=600, max_active=1,
    )
    svc.spin_up(FIXTURE)  # t=1000
    clock.now = 2000.0  # 1000s 경과(>600 만료)
    svc.spin_up(FIXTURE)  # 만료분 회수 후 스핀업 성공
    assert len(svc.active_ids()) == 1


# --- 견고화: 고아 회수 -----------------------------------------------------

def test_reclaim_orphans_preserves_active_containers():
    captured = {}

    def fake_reclaim(keep_ids):
        captured["keep"] = set(keep_ids)
        return ["orphan-x"]

    svc = ChallengeService(
        deploy_fn=FakeDeployer(), stop_fn=FakeStopper(),
        reclaim_fn=fake_reclaim, clock=FakeClock(),
    )
    view = svc.spin_up(FIXTURE)

    removed = svc.reclaim_orphans()

    assert removed == ["orphan-x"]
    # 살아있는 세션의 컨테이너는 보존 집합에 포함되어 회수 대상이 아니다.
    assert f"cont-ulsaner-{view['challenge_id'][:12]}" in captured["keep"]
