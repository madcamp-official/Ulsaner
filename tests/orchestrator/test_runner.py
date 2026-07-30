"""오케스트레이터 v1-a — 번들 빌드·실행 (단일 컨테이너) 유닛 테스트.

docker 를 실제로 돌리지 않고, (1) 잘못된 번들 거부 (2) docker 명령을 올바르게
구성하는지 를 검증한다. 실제 빌드·실행은 test_runner_integration.py(@integration).
runner(=명령 실행기)를 주입받게 설계해 docker 데몬 없이도 테스트한다.
"""

import subprocess

import pytest

from orchestrator.runner import (
    Instance,
    OrchestratorError,
    build_image,
    container_logs,
    container_state,
    deploy_bundle,
    get_mapped_port,
    instance_url,
    list_managed,
    reclaim_orphans,
    run_container,
    stop_container,
    wait_until_ready,
)


class ScriptRunner:
    """docker 하위명령(argv[1])별로 지정한 stdout 을 돌려주는 가짜 실행기.

    fail_on 에 든 하위명령은 OrchestratorError 를 던진다(실패 경로 테스트).
    """

    def __init__(self, outputs: dict | None = None, fail_on=None):
        self.calls: list[list[str]] = []
        self.outputs = outputs or {}
        self.fail_on = set(fail_on or [])

    def __call__(self, argv):
        self.calls.append(argv)
        verb = argv[1]
        if verb in self.fail_on:
            raise OrchestratorError(f"boom: {verb}")
        return subprocess.CompletedProcess(
            argv, 0, stdout=self.outputs.get(verb, ""), stderr=""
        )

    def verbs(self) -> list[str]:
        return [c[1] for c in self.calls]


class FakeRunner:
    """docker CLI 를 실제로 부르지 않고 argv 를 기록하는 가짜 실행기."""

    def __init__(self, stdout: str = ""):
        self.calls: list[list[str]] = []
        self._stdout = stdout

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess:
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=self._stdout, stderr="")


def test_build_image_rejects_dir_without_dockerfile(tmp_path):
    # Dockerfile 이 없으면 docker 를 부르기 전에 명확히 거부해야 한다.
    fake = FakeRunner()
    with pytest.raises(OrchestratorError):
        build_image(tmp_path, "tag", runner=fake)
    assert fake.calls == []  # docker 를 부르지도 않았어야 함


def test_build_image_rejects_missing_dir(tmp_path):
    with pytest.raises(OrchestratorError):
        build_image(tmp_path / "does-not-exist", "tag", runner=FakeRunner())


def test_build_image_runs_docker_build_with_tag_and_context(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    fake = FakeRunner()

    tag = build_image(tmp_path, "ulsaner-test:latest", runner=fake)

    assert tag == "ulsaner-test:latest"
    assert fake.calls == [["docker", "build", "-t", "ulsaner-test:latest", str(tmp_path)]]


def test_run_container_returns_container_id():
    fake = FakeRunner(stdout="abc123def456\n")

    cid = run_container("ulsaner-test:latest", runner=fake)

    assert cid == "abc123def456"  # stdout 의 컨테이너 ID, 공백 제거
    argv = fake.calls[0]
    assert argv[:3] == ["docker", "run", "-d"]  # detached
    assert argv[-1] == "ulsaner-test:latest"  # 마지막은 이미지 태그


def test_run_container_includes_name_when_given():
    fake = FakeRunner(stdout="cid\n")

    run_container("img", name="inst-1", runner=fake)

    argv = fake.calls[0]
    assert "--name" in argv
    assert "inst-1" in argv


def test_stop_container_force_removes_by_id():
    fake = FakeRunner()

    stop_container("abc123", runner=fake)

    assert fake.calls == [["docker", "rm", "-f", "abc123"]]


# --- v1-b: 동적 포트 + URL -------------------------------------------------

class ArgvRunner:
    """argv 내용에 따라 다른 stdout 을 돌려주는 가짜 실행기 (deploy 조합 테스트용)."""

    def __init__(self, *, run_stdout="cid123\n", port_stdout="127.0.0.1:54321\n"):
        self.calls: list[list[str]] = []
        self._run_stdout = run_stdout
        self._port_stdout = port_stdout

    def __call__(self, argv):
        self.calls.append(argv)
        out = ""
        if "run" in argv:
            out = self._run_stdout
        elif "port" in argv:
            out = self._port_stdout
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")


def test_run_container_publishes_dynamic_localhost_port():
    fake = FakeRunner(stdout="cid\n")

    run_container("img", publish_port=8000, runner=fake)

    argv = fake.calls[0]
    assert "-p" in argv
    # 127.0.0.1:: 로 바인딩 → 호스트 랜덤 포트, localhost 에만 노출(격리)
    assert "127.0.0.1::8000" in argv


def test_get_mapped_port_parses_host_port():
    fake = FakeRunner(stdout="127.0.0.1:54321\n")

    port = get_mapped_port("cid", 8000, runner=fake)

    assert port == 54321
    assert fake.calls[0] == ["docker", "port", "cid", "8000/tcp"]


def test_get_mapped_port_handles_multiline_output():
    # docker 가 ipv4/ipv6 두 줄을 낼 수 있다.
    fake = FakeRunner(stdout="0.0.0.0:49155\n[::]:49155\n")

    assert get_mapped_port("cid", 8000, runner=fake) == 49155


def test_instance_url_builds_localhost_url():
    assert instance_url(54321) == "http://127.0.0.1:54321"


def test_deploy_bundle_builds_runs_and_reports_instance(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    fake = ArgvRunner(run_stdout="abc999\n", port_stdout="127.0.0.1:60001\n")

    inst = deploy_bundle(tmp_path, "ulsaner-x:latest", container_port=8000, runner=fake)

    assert isinstance(inst, Instance)
    assert inst.container_id == "abc999"
    assert inst.host_port == 60001
    assert inst.url == "http://127.0.0.1:60001"
    # build → run → port 순서로 docker 를 불렀는지
    verbs = [c[1] for c in fake.calls]
    assert verbs == ["build", "run", "port"]


# --- 견고화: 라벨·상태·로그 -------------------------------------------------

def test_run_container_tags_managed_label():
    # 고아 회수의 안전 필터 — 우리가 띄운 컨테이너에만 라벨을 붙인다.
    fake = FakeRunner(stdout="cid\n")
    run_container("img", runner=fake)
    argv = fake.calls[0]
    assert "--label" in argv
    assert "ulsaner.managed=1" in argv


def test_container_state_parses_inspect():
    fake = ScriptRunner(outputs={"inspect": "running\n"})
    assert container_state("cid", runner=fake) == "running"
    assert fake.calls[0] == ["docker", "inspect", "-f", "{{.State.Status}}", "cid"]


def test_container_logs_combines_streams_and_survives_failure():
    ok = ScriptRunner(outputs={"logs": "boot ok\n"})
    assert "boot ok" in container_logs("cid", runner=ok)
    dead = ScriptRunner(fail_on=["logs"])
    assert container_logs("cid", runner=dead) == "(로그를 가져올 수 없음)"


# --- 견고화: 준비 대기(헬스체크) -------------------------------------------

def _clock_seq(values):
    it = iter(values)
    return lambda: next(it)


def test_wait_until_ready_returns_when_probe_succeeds():
    fake = ScriptRunner()
    wait_until_ready(
        60001, "cid", timeout=5, probe=lambda h, p, t: True,
        sleep=lambda _: None, clock=_clock_seq([0, 0.1]), runner=fake,
    )
    # 프로브가 바로 통과하면 inspect 조차 부르지 않는다.
    assert fake.calls == []


def test_wait_until_ready_raises_on_timeout_while_still_alive():
    fake = ScriptRunner(outputs={"inspect": "running\n"})
    with pytest.raises(OrchestratorError, match="타임아웃"):
        wait_until_ready(
            60001, "cid", timeout=1.0, probe=lambda h, p, t: False,
            sleep=lambda _: None, clock=_clock_seq([0, 0.3, 0.6, 1.5]), runner=fake,
        )


def test_wait_until_ready_fails_fast_when_container_exits():
    # 앱이 뜨기 전에 컨테이너가 죽으면 기다리지 말고 로그와 함께 즉시 실패.
    fake = ScriptRunner(outputs={"inspect": "exited\n", "logs": "Traceback: boom\n"})
    with pytest.raises(OrchestratorError, match="종료"):
        wait_until_ready(
            60001, "cid", timeout=5, probe=lambda h, p, t: False,
            sleep=lambda _: None, clock=_clock_seq([0, 0.3]), runner=fake,
        )


# --- 견고화: 고아 회수 ------------------------------------------------------

def test_list_managed_filters_by_label_including_stopped():
    fake = ScriptRunner(outputs={"ps": "aaa\nbbb\n"})
    ids = list_managed(runner=fake)
    assert ids == ["aaa", "bbb"]
    argv = fake.calls[0]
    assert argv[:3] == ["docker", "ps", "-a"]  # 종료된 것까지
    assert "--no-trunc" in argv  # full id 로 추적 id 와 비교 가능하게
    assert "label=ulsaner.managed=1" in argv


def test_reclaim_orphans_removes_only_untracked_managed():
    fake = ScriptRunner(outputs={"ps": "keepme\norphan1\norphan2\n"})
    removed = reclaim_orphans({"keepme"}, runner=fake)
    assert removed == ["orphan1", "orphan2"]
    # keep 은 건드리지 않고, 고아 2개만 rm.
    rm_targets = [c[-1] for c in fake.calls if c[1] == "rm"]
    assert rm_targets == ["orphan1", "orphan2"]


# --- 견고화: deploy_bundle 트랜잭셔널 + 헬스체크 ---------------------------

def test_deploy_bundle_cleans_up_container_on_port_failure(tmp_path):
    # run 은 됐지만 포트 조회가 실패하면 → 남은 컨테이너를 정리하고 예외를 올린다.
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    fake = ScriptRunner(outputs={"run": "leaked-cid\n", "port": ""})  # port 빈 출력 → 실패
    with pytest.raises(OrchestratorError):
        deploy_bundle(tmp_path, "tag", container_port=8000, runner=fake)
    # 고아를 남기지 않도록 rm 이 불렸는지
    rm_targets = [c[-1] for c in fake.calls if c[1] == "rm"]
    assert rm_targets == ["leaked-cid"]


def test_deploy_bundle_waits_for_readiness_when_requested(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    fake = ScriptRunner(outputs={"run": "cid\n", "port": "127.0.0.1:60002\n"})
    inst = deploy_bundle(
        tmp_path, "tag", container_port=8000, wait_ready=True,
        probe=lambda h, p, t: True, runner=fake,
    )
    assert inst.host_port == 60002
    assert fake.verbs() == ["build", "run", "port"]  # 프로브 통과 → inspect 불필요
