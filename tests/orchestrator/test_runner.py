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
    deploy_bundle,
    get_mapped_port,
    instance_url,
    run_container,
    stop_container,
)


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
