"""번들을 Docker 컨테이너로 빌드·실행하는 오케스트레이터.

Docker 조작은 `docker` CLI 를 subprocess 로 감싼다 — 로컬이 Colima 라 소켓 위치가
표준과 다른데, CLI 는 현재 docker 컨텍스트(colima)를 자동으로 따라가 연결이 안 깨진다.

명령 실행기(runner)를 주입받게 해, docker 데몬 없이도 명령 구성·검증을 테스트할 수 있다.

구성:
  - v1-a: 빌드·실행 (build_image/run_container/stop_container)
  - v1-b: 동적 포트 + URL (get_mapped_port/instance_url/deploy_bundle)
  - 견고화: 준비 대기(wait_until_ready)·컨테이너 상태/로그·고아 회수(reclaim_orphans)·
    배포 실패 시 부분 컨테이너 정리(deploy_bundle 트랜잭셔널).
"""

from __future__ import annotations

import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]
# 준비 프로브: (host, port, timeout) -> 접속 가능하면 True.
Probe = Callable[[str, int, float], bool]

# 컨테이너는 localhost 에만 노출한다(외부 직접 접근 차단 — 설계 §11 격리).
_HOST_BIND = "127.0.0.1"
# 이 오케스트레이터가 띄운 컨테이너에만 붙이는 라벨 — 고아 회수의 안전 필터.
_MANAGED_LABEL = "ulsaner.managed=1"
# 컨테이너가 아직 살아 있다고 볼 상태들(inspect State.Status).
_LIVE_STATES = frozenset({"created", "running", "restarting"})


class OrchestratorError(RuntimeError):
    """번들 배포 중 발생한 오류(잘못된 번들, docker 실패 등)."""


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """실제 docker CLI 실행기. 실패 시 OrchestratorError 로 감싼다."""
    try:
        return subprocess.run(argv, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:  # docker 미설치
        raise OrchestratorError("docker 명령을 찾을 수 없다 (Docker/Colima 미기동?)") from exc
    except subprocess.CalledProcessError as exc:
        raise OrchestratorError(
            f"docker 명령 실패: {' '.join(argv)}\n{exc.stderr}"
        ) from exc


def build_image(bundle_dir: str | Path, tag: str, *, runner: Runner = _default_runner) -> str:
    """번들 디렉토리를 docker 이미지로 빌드한다. 빌드에 성공하면 tag 를 반환.

    학생에게 노출되는 것은 app/ 뿐이므로, 번들의 Dockerfile 이 app/ 만 담도록 하는 책임은
    번들 생성(엔진) 쪽이지만, 여기서는 최소한 Dockerfile 존재를 확인해 명확히 실패시킨다.
    """
    bundle_dir = Path(bundle_dir)
    if not bundle_dir.is_dir():
        raise OrchestratorError(f"번들 디렉토리가 없다: {bundle_dir}")
    if not (bundle_dir / "Dockerfile").is_file():
        raise OrchestratorError(f"번들에 Dockerfile 이 없다: {bundle_dir}")

    runner(["docker", "build", "-t", tag, str(bundle_dir)])
    return tag


def run_container(
    tag: str,
    *,
    name: str | None = None,
    publish_port: int | None = None,
    runner: Runner = _default_runner,
) -> str:
    """이미지를 detached 컨테이너로 실행하고 컨테이너 ID 를 반환한다.

    publish_port(컨테이너 내부 포트)를 주면 `127.0.0.1::<port>` 로 발행 →
    docker 가 **랜덤 호스트 포트**를 골라 localhost 에만 매핑한다(동적 포트 + 격리).
    """
    argv = ["docker", "run", "-d", "--label", _MANAGED_LABEL]
    if name is not None:
        argv += ["--name", name]
    if publish_port is not None:
        argv += ["-p", f"{_HOST_BIND}::{publish_port}"]
    argv.append(tag)

    result = runner(argv)
    return (result.stdout or "").strip()


def get_mapped_port(
    container_id: str, container_port: int, *, runner: Runner = _default_runner
) -> int:
    """컨테이너 내부 포트에 매핑된 호스트 포트를 조회한다.

    `docker port <cid> <port>/tcp` 는 "127.0.0.1:54321" 같은 줄을 낸다
    (ipv4/ipv6 두 줄일 수 있어 첫 줄만 파싱).
    """
    result = runner(["docker", "port", container_id, f"{container_port}/tcp"])
    lines = [ln for ln in (result.stdout or "").splitlines() if ln.strip()]
    if not lines:
        raise OrchestratorError(
            f"컨테이너 {container_id} 의 {container_port} 포트 매핑을 찾을 수 없다"
        )
    # "host:port" 의 마지막 콜론 뒤가 포트 (ipv6 [::]:port 도 안전)
    return int(lines[0].rsplit(":", 1)[1])


def instance_url(host_port: int) -> str:
    """호스트 포트로 학생 접속용 URL 을 만든다."""
    return f"http://{_HOST_BIND}:{host_port}"


@dataclass
class Instance:
    """배포된 인스턴스 핸들 — 컨테이너 ID + 접속 정보."""

    container_id: str
    host_port: int
    url: str


# --- 견고화: 상태·로그·준비 대기 ------------------------------------------

def container_state(container_id: str, *, runner: Runner = _default_runner) -> str:
    """컨테이너의 현재 상태(created/running/exited/…)를 반환한다."""
    result = runner(["docker", "inspect", "-f", "{{.State.Status}}", container_id])
    return (result.stdout or "").strip()


def container_logs(
    container_id: str, *, tail: int = 50, runner: Runner = _default_runner
) -> str:
    """컨테이너 로그 마지막 tail 줄(진단용). 실패해도 예외 대신 안내 문자열."""
    try:
        result = runner(["docker", "logs", "--tail", str(tail), container_id])
    except OrchestratorError:
        return "(로그를 가져올 수 없음)"
    return ((result.stdout or "") + (result.stderr or "")).strip()


def _http_probe(host: str, port: int, timeout: float) -> bool:
    """host:port 로 HTTP 응답이 오면(앱이 실제로 요청을 처리하면) True.

    TCP 연결만으로는 부족하다 — docker 의 포트 프록시는 컨테이너 앱이 바인딩되기 전에도
    연결을 받아버려, 아직 안 뜬 URL 을 '준비됨'으로 오판할 수 있다. HTTP 응답(상태코드가
    4xx/5xx여도 서버가 답한 것)을 준비 신호로 본다.
    """
    url = f"http://{host}:{port}/"
    try:
        with urllib.request.urlopen(url, timeout=timeout):  # localhost 고정 URL
            return True
    except urllib.error.HTTPError:
        return True  # 서버가 상태코드로 답함 = 리슨 중
    except (urllib.error.URLError, OSError):
        return False  # 연결 거부·리셋·타임아웃 = 아직 안 뜸


def wait_until_ready(
    host_port: int,
    container_id: str,
    *,
    timeout: float = 30.0,
    interval: float = 0.5,
    probe: Probe = _http_probe,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    runner: Runner = _default_runner,
) -> None:
    """앱이 실제로 요청을 받을 수 있을 때까지 기다린다(헬스체크).

    컨테이너가 떴다(run 성공)와 앱이 리슨한다는 별개다 — 학생에게 아직 안 뜬 URL 을
    주지 않도록 여기서 막는다. 대기 중 컨테이너가 조기 종료되면 로그와 함께 즉시 실패한다.
    """
    deadline = clock() + timeout
    while clock() < deadline:
        if probe(_HOST_BIND, host_port, interval):
            return
        # 아직 안 뜬 건지, 죽은 건지 구분 — 죽었으면 기다릴 이유가 없다.
        if container_state(container_id, runner=runner) not in _LIVE_STATES:
            logs = container_logs(container_id, runner=runner)
            raise OrchestratorError(
                f"컨테이너 {container_id} 가 준비 전에 종료됨. 로그:\n{logs}"
            )
        sleep(interval)
    raise OrchestratorError(
        f"컨테이너 {container_id} 가 {timeout:.0f}s 내에 준비되지 않음(헬스체크 타임아웃)"
    )


# --- 견고화: 고아 회수 ------------------------------------------------------

def list_managed(*, all_states: bool = True, runner: Runner = _default_runner) -> list[str]:
    """이 오케스트레이터가 띄운(라벨이 붙은) 컨테이너 ID 목록(full id)."""
    argv = ["docker", "ps", "-q", "--no-trunc", "--filter", f"label={_MANAGED_LABEL}"]
    if all_states:
        argv.insert(2, "-a")  # 종료된 것까지 포함
    result = runner(argv)
    return [ln.strip() for ln in (result.stdout or "").splitlines() if ln.strip()]


def reclaim_orphans(keep_ids: set[str], *, runner: Runner = _default_runner) -> list[str]:
    """추적 중이 아닌(keep_ids 에 없는) 관리 컨테이너를 정리하고 그 ID 목록을 반환한다.

    서버 크래시·TTL 누락 등으로 남은 고아 컨테이너를 회수한다. 라벨로 필터하므로
    다른 용도의 컨테이너는 절대 건드리지 않는다.
    """
    keep = set(keep_ids)
    orphans = [cid for cid in list_managed(runner=runner) if cid not in keep]
    for cid in orphans:
        try:
            stop_container(cid, runner=runner)
        except OrchestratorError:
            pass  # 이미 사라졌으면 무시(멱등)
    return orphans


def deploy_bundle(
    bundle_dir: str | Path,
    tag: str,
    container_port: int,
    *,
    name: str | None = None,
    wait_ready: bool = False,
    ready_timeout: float = 30.0,
    probe: Probe = _http_probe,
    runner: Runner = _default_runner,
) -> Instance:
    """번들을 빌드 → 실행(동적 포트) → 매핑된 URL 까지 한 번에. v1-a + v1-b 조합.

    wait_ready=True 면 앱이 실제로 리슨할 때까지 기다린 뒤 반환한다(헬스체크).
    실행 이후 단계(포트 조회·헬스체크)가 실패하면 남은 컨테이너를 정리하고 예외를
    올린다(부분 실패로 고아를 남기지 않는다 — 트랜잭셔널).
    """
    build_image(bundle_dir, tag, runner=runner)
    container_id = run_container(tag, name=name, publish_port=container_port, runner=runner)
    try:
        host_port = get_mapped_port(container_id, container_port, runner=runner)
        instance = Instance(
            container_id=container_id, host_port=host_port, url=instance_url(host_port)
        )
        if wait_ready:
            wait_until_ready(
                host_port, container_id, timeout=ready_timeout, probe=probe, runner=runner
            )
    except Exception:
        try:
            stop_container(container_id, runner=runner)
        except OrchestratorError:
            pass
        raise
    return instance


def stop_container(container_id: str, *, runner: Runner = _default_runner) -> None:
    """컨테이너를 강제 중지·삭제한다(teardown)."""
    runner(["docker", "rm", "-f", container_id])
