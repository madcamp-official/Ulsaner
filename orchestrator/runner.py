"""번들을 Docker 컨테이너로 빌드·실행하는 v1-a.

Docker 조작은 `docker` CLI 를 subprocess 로 감싼다 — 로컬이 Colima 라 소켓 위치가
표준과 다른데, CLI 는 현재 docker 컨텍스트(colima)를 자동으로 따라가 연결이 안 깨진다.

명령 실행기(runner)를 주입받게 해, docker 데몬 없이도 명령 구성·검증을 테스트할 수 있다.
동적 포트·URL 발급은 v1-b, 동시상한·헬스체크·회수는 이후 견고화 태스크에서 얹는다.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


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


def run_container(tag: str, *, name: str | None = None, runner: Runner = _default_runner) -> str:
    """이미지를 detached 컨테이너로 실행하고 컨테이너 ID 를 반환한다."""
    argv = ["docker", "run", "-d"]
    if name is not None:
        argv += ["--name", name]
    argv.append(tag)

    result = runner(argv)
    return (result.stdout or "").strip()


def stop_container(container_id: str, *, runner: Runner = _default_runner) -> None:
    """컨테이너를 강제 중지·삭제한다(teardown)."""
    runner(["docker", "rm", "-f", container_id])
