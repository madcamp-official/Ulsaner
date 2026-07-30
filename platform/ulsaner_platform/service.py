"""검증 서비스 — 챌린지 인스턴스의 수명주기와 flag 판정.

manifest 로더(계약 소비)와 오케스트레이터(Docker 배포)를 조립한다:
  스핀업(배포) → 학생에게 URL+과제 발급 → flag 제출 판정 → 시도 로깅 → TTL/teardown.

상태는 인메모리(YAGNI — 영속 저장은 비범위). 배포/정리 함수와 시계를 주입받아
Docker 없이도 로직을 테스트할 수 있게 한다.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

from orchestrator.runner import Instance, deploy_bundle, reclaim_orphans, stop_container
from ulsaner_platform.manifest import Manifest, load_bundle_manifest

DEFAULT_TTL_SECONDS = 30 * 60  # 30분
DEFAULT_MAX_ACTIVE = 8  # 동시 인스턴스 상한(로컬 데모 자원 보호). None 이면 무제한.

# 실배포는 앱이 실제로 리슨할 때까지 기다린 뒤 URL 을 준다(헬스체크).
_DEFAULT_DEPLOY = partial(deploy_bundle, wait_ready=True)

DeployFn = Callable[..., Instance]
StopFn = Callable[[str], None]
ReclaimFn = Callable[[set[str]], list[str]]
Clock = Callable[[], float]


class ChallengeError(RuntimeError):
    """검증 서비스 일반 오류."""


class ChallengeNotFound(ChallengeError):
    """존재하지 않거나 이미 정리된 챌린지에 접근."""


class CapacityError(ChallengeError):
    """동시 인스턴스 상한에 도달 — 더 스핀업할 수 없다."""


@dataclass
class SubmitResult:
    """flag 제출 판정 결과. 정답일 때만 reveal(취약점 해설)이 채워진다."""

    correct: bool
    reveal: dict | None = None

    def __bool__(self) -> bool:  # `if result:` 를 correct 로 취급(편의)
        return self.correct


@dataclass
class Attempt:
    """flag 제출 시도 한 건(통계·로깅용)."""

    challenge_id: str  # 인스턴스 uuid(스핀업마다 다름)
    challenge_name: str  # 카탈로그 슬롯 이름(easy-idor-01 등, 스핀업 간 안정) — 챌린지별 집계 키
    vuln_type: str
    tier: str
    correct: bool
    at: float


def _noop() -> None:
    """기본 정리 콜백 — fixture 처럼 정리할 임시 디렉토리가 없을 때."""


@dataclass
class ActiveChallenge:
    id: str
    manifest: Manifest
    instance: Instance
    created_at: float
    name: str = ""  # 카탈로그 슬롯 이름(챌린지별 성공 횟수 집계용)
    attempts: list[Attempt] = field(default_factory=list)
    # 엔진 생성 번들처럼 스핀업마다 임시 디렉토리를 쓰는 경우, teardown 시 호출해 정리한다.
    cleanup: Callable[[], None] = _noop


class ChallengeService:
    def __init__(
        self,
        *,
        deploy_fn: DeployFn = _DEFAULT_DEPLOY,
        stop_fn: StopFn = stop_container,
        reclaim_fn: ReclaimFn = reclaim_orphans,
        clock: Clock = time.time,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_active: int | None = DEFAULT_MAX_ACTIVE,
        public_base_url: str | None = None,
    ):
        self._deploy = deploy_fn
        self._stop = stop_fn
        self._reclaim = reclaim_fn
        self._clock = clock
        self._ttl = ttl_seconds
        self._max_active = max_active
        # 배포 환경(Cloudflare Tunnel 등)에서 컨테이너의 127.0.0.1:<port>는 학생 브라우저에서
        # 무의미하므로, 설정돼 있으면 플랫폼 자신의 공인 URL(+프록시 라우트)을 대신 준다.
        self._public_base_url = public_base_url.rstrip("/") if public_base_url else None
        self._active: dict[str, ActiveChallenge] = {}
        self._log: list[Attempt] = []  # teardown 후에도 남는 통계용 로그

    def get_host_port(self, challenge_id: str) -> int | None:
        """활성 챌린지의 호스트 포트. 없거나 이미 종료됐으면 None(프록시가 404 처리에 씀)."""
        active = self._active.get(challenge_id)
        return active.instance.host_port if active else None

    # --- 스핀업 ---------------------------------------------------------
    def spin_up(
        self,
        bundle_dir: str | Path,
        *,
        name: str = "",
        cleanup: Callable[[], None] = _noop,
    ) -> dict:
        """번들을 배포하고 학생용 뷰(challenge_id + URL + 과제)를 돌려준다.

        manifest 는 항상 ``bundle_dir/manifest.json`` 에 있다. 빌드 컨텍스트(Dockerfile 위치)는
        번들 레이아웃에 따라 다르다:
          - fixture: 루트에 Dockerfile → 컨텍스트 = bundle_dir
          - 엔진 생성 번들: app/ 안에 Dockerfile → 컨텍스트 = bundle_dir/app
        엔진 번들의 exploits/(평문 flag)는 app/ 밖에 있어 빌드 컨텍스트에 포함되지 않는다.

        cleanup 은 teardown 시 호출된다(엔진 번들의 임시 디렉토리 삭제 등).
        """
        # 만료분을 먼저 회수한 뒤에도 자리가 없으면 거절(자원 보호).
        self.sweep_expired()
        if self.at_capacity():
            raise CapacityError(
                f"동시 인스턴스 상한({self._max_active})에 도달했습니다. 잠시 후 다시 시도하세요."
            )

        bundle_dir = Path(bundle_dir)
        manifest = load_bundle_manifest(bundle_dir)
        build_context = bundle_dir if (bundle_dir / "Dockerfile").exists() else bundle_dir / "app"
        challenge_id = uuid.uuid4().hex
        try:
            instance = self._deploy(
                build_context,
                tag=f"ulsaner-{challenge_id[:12]}",
                container_port=manifest.port,
            )
        except Exception:
            cleanup()  # 배포 실패 시에도 임시 번들은 정리
            raise
        self._active[challenge_id] = ActiveChallenge(
            id=challenge_id,
            manifest=manifest,
            instance=instance,
            created_at=self._clock(),
            name=name,
            cleanup=cleanup,
        )
        return self._student_view(challenge_id)

    def _student_view(self, challenge_id: str) -> dict:
        active = self._active[challenge_id]
        view = active.manifest.public_view()  # flag/_internal 은 여기서 이미 제거됨
        view["challenge_id"] = challenge_id
        view["url"] = (
            f"{self._public_base_url}/play" if self._public_base_url else active.instance.url
        )
        return view

    # --- flag 판정 ------------------------------------------------------
    def submit_flag(self, challenge_id: str, submitted: str) -> SubmitResult:
        """제출 flag 를 판정·로깅한다. 정답이면 취약점 해설(reveal)을 담고 인스턴스를 정리한다."""
        active = self._active.get(challenge_id)
        if active is None:
            raise ChallengeNotFound(challenge_id)

        correct = active.manifest.check_flag(submitted)
        attempt = Attempt(
            challenge_id=challenge_id,
            challenge_name=active.name,
            vuln_type=active.manifest.vuln_type,
            tier=active.manifest.tier,
            correct=correct,
            at=self._clock(),
        )
        active.attempts.append(attempt)
        self._log.append(attempt)

        # 정답일 때만 해설을 만든다(teardown 으로 사라지기 전에 manifest 에서 뽑는다).
        reveal = active.manifest.reveal() if correct else None
        if correct:
            self.teardown(challenge_id)
        return SubmitResult(correct=correct, reveal=reveal)

    # --- 수명주기 -------------------------------------------------------
    def teardown(self, challenge_id: str) -> None:
        """컨테이너를 정리하고 활성 목록에서 제거한다(로그는 남는다)."""
        active = self._active.pop(challenge_id, None)
        if active is not None:
            self._stop(active.instance.container_id)
            active.cleanup()  # 임시 번들 디렉토리 등 정리(엔진 생성 번들)

    def sweep_expired(self) -> list[str]:
        """TTL 이 지난 인스턴스를 모두 teardown 하고 그 id 목록을 반환한다."""
        now = self._clock()
        expired = [
            cid for cid, active in self._active.items() if now - active.created_at >= self._ttl
        ]
        for cid in expired:
            self.teardown(cid)
        return expired

    def at_capacity(self) -> bool:
        """동시 인스턴스 상한에 도달했는지(순수 조회, sweep 하지 않음)."""
        return self._max_active is not None and len(self._active) >= self._max_active

    def reclaim_orphans(self) -> list[str]:
        """추적 중이 아닌 고아 컨테이너를 회수한다(서버 재시작·크래시 후 정리).

        현재 추적 중인 컨테이너는 보존 집합으로 넘겨 살아 있는 세션은 건드리지 않는다.
        """
        keep = {a.instance.container_id for a in self._active.values()}
        return self._reclaim(keep)

    # --- 조회 -----------------------------------------------------------
    def attempt_log(self) -> list[Attempt]:
        """모든 제출 시도 로그(대시보드 통계용). teardown 후에도 유지."""
        return list(self._log)

    def active_ids(self) -> list[str]:
        return list(self._active)
