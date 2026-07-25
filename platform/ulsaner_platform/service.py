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
from pathlib import Path

from orchestrator.runner import Instance, deploy_bundle, stop_container
from ulsaner_platform.manifest import Manifest, load_bundle_manifest

DEFAULT_TTL_SECONDS = 30 * 60  # 30분

DeployFn = Callable[..., Instance]
StopFn = Callable[[str], None]
Clock = Callable[[], float]


class ChallengeError(RuntimeError):
    """검증 서비스 일반 오류."""


class ChallengeNotFound(ChallengeError):
    """존재하지 않거나 이미 정리된 챌린지에 접근."""


@dataclass
class Attempt:
    """flag 제출 시도 한 건(통계·로깅용)."""

    challenge_id: str
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
    attempts: list[Attempt] = field(default_factory=list)
    # 엔진 생성 번들처럼 스핀업마다 임시 디렉토리를 쓰는 경우, teardown 시 호출해 정리한다.
    cleanup: Callable[[], None] = _noop


class ChallengeService:
    def __init__(
        self,
        *,
        deploy_fn: DeployFn = deploy_bundle,
        stop_fn: StopFn = stop_container,
        clock: Clock = time.time,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
    ):
        self._deploy = deploy_fn
        self._stop = stop_fn
        self._clock = clock
        self._ttl = ttl_seconds
        self._active: dict[str, ActiveChallenge] = {}
        self._log: list[Attempt] = []  # teardown 후에도 남는 통계용 로그

    # --- 스핀업 ---------------------------------------------------------
    def spin_up(
        self,
        bundle_dir: str | Path,
        *,
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
            cleanup=cleanup,
        )
        return self._student_view(challenge_id)

    def _student_view(self, challenge_id: str) -> dict:
        active = self._active[challenge_id]
        view = active.manifest.public_view()  # flag/_internal 은 여기서 이미 제거됨
        view["challenge_id"] = challenge_id
        view["url"] = active.instance.url
        return view

    # --- flag 판정 ------------------------------------------------------
    def submit_flag(self, challenge_id: str, submitted: str) -> bool:
        """제출 flag 를 판정하고 로깅한다. 정답이면 인스턴스를 정리(teardown)."""
        active = self._active.get(challenge_id)
        if active is None:
            raise ChallengeNotFound(challenge_id)

        correct = active.manifest.check_flag(submitted)
        attempt = Attempt(
            challenge_id=challenge_id,
            vuln_type=active.manifest.vuln_type,
            tier=active.manifest.tier,
            correct=correct,
            at=self._clock(),
        )
        active.attempts.append(attempt)
        self._log.append(attempt)

        if correct:
            self.teardown(challenge_id)
        return correct

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

    # --- 조회 -----------------------------------------------------------
    def attempt_log(self) -> list[Attempt]:
        """모든 제출 시도 로그(대시보드 통계용). teardown 후에도 유지."""
        return list(self._log)

    def active_ids(self) -> list[str]:
        return list(self._active)
