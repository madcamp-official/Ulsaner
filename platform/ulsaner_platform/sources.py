"""챌린지 번들 소스 — 스핀업 때 배포할 번들을 어디서 얻을지 추상화한다.

두 종류:
  - fixture_source: 손으로 만든 정적 번들(고정 flag). 테스트·데모 기준.
  - engine_source: 엔진(engine.bundle.generate_bundle)이 **스핀업마다** 새로 생성하는
    실번들. 시드가 매번 랜덤이라 인스턴스마다 flag 가 다르다 — thesis("정답을 찾아볼 수
    없다")를 실현하는 경로.

소스는 provision() 콜러블이다: 호출하면 ``(bundle_dir, cleanup)`` 를 돌려준다.
  - bundle_dir: manifest.json 이 있는 번들 루트(ChallengeService.spin_up 에 그대로 넘김).
  - cleanup: teardown 시 호출할 정리 콜백(엔진 번들의 임시 디렉토리 삭제).

보안(CLAUDE.md): 엔진 번들에는 exploits/reference.json(평문 flag·공격자 토큰)이 들어 있다.
빌드 컨텍스트는 bundle_dir/app 뿐이라 exploits/ 는 컨테이너 이미지에 포함되지 않으며,
번들 디렉토리 자체도 정적으로 노출하지 않는다(HTTP 로는 이름으로만 스핀업 가능).
"""

from __future__ import annotations

import importlib
import secrets
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

# provision() -> (bundle_dir, cleanup)
Provision = Callable[[], tuple[Path, Callable[[], None]]]


def _noop() -> None:
    """fixture 처럼 정리할 임시 디렉토리가 없을 때의 기본 정리 콜백."""


# (vuln_type, tier) -> (슬롯 빌더가 있는 모듈, 빌더 함수명, task_prompt, solution_summary).
# 엔진(libcst 등 무거운 AST 툴체인)은 여기서 임포트하지 않고, 실제로 실번들을 생성할 때만
# 지연 임포트한다 — 플랫폼(검증 서비스·/stats·fixture 스핀업)이 엔진 임포트에 묶이지 않도록.
_SLOTS: dict[tuple[str, str], tuple[str, str, str, str]] = {
    ("idor", "easy"): (
        "engine.slots.easy_idor",
        "build_easy_idor_slot",
        "당신은 alice 계정입니다. 다른 사용자의 비공개 노트를 읽어 그 안에 심긴 flag 를 획득하세요.",
        "노트 조회에서 소유권(owner) 검증이 빠져 있어 남의 비공개 노트를 읽을 수 있다(IDOR).",
    ),
    ("idor", "hard"): (
        "engine.slots.hard_idor",
        "build_hard_idor_slot",
        "당신은 alice 계정입니다. 다른 사용자의 비공개 노트를 읽어 그 안에 심긴 flag 를 획득하세요.",
        "소유권 비교 로직이 변형돼 정적분석으로는 잘 안 잡히는 IDOR(하드 티어).",
    ),
    ("sqli", "easy"): (
        "engine.slots.easy_sqli",
        "build_easy_sqli_slot",
        "노트 검색 기능(GET /notes/search?q=)에 SQL 인젝션이 있습니다. 비공개 노트에 심긴 flag 를 빼내세요.",
        "검색 쿼리가 입력을 문자열로 이어붙여 SQL 인젝션이 가능하다 — UNION 으로 비공개 노트 본문 유출.",
    ),
}


def fixture_source(bundle_dir: str | Path) -> Provision:
    """정적 fixture 번들을 그대로 배포하는 소스(정리할 것 없음)."""
    resolved = Path(bundle_dir)

    def provision() -> tuple[Path, Callable[[], None]]:
        return resolved, _noop

    return provision


def engine_source(vuln_type: str, tier: str) -> Provision:
    """스핀업마다 엔진으로 새 번들을 생성하는 소스(인스턴스별 랜덤 flag).

    generate_bundle 은 스스로 컨테이너를 빌드·실행해 레퍼런스 익스플로잇으로 자가검증한
    뒤에만 번들을 반환한다(엔진의 출하 게이트). 따라서 provision() 은 Docker 를 필요로 하고
    수십 초가 걸릴 수 있다.
    """
    if (vuln_type, tier) not in _SLOTS:
        raise KeyError(f"지원하지 않는 챌린지 조합: {vuln_type}/{tier}")
    module_path, builder_attr, task_prompt, solution_summary = _SLOTS[(vuln_type, tier)]

    def provision() -> tuple[Path, Callable[[], None]]:
        # 엔진은 실제 생성 시점에만 임포트(무거운 libcst 등을 플랫폼 임포트 경로에서 분리).
        from engine.bundle import generate_bundle

        slot_builder = getattr(importlib.import_module(module_path), builder_attr)

        tmp = Path(tempfile.mkdtemp(prefix="ulsaner-bundle-"))

        def cleanup() -> None:
            shutil.rmtree(tmp, ignore_errors=True)

        try:
            generate_bundle(
                seed=secrets.randbelow(2**31),  # 매번 랜덤 → 인스턴스마다 다른 flag
                output_dir=tmp,
                slot_builder=slot_builder,
                task_prompt=task_prompt,
                solution_summary=solution_summary,
            )
        except BaseException:
            cleanup()  # 생성 실패 시 임시 디렉토리 즉시 정리
            raise
        return tmp, cleanup

    return provision
