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
from dataclasses import dataclass
from pathlib import Path

# provision() -> (bundle_dir, cleanup)
Provision = Callable[[], tuple[Path, Callable[[], None]]]


def _noop() -> None:
    """fixture 처럼 정리할 임시 디렉토리가 없을 때의 기본 정리 콜백."""


@dataclass(frozen=True)
class _SlotSpec:
    """카탈로그 엔트리 하나 → generate_bundle 을 어떻게 부를지의 명세.

    엔진(engine.bundle)의 무거운 심볼(TICKETS_TEMPLATE_DIR·EXPLOIT_BUILDERS 등)은 여기
    담지 않고, template 선택자("notes"|"tickets")만 문자열로 둔다. 실제 엔진 심볼은
    provision() 실행 시점(=실번들 생성 시점)에만 지연 해석한다 — 플랫폼(검증 서비스·
    /stats·fixture 스핀업)이 libcst 등 엔진 임포트 경로에 묶이지 않도록.
    """

    module_path: str  # 슬롯 빌더가 있는 모듈
    builder_attr: str  # 빌더 함수명
    task_prompt: str
    solution_summary: str
    template: str = "notes"  # "notes" | "tickets" — 어떤 템플릿 앱에 주입하는가
    reorder_var_name: str = "note"  # 하드 티어 지역변수 리네임 대상(tickets 는 "ticket")
    health_check_path: str = "/notes/2"  # 자가검증 기동 대기용 헬스 경로
    seed_builder_attr: str | None = None  # engine.params 의 커스텀 seed 빌더명(하드=랜덤 id 등). None 이면 기본


# (vuln_type, tier, template) -> _SlotSpec.
# template 축을 키에 둔 이유: tickets_app 의 idor-easy/hard·sqli-easy 가 notes 의 같은
# (vuln_type, tier) 와 충돌하기 때문 — 두 번째 템플릿을 별도 카탈로그 엔트리로 노출한다.
_SLOTS: dict[tuple[str, str, str], _SlotSpec] = {
    ("idor", "easy", "notes"): _SlotSpec(
        "engine.slots.easy_idor",
        "build_easy_idor_slot",
        "당신은 bob 계정입니다 (요청 헤더 Authorization: Bearer {attacker_token}). 다른 사용자(alice)의 비공개 노트를 읽어 그 안에 심긴 flag 를 획득하세요.",
        "노트 조회에서 소유권(owner) 검증이 빠져 있어 남의 비공개 노트를 읽을 수 있다(IDOR).",
    ),
    ("idor", "hard", "notes"): _SlotSpec(
        "engine.slots.hard_idor",
        "build_hard_idor_slot",
        "당신은 bob 계정입니다 (요청 헤더 Authorization: Bearer {attacker_token}). 다른 사용자(alice)의 비공개 노트를 읽어 flag 를 획득하세요. "
        "주의: 노트 id 는 추측할 수 없는 랜덤 값이라 번호를 눌러보는 것으로는 못 찾습니다. 앱이 노출하는 정보 어딘가에서 다른 노트의 id 가 새어 나옵니다 — 그 유출 지점을 찾아 피해자 노트 id 를 알아낸 뒤 열으세요.",
        "노트 id 가 랜덤이라 열거 불가 + get_note 의 소유권 검증이 workspace 스코프로 변형됨(정적분석 회피). "
        "GET /notes 목록이 워크스페이스 전체 노트 id 를 흘리는 걸 이용해 피해자 노트 id 를 얻어 IDOR — '유출 발견 → 악용' 2단계.",
        seed_builder_attr="build_hard_seed_data",
    ),
    ("sqli", "easy", "notes"): _SlotSpec(
        "engine.slots.easy_sqli",
        "build_easy_sqli_slot",
        "노트 검색 기능(GET /notes/search?q=)에 SQL 인젝션이 있습니다. 비공개 노트에 심긴 flag 를 빼내세요.",
        "검색 쿼리가 입력을 문자열로 이어붙여 SQL 인젝션이 가능하다 — UNION 으로 비공개 노트 본문 유출.",
    ),
    ("hard_sqli", "hard", "notes"): _SlotSpec(
        "engine.slots.hard_sqli",
        "build_hard_sqli_slot",
        "고급 검색(GET /notes/search/advanced)의 exclude 파라미터로 비공개 노트 본문을 유출해 flag 를 찾으세요.",
        "exclude 값이 파라미터 바인딩처럼 보이지만 실제로는 문자열 보간된다(prepared statement 위장) — UNION 인젝션으로 유출.",
    ),
    ("xss", "easy", "notes"): _SlotSpec(
        "engine.slots.xss",
        "build_xss_slot",
        "검색 결과 페이지(GET /notes/search/view)에 검색어가 이스케이프 없이 반사됩니다. <script> 페이로드가 원문 그대로 반영됨을 증명하세요(반사형 XSS).",
        "search_notes_view 가 검색어 q 를 html.escape 없이 HTML 에 삽입 — <script> 페이로드가 그대로 반사된다.",
    ),
    ("idor", "easy", "tickets"): _SlotSpec(
        "engine.slots.tickets",
        "build_tickets_easy_idor_slot",
        "당신은 bob 계정입니다 (요청 헤더 X-User-Token: {attacker_token}). 다른 사용자(alice)의 기밀 티켓(description)을 읽어 그 안에 심긴 flag 를 획득하세요.",
        "티켓 조회에서 소유권(owner) 검증이 빠져 있어 남의 기밀 티켓을 읽을 수 있다(IDOR · 2번째 템플릿).",
        template="tickets",
        reorder_var_name="ticket",
        health_check_path="/tickets/2",
    ),
    ("idor", "hard", "tickets"): _SlotSpec(
        "engine.slots.tickets",
        "build_tickets_hard_idor_slot",
        "당신은 bob 계정입니다 (요청 헤더 X-User-Token: {attacker_token}). 다른 사용자(alice)의 기밀 티켓(description)을 읽어 그 안에 심긴 flag 를 획득하세요.",
        "소유권 비교가 workspace 스코프로 뒤바뀌어 같은 workspace 면 통과되는 IDOR(하드 · 2번째 템플릿).",
        template="tickets",
        reorder_var_name="ticket",
        health_check_path="/tickets/2",
    ),
    ("sqli", "easy", "tickets"): _SlotSpec(
        "engine.slots.tickets",
        "build_tickets_easy_sqli_slot",
        "티켓 검색(GET /tickets/search?q=)에 SQL 인젝션이 있습니다. 비공개 티켓에 심긴 flag 를 빼내세요.",
        "검색 쿼리가 입력을 문자열로 이어붙여 SQL 인젝션이 가능하다 — UNION 으로 기밀 티켓 본문 유출(2번째 템플릿).",
        template="tickets",
        reorder_var_name="ticket",
        health_check_path="/tickets/2",
    ),
}


def fixture_source(bundle_dir: str | Path) -> Provision:
    """정적 fixture 번들을 그대로 배포하는 소스(정리할 것 없음)."""
    resolved = Path(bundle_dir)

    def provision() -> tuple[Path, Callable[[], None]]:
        return resolved, _noop

    return provision


def engine_source(vuln_type: str, tier: str, *, template: str = "notes") -> Provision:
    """스핀업마다 엔진으로 새 번들을 생성하는 소스(인스턴스별 랜덤 flag).

    generate_bundle 은 스스로 컨테이너를 빌드·실행해 레퍼런스 익스플로잇으로 자가검증한
    뒤에만 번들을 반환한다(엔진의 출하 게이트). 따라서 provision() 은 Docker 를 필요로 하고
    수십 초가 걸릴 수 있다.

    template("notes"|"tickets")로 어떤 템플릿 앱을 쓸지 고른다 — 기본 notes 라 기존 2-인자
    호출부(idor/sqli notes)는 그대로 동작한다(하위호환).
    """
    key = (vuln_type, tier, template)
    if key not in _SLOTS:
        raise KeyError(f"지원하지 않는 챌린지 조합: {vuln_type}/{tier}/{template}")
    spec = _SLOTS[key]

    def provision() -> tuple[Path, Callable[[], None]]:
        # 엔진은 실제 생성 시점에만 임포트(무거운 libcst 등을 플랫폼 임포트 경로에서 분리).
        from engine.bundle import (
            TICKETS_EXPLOIT_BUILDERS,
            TICKETS_TEMPLATE_DIR,
            generate_bundle,
        )

        slot_builder = getattr(importlib.import_module(spec.module_path), spec.builder_attr)

        # generate_bundle 오버라이드: notes 는 전부 기본값이라 손대지 않고, tickets 만
        # 다른 템플릿·익스플로잇 빌더·시드 빌더를 붙인다(엔진 테스트 _generate_tickets_bundle 과 동일).
        kwargs: dict = {
            "reorder_var_name": spec.reorder_var_name,
            "health_check_path": spec.health_check_path,
        }
        if spec.template == "tickets":
            from engine import tickets_params

            kwargs["template_dir"] = TICKETS_TEMPLATE_DIR
            kwargs["exploit_builders"] = TICKETS_EXPLOIT_BUILDERS
            kwargs["seed_data_builder"] = tickets_params.build_seed_data
        if spec.seed_builder_attr:
            # 하드 IDOR 등 커스텀 seed(랜덤 id)를 engine.params 에서 지연 해석해 넘긴다.
            from engine import params

            kwargs["seed_data_builder"] = getattr(params, spec.seed_builder_attr)

        tmp = Path(tempfile.mkdtemp(prefix="ulsaner-bundle-"))

        def cleanup() -> None:
            shutil.rmtree(tmp, ignore_errors=True)

        try:
            generate_bundle(
                seed=secrets.randbelow(2**31),  # 매번 랜덤 → 인스턴스마다 다른 flag
                output_dir=tmp,
                slot_builder=slot_builder,
                task_prompt=spec.task_prompt,
                solution_summary=spec.solution_summary,
                **kwargs,
            )
        except BaseException:
            cleanup()  # 생성 실패 시 임시 디렉토리 즉시 정리
            raise
        return tmp, cleanup

    return provision
