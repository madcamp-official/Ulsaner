# VibeCutter 벤치마크 실행 가이드

"자동도구(VibeCutter) vs 사람" 성공률 비교에서 **자동도구 쪽 숫자**를 만드는 절차다.
하네스는 `engine/vibecutter_bench.py` 하나(gen/audit 두 서브커맨드)이고, 결과 JSON을
`platform/data/vibecutter_result.json`에 쓰면 대시보드(`/dashboard`)가 이를
`ulsaner_platform.app._load_vibecutter`로 읽어 자동으로 채운다.

> 이 문서는 예전 inline-heredoc `engine.bundle.generate_bundle` 기반 워크플로우(Docker
> 자가검증, git-repo 타깃, 대화형 MCP 승인 흐름)를 **벤치마킹 목적으로 대체**한다. 자세한
> 배경(왜 VibeCutter가 `--target <dir>` 배치 CLI가 아니라 대화형 MCP 서버인지, 왜
> `engine.benchmark.run_external_auditor`의 제네릭 exit-code 방식이 안 맞는지)은
> `engine/vibecutter_config.py`의 모듈 docstring에 여전히 문서화되어 있다 — 이 문서는
> 그 대신 실제로 동작하는 2단계 배치 하네스만 다룬다.

## 개요

`engine/vibecutter_bench.py`는 seed별 취약앱 생성(Phase 1) → VibeCutter 감사 + Ulsaner
레퍼런스 익스플로잇으로 독립 ground truth 확인(Phase 2) → 결과 JSON 저장을 담당하는
단일 모듈/두 서브커맨드(`gen`, `audit`) 하네스다. 두 단계는 의존성이 상호 배타적이라
**서로 다른 파이썬 인터프리터**에서 실행해야 한다(gen=Ulsaner `.venv`, audit=VibeCutter
자체 venv). 그래서 이 파일은 단일 진입점이되, VibeCutter 관련 import는 `cmd_audit` 내부에,
engine 관련 import는 `generate_apps`/`cmd_gen` 내부에 지연(lazy) 배치되어 있다 — 모듈
최상단은 표준 라이브러리만 import 한다.

## 사전준비

**Phase 1 (gen) — Ulsaner 쪽:**
- 이 저장소의 `.venv` (libcst + `engine` 패키지가 설치되어 있으면 충분). 별도 설정 불필요.

**Phase 2 (audit) — VibeCutter 쪽:**
- VibeCutter(https://github.com/madcamp-official/VibeCutter)를 **별도 경로에 클론**하고
  자체 venv를 만들어 `requirements.txt`를 설치해야 한다.
- `docs/vibecutter-patches/idor-prefilter-authz-blindspot.patch`를 그 클론에 적용해야
  한다(IDOR prefilter의 인가맹점 수정 — 이게 없으면 `success_rate`가 아닌
  `success_rate_stock`만 의미 있는 숫자가 된다).
- 감사 대상 앱을 실제로 띄울 **타겟별 venv**(uvicorn + 앱 의존성)의 인터프리터 경로가
  하나 더 필요하다(`VCVENV_PY`).
- `vibecutter_bench.py`의 `_DEFAULT_VC_ROOT`/`_DEFAULT_VCVENV_PY`는 **팀원 개인 머신의
  절대경로**라 다른 환경에서는 반드시 안 맞는다 — 정상 사용은 항상 `VC_ROOT`/`VCVENV_PY`
  환경변수로 덮어쓰는 것이다.

## Phase 1 — 취약앱 생성 (Ulsaner venv, 저장소 루트에서)

```bash
ULSANER_ROOT="$(pwd)" .venv/bin/python -m engine.vibecutter_bench gen <workdir> \
    [--classes idor-easy,idor-hard,sqli-easy,sqli-hard] [--seeds-per-class N]
```

- `<workdir>`: 생성된 앱들과 `index.json`이 놓일 작업 디렉토리.
- `--classes`: 쉼표구분 클래스 목록. 기본값은 4개 클래스 전부
  (`idor-easy,idor-hard,sqli-easy,sqli-hard`).
- `--seeds-per-class`: 클래스당 seed 개수 (기본 5).

## Phase 2 — VibeCutter 감사 (VibeCutter venv, 아무 cwd에서 절대경로 스크립트로)

```bash
VC_ROOT=/path/to/VibeCutter VCVENV_PY=/path/to/target/.vcvenv/bin/python \
    "$VC_ROOT/.venv/bin/python" "$ULSANER_ROOT/engine/vibecutter_bench.py" audit \
    <workdir> <out.json>
```

- `<workdir>`: Phase 1이 만든 `index.json`이 있는 그 작업 디렉토리(동일 경로).
- `<out.json>`: 결과 JSON 출력 경로. 대시보드에 연동하려면
  `platform/data/vibecutter_result.json`로 지정한다.
- 이 단계는 각 앱마다 `uvicorn`을 로컬 포트에 기동하고, VibeCutter의 탐지/검증기와
  Ulsaner 레퍼런스 익스플로잇을 둘 다 실행한 뒤 프로세스를 정리한다.

## 출력 스키마

정식 예시는 `docs/vibecutter-patches/benchmark/benchmark-result.json`를 참고한다(실제
15-seed 실행 결과, 4개 클래스 중 idor-easy/idor-hard/sqli-easy 3개 채움). `_load_vibecutter`가
소비하는 필드:

- `success_rate` (float) — 필수. 없으면 대시보드는 "벤치마크 대기" 상태를 유지한다.
- `results` (list[bool]) — 인스턴스 개수·solved 개수 계산에 사용.
- `success_rate_stock` (float, 선택) — IDOR prefilter 수정 전(stock) 성공률. 있으면
  `stock_rate`로 노출.
- `success_rate_by_class` (dict, 선택) — 클래스별(`idor-easy`, `idor-hard`, `sqli-easy`,
  `sqli-hard`) 성공률. 있으면 `by_class`로 노출.
- `detail` (list[dict], 선택) — 인스턴스별 상세 행. 각 행의 `exploitable` 필드 합계가
  대시보드의 "취약점 실재" 카운트(자동도구가 놓쳐도 실제로는 취약한 인스턴스 수)로
  노출된다.
- `seeds` (list[int]) — 참고용, 소비되지 않지만 재현성을 위해 항상 채운다.

## 관계 노트

이 2단계 하네스(`engine/vibecutter_bench.py`)는 옛 수동 `generate_bundle` heredoc
워크플로우를 **벤치마킹 목적으로만** 대체한다 — Docker 자가검증을 포함한 정식 번들
생성(`engine.bundle.generate_bundle`)은 여전히 플랫폼이 실제 학생 인스턴스를 스핀업할 때
쓰는 경로이고 바뀌지 않았다. 반면 VibeCutter를 **대화형 MCP 서버로 사람이 직접 승인
게이트를 눌러가며 구동하는 절차**에 대한 설명은 이 문서가 아니라
`engine/vibecutter_config.py`의 모듈 docstring에 남아 있다(왜 배치 CLI가 아닌지, 왜
`engine.benchmark.run_external_auditor`의 제네릭 exit-code 인터페이스와 근본적으로
안 맞는지 포함).

## 테제 해석

`docs/vibecutter-patches/benchmark/benchmark-result.json`의 실제 수치가 보여주듯,
hard 티어(및 sqli)로 갈수록 VibeCutter의 정적 prefilter가 못 잡아내는 케이스가
늘어난다(`success_rate_by_class`: idor-easy 1.0, idor-hard 0.0, sqli-easy 0.0). 하지만
`exploitable`은 모든 행에서 계속 `true`로 남는다 — 즉 인스턴스는 실제로 취약하고,
Ulsaner 레퍼런스 익스플로잇이 매번 flag를 뽑아낸다. 이것이 우리 테제다: **"존재 vs
정확성이 자동도구를 속인다."** 자동도구의 미탐은 취약점이 없다는 뜻이 아니라, 자동도구가
찾아내는 능력의 한계일 뿐이다 — hard-idor(owner→workspace 위장)와 easy-sqli(sink이
서비스 계층 `db.py`에 있어 라우트에 안 붙는 경우)가 이를 보여주는 구체적 예시다.
