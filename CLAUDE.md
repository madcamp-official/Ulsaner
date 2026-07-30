# CLAUDE.md

Ulsaner(취약점 주입 훈련 엔진) 프로젝트의 개발 규칙. 코드를 작성하기 전에 이 파일과 아래 문서를 먼저 확인할 것.

- 설계: [`docs/superpowers/specs/2026-07-23-vuln-injection-training-engine-design.md`](docs/superpowers/specs/2026-07-23-vuln-injection-training-engine-design.md)
- 구현 계획: [`docs/superpowers/plans/2026-07-23-ulsaner-implementation-plan.md`](docs/superpowers/plans/2026-07-23-ulsaner-implementation-plan.md)
- 논의 기록: [`docs/2026-07-24-design-review-qna.md`](docs/2026-07-24-design-review-qna.md)
- 실행 가이드: [`docs/running-the-engine.md`](docs/running-the-engine.md)

## 소유권 모델

- **A(엔진)**: `engine/`, `templates/` — 슬롯 라이브러리, 주입 엔진(AST), 레퍼런스 익스플로잇, 자가검증, VibeCutter 벤치마크 하네스.
- **B(플랫폼)**: `platform/`, `orchestrator/` — Docker 오케스트레이션, 검증 서비스, 웹 UI·대시보드.
- **공용**: `contract/manifest_schema.json` — **수정 전 반드시 상대방에게 공지**. 이 파일이 두 파트를 잇는 유일한 계약이므로, 여기가 깨지면 양쪽 다 멈춘다.

## 브랜치 전략 (팀원별 단일 브랜치)

1주일짜리 2인 프로젝트라 태스크별 브랜치 대신 **사람별 브랜치 하나**로 간소화한다.

- **`main`** — 항상 데모 가능한 상태만 유지.
- **`feature-sy`** — A(엔진, `engine/`·`templates/`) 담당자 브랜치. 이 플랜의 모든 태스크는 여기서 커밋된다.
- **`feature-mj`** — B(플랫폼, `platform/`·`orchestrator/`) 담당자 브랜치.
- **병합 시점**: Day 3(바닥 E2E 게이트), Day 5(하드 코어 완료), Day 7(최종) — 이 시점마다 각자 브랜치를 `main`으로 병합 후 데모 가능한 상태인지 확인.
- **계약 파일(`contract/manifest_schema.json`) 변경**은 어느 브랜치에서 하든, 커밋 전 상대방에게 먼저 알리고 진행한다.

## 개발 환경 셋업 (엔진 파트)

- **Python 3.11 필수.** `python3.11 -m venv .venv` 후 `.venv/bin/pip install -r engine/requirements-dev.txt`. 항상 `.venv/bin/python`·`.venv/bin/pytest`를 쓸 것 (시스템 기본 `python3`는 3.9일 수 있음).
- **Docker Desktop 필요** (자가검증·번들 E2E 테스트용). `docker info`로 데몬이 떠 있는지 먼저 확인.
- **Semgrep은 `.venv`에 설치하지 말 것** — fastapi/starlette 버전과 의존성 충돌 남. `brew install semgrep`으로 시스템에 별도 설치해서 PATH의 `semgrep` 커맨드로 사용.
- 통합 테스트(Docker·semgrep 필요)는 `@pytest.mark.integration`로 마킹됨: `pytest -m integration`으로 따로 실행, 빠른 유닛 테스트만 돌리려면 `pytest -m "not integration"`.

## 보안 주의사항

- `engine.bundle.generate_bundle`이 만드는 번들에는 `app/`(학생에게 노출되는 실행 앱)과 `manifest.json` 외에 **`exploits/reference.json`도 함께 생성됨** — 여기엔 평문 flag와 공격자 토큰이 들어있음. **B(플랫폼)는 `app/`만 배포해야 하며, `exploits/`나 번들 루트 전체를 절대 정적으로 노출하면 안 됨.** `manifest.json`의 `_internal` 블록뿐 아니라 `exploits/` 디렉토리 자체도 학생에게 도달 불가능해야 함.

## 커밋 컨벤션

기존 커밋 스타일을 따른다: `type: 설명` (한글 설명 가능).

- `feat:` 새 기능, `fix:` 버그 수정, `docs:` 문서, `test:` 테스트, `refactor:` 리팩터링, `chore:` 잡일

## 개발 원칙

- **YAGNI**: 설계 문서 섹션 3의 비범위(회원가입, 리더보드, k8s 등)는 지금 만들지 않는다. 게이미피케이션처럼 나중에 얹을 걸 알고 있는 것도, 로깅 스키마에 필드 여유만 두고 실제 기능은 짓지 않는다.
- **자가검증 우선**: 엔진이 생성한 인스턴스는 레퍼런스 익스플로잇이 실제로 통과해야만 출하한다. 이 게이트를 우회하는 코드는 작성하지 않는다.
- **Day 3 게이트가 우선순위 기준**: `easy/idor` E2E가 막히면 SQLi·하드 티어보다 이 게이트 통과가 항상 우선이다.
