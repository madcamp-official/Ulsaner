# Ulsaner — 구현 계획 (7일)

> 설계 문서: [2026-07-23-vuln-injection-training-engine-design.md](../specs/2026-07-23-vuln-injection-training-engine-design.md)
> A(엔진) 파트 상세 TDD 구현 계획: [2026-07-24-ulsaner-engine-implementation-plan.md](2026-07-24-ulsaner-engine-implementation-plan.md)
> 몰입캠프 4주차 · 2인 · 작성일 2026-07-23

## 소유권 모델

- **Part A — 엔진** · 소유: 박서윤 · 디렉토리 `engine/`, `templates/`
  - 취약 슬롯, 주입(AST), 레퍼런스 익스플로잇, 자가검증, 벤치마크 하네스
- **Part B — 플랫폼** · 소유: 김민재 · 디렉토리 `platform/`, `orchestrator/`
  - Docker 오케스트레이션, 검증 서비스, 웹 UI/대시보드
- **🤝 공유 구역**: 하드티어 취약점 설계(무엇이 VibeCutter를 이기나) + VibeCutter 벤치마크
- **공용 파일**: `contract/manifest_schema.json` — 수정 전 서로 공지

## 리스크 게이트 & MVP 경계

- **Day 3 게이트:** `easy/idor` E2E(생성→배포→익스플로잇→검증) = 바닥. 못 넘으면 SQLi·하드티어 스코프 컷.
- **하드 코어(AST 재배열 + VibeCutter 벤치마크)는 바닥 뒤에 층으로** 배치 → 최악에도 바닥+컨셉 데모 가능.
- **MVP 필수:** 템플릿앱 + 계약 + `easy/idor` 풀루프 + 기본 웹 UI + 인스턴스 Docker.
- **컷:** 회원가입/인증(세션토큰 대체), 리더보드, 영속저장, k8s급 인프라.

## 7일 태스크 (A=박서윤 · B=김민재 · 🤝=공유)

### Day 1 — 기반
- 🤝 레포 세팅, 폴더 구조, Docker 베이스 이미지
- 🤝 `manifest_schema.json` 계약 합의·작성
- 🤝 템플릿 앱 데이터 모델 합의 + 하드티어 취약점 브레인스토밍 킥오프
- A: 깨끗한 템플릿 FastAPI 앱 구현(모델·라우트·시드 데이터)
- B: 레포/Docker 스캐폴딩 + 손으로 만든 fixture 번들 1개

### Day 2 — 엔진 씨앗 & 플랫폼 골격
- A: `easy/idor` 슬롯 + 파라미터화(타깃 리소스/flag/id 랜덤)
- A: 레퍼런스 익스플로잇 생성 + 자가검증 루프
- B: 오케스트레이터 v1(Docker 빌드+실행, 동적 포트, URL 발급)
- B: 웹 UI 골격(요청→URL+task_prompt→flag 제출)

### Day 3 — 통합 & 바닥 데모 ⭐
- A: `easy/idor` 완성 → 첫 실제 번들
- 🤝 A 실번들 ↔ B 플랫폼 연결 → 첫 E2E = 바닥 데모
- B: 검증 서비스(flag 판정·로깅) + TTL/teardown 기본
- A: `easy/sqli` 슬롯 착수

### Day 4 — 일반성 & 견고화
- A: `easy/sqli` 완성(2종 처리=일반성) + 자가검증 확장
- A: `hard/idor` 슬롯 착수 — 권한 체크는 존재하되 틀린 필드/스코프(workspace_id 등)를 비교하도록 설계(존재 vs 정확성)
- B: 오케스트레이터 견고화(동시 상한·헬스체크·고아 회수·에러처리)
- B: 대시보드 v1(시도/성공 통계)

### Day 5 — 하드 코어 (AST)
- A: `hard/idor` + AST 배치/재배열(libcst) ← "체크 존재 vs 정확성" 차별화의 핵심 구현
- A: Semgrep "안 잡힘" 테스트 추가
- 🤝 VibeCutter 벤치마크 셋업(클론/실행, 화이트박스 실행 준비)
- B: 대시보드 "VibeCutter vs 사람" 뷰

### Day 6 — 적대적 루프 & 폴리싱
- 🤝 VibeCutter 벤치마크 실행 → 첫 성공률, 뚫린 인스턴스로 슬롯 강화
- A: 재배열/슬롯 강화 + 속성기반 테스트 정비
- B: 웹 UI 폴리싱, 데모 플로우 정리
- (스트레치) A: `hard/sqli`(블라인드/2차) 착수 판단

### Day 7 — 마감 & 발표
- 🤝 E2E 전체 통과 확인 + 버그 픽스
- 🤝 발표 리허설("VibeCutter/GPT 실패 → 사람 성공" + 대시보드 숫자)
- B: 데모 환경 안정화
- A: README/문서 + 향후 확장 로드맵
- 🤝 버퍼

## 완료 정의 (Definition of Done)

- 엔진: 슬롯×티어마다 N 시드 → 앱 부팅 + 레퍼런스 익스플로잇 성공 + [하드] Semgrep 미검출.
- 플랫폼: fixture/실번들 배포 → 올바른/틀린 flag/TTL 만료 경로 통과.
- E2E: 생성→배포→(레퍼런스)익스플로잇→flag 제출→통과.
- 벤치마크: VibeCutter 배치 성공률 숫자 확보(발표용 "VibeCutter X% vs 사람 Y%").
