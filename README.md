# Ulsaner

몰입캠프 26s-w4-c2-03 — **정답을 찾아볼 수 없는, 매번 새로 생성되는 웹 취약점 훈련 엔진**.

템플릿 FastAPI 앱을 AST 변형(libcst)해 취약점(IDOR/SQLi)을 매번 다른 위치에 심고,
격리 Docker로 배포하고, flag로 자동 검증한다. 설계: [`docs/superpowers/specs`](docs/superpowers/specs/2026-07-23-vuln-injection-training-engine-design.md).

## 저장소 구조 / 소유권

| 디렉토리 | 소유 | 내용 |
|---|---|---|
| `engine/`, `templates/` | Part A (엔진) | 취약 슬롯, AST 주입, 레퍼런스 익스플로잇, 자가검증, 벤치마크 |
| `platform/`, `orchestrator/` | Part B (플랫폼) | Docker 오케스트레이션, 검증 서비스, 웹 UI/대시보드 |
| `contract/manifest_schema.json` | 🤝 공용 | 엔진↔플랫폼 유일한 계약. **수정 전 팀에 공지** |

> `platform/` 는 파이썬 stdlib `platform` 과 이름이 겹치므로, 실제 임포트 패키지는
> `platform/ulsaner_platform/` 로 한 단계 중첩돼 있다(섀도잉 방지).

## 데모 실행 (플랫폼)

Docker 데몬이 떠 있는 상태에서:

```bash
./scripts/demo.sh
```

사전점검 → 이미지·임포트 예열 → 서버 기동 → 브라우저로 훈련장(`/`)을 연다. 데모 시나리오·트러블슈팅은 [`docs/running-the-platform.md`](docs/running-the-platform.md), 엔진 실행은 [`docs/running-the-engine.md`](docs/running-the-engine.md) 참고.

## 개발 세팅

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## 테스트

```bash
pytest
```

린트:

```bash
ruff check .
```

## 계약: 챌린지 번들

엔진이 생성하고 플랫폼이 소비하는 번들 = 하나의 디렉토리.

```
<bundle>/
├── app/           # 변형된 FastAPI 앱 소스 (+ Dockerfile)
├── Dockerfile
└── manifest.json  # contract/manifest_schema.json 을 따른다
```

손으로 만든 기준 번들(플랫폼 선개발용): [`platform/fixtures/easy-idor-01/`](platform/fixtures/easy-idor-01/).
