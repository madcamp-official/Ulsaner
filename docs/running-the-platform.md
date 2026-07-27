# 플랫폼(Part B) 실행 & 데모 가이드

`platform/`·`orchestrator/`(검증 서비스 · 웹 UI · 대시보드) 실행법과 발표 데모 시나리오.
엔진 실행은 [`docs/running-the-engine.md`](running-the-engine.md) 참고.

## 0. 사전 준비

- **Python 3.11**
- **Docker 데몬 실행 중** — `docker info` 로 확인. 로컬은 Colima 사용(`colima start`).

## 1. 최초 세팅 (한 번만)

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## 2. 원커맨드 실행 (데모용)

```bash
./scripts/demo.sh
```

이 스크립트가 순서대로: 파이썬 venv 확인 → Docker 데몬 확인(안 떠 있으면 `colima start` 시도)
→ 포트 확인(이미 서버가 떠 있으면 브라우저만 열고 종료) → **fixture 이미지 예열**(첫 스핀업을 빠르게)
→ 앱 임포트 예열 → `uvicorn` 기동 → `/health` 대기 → 브라우저로 훈련장(`/`)을 연다.
종료는 `Ctrl-C`. 포트를 바꾸려면 `ULSANER_PORT=8099 ./scripts/demo.sh`.

### 수동 실행 (스크립트 없이)

```bash
PYTHONPATH=platform:. .venv/bin/python -m uvicorn ulsaner_platform.app:app --host 127.0.0.1 --port 8000
```

주요 화면:
- `/` — 훈련장(챌린지 목록 · 스핀업 · flag 제출)
- `/dashboard` — 통계 대시보드(시도/성공/정답률 · VibeCutter vs 사람)

## 3. 데모 시나리오 (발표용)

### ① "사람이 직접 푼다" — easy-idor-01 (고정 fixture, 결정적)

1. 훈련장에서 **easy-idor-01 → 시작하기**. 스핀업 로그가 흐르고 **접속 URL + 과제**가 뜬다.
2. 발급된 URL 을 새 탭에서 열면 안내 페이지(취약점·flag 는 비노출). 공략은 IDOR:

   ```bash
   curl "<접속URL>/notes/42" -H "Authorization: Bearer alice-token"
   ```

   → 응답 본문에 `FLAG{idor_bob_private_2f9c}`. (alice 로 인증했지만 소유권 검사가 없어 bob 의 비공개 노트가 읽힘)
3. 그 flag 를 훈련장 입력창에 제출 → **정답** → 인스턴스 종료 + 풀이 수 +1.

### ② "매번 답이 다르다" — easy-idor-live / hard-idor-live (엔진 생성, thesis)

- **live** 챌린지는 스핀업마다 엔진이 새 번들을 생성한다(자가검증 포함이라 수십 초 소요). flag·토큰·노트 ID 가 **매 인스턴스 랜덤** → 정답을 미리 검색해 찾을 수 없다.
- 공략은 같은 IDOR 이지만, 노트 ID·토큰을 그때그때 관찰해 찾아야 한다.
- **hard-idor-live** 는 소유권 체크가 *존재하지만 틀린 필드*를 비교하도록 변형돼 있어 정적분석/자동도구가 잘 못 잡는다 — 이게 발표의 핵심.

### ③ 대시보드로 마무리 — `/dashboard`

- 총 시도/성공/정답률, 그리고 **VibeCutter(자동도구) vs 사람** 성공률 대비.
- VibeCutter 숫자는 엔진 벤치마크 결과 파일(`platform/data/vibecutter_result.json`)이 있으면 자동으로 채워진다(형식: [`vibecutter_result.example.json`](../platform/data/vibecutter_result.example.json)). 없으면 "벤치마크 대기".

## 4. 트러블슈팅

| 증상 | 원인 / 해결 |
|---|---|
| 스핀업 시 503 "인스턴스 생성/배포 실패" | Docker 데몬이 죽었거나 이미지 빌드 실패. `docker info` 확인. |
| 스핀업 시 503 "동시 인스턴스 상한" | 활성 인스턴스가 상한(기본 8)에 도달. 기존 세션을 종료하거나 잠시 후 재시도(만료분은 자동 회수). |
| 접속 URL 이 404 | 그 URL 은 **공략 대상 API**다. 루트(`/`)엔 안내 페이지만 있고, 취약 엔드포인트를 직접 찔러야 한다. |
| 첫 실행이 수십 초 느림 | 이 머신은 첫 파일 접근이 느리다(보안 스캔). `demo.sh` 가 미리 예열하지만, 콜드 상태면 기다리면 된다. 이후로는 빠르다. |
| 포트 충돌 | `ULSANER_PORT=8099 ./scripts/demo.sh` 로 포트 변경. |
| 컨테이너 정리 | 서버는 정답/종료/TTL(30분)에 인스턴스를 회수하고, 재기동 시 남은 고아도 회수한다. 수동: `docker ps -aq --filter label=ulsaner.managed=1 | xargs docker rm -f`. |

## 5. 테스트

```bash
.venv/bin/pytest -m "not integration"   # 빠른 유닛/엔드포인트
.venv/bin/pytest -m integration         # Docker 필요 (실배포·엔진 실번들 E2E)
```
