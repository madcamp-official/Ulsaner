# 엔진(Part A) 실행 가이드

`engine/`·`templates/` 실행에 필요한 명령어 모음. 구현 세부 내용은 [`docs/superpowers/plans/2026-07-24-ulsaner-engine-implementation-plan.md`](superpowers/plans/2026-07-24-ulsaner-engine-implementation-plan.md), 설계 배경은 [`docs/superpowers/specs/2026-07-23-vuln-injection-training-engine-design.md`](superpowers/specs/2026-07-23-vuln-injection-training-engine-design.md) 참고.

## 0. 사전 준비

- Python 3.11
- Docker Desktop (실행 중이어야 함 — `docker info`로 확인)
- Homebrew (semgrep 설치용)

## 1. 최초 환경 세팅 (한 번만)

```bash
python3.11 -m venv .venv
.venv/bin/pip install -r engine/requirements-dev.txt -r templates/notes_app/requirements.txt
brew install semgrep
```

**주의: semgrep은 `.venv`에 pip로 설치하지 말 것.** fastapi/starlette 버전과 의존성이 충돌한다 (직접 겪은 문제). 항상 Homebrew로 시스템에 별도 설치해서 PATH의 `semgrep` 커맨드를 쓴다.

## 2. 테스트 실행

```bash
# 빠른 테스트만 (Docker·semgrep 불필요, 1초 내외)
.venv/bin/pytest -m "not integration" -v

# 전체 통합 테스트 (Docker + semgrep 필요, 실제 컨테이너 빌드/실행)
.venv/bin/pytest -m integration -v

# 전부 다
.venv/bin/pytest -v
```

## 3. 핵심 증거 확인 (Semgrep: 존재 vs 정확성)

프로젝트의 핵심 주장 — "권한 체크가 아예 없는 것"(easy/idor)과 "체크는 있지만 틀린 필드를 보는 것"(hard/idor)은 자동 탐지 난이도가 다르다 — 을 직접 확인하는 테스트:

```bash
.venv/bin/pytest tests/engine/test_semgrep_sanity.py -v -m integration
```

easy/idor는 flag 되고 hard/idor는 안 되는 걸 실제 semgrep 실행으로 확인한다.

## 4. 데모: 취약 인스턴스 하나 생성해서 직접 공격해보기

### 4-1. 번들 생성

```bash
.venv/bin/python -c "
from pathlib import Path
from engine.bundle import generate_bundle
from engine.slots.hard_idor import build_hard_idor_slot

result = generate_bundle(
    seed=42,
    output_dir=Path('/tmp/demo-bundle'),
    slot_builder=build_hard_idor_slot,
    task_prompt='다른 사용자의 비공개 노트를 읽어 flag를 찾아라',
    solution_summary='workspace_id 스코프 체크가 owner_id를 대신하는 결함',
)
print('생성됨:', result)
"
```

`build_easy_idor_slot`으로 바꾸면 easy 티어(체크 아예 없음) 버전이 생성된다.

### 4-2. 생성된 내용 확인

```bash
cat /tmp/demo-bundle/manifest.json          # flag, task_prompt
cat /tmp/demo-bundle/app/routes/notes.py    # 실제 취약 코드
cat /tmp/demo-bundle/app/seed_data.json     # 유저 토큰, 소유권 정보
```

### 4-3. 컨테이너로 띄우기

```bash
docker build -t demo /tmp/demo-bundle/app
docker run -d -p 8000:8000 --name demo-run demo
```

(포트 8000이 이미 쓰이고 있으면 `lsof -nP -i :8000`으로 뭐가 물고 있는지 확인 후 `docker ps`에서 정리하거나 다른 호스트 포트로 매핑: `-p 8001:8000`)

### 4-4. 익스플로잇 (bob이 alice의 비공개 노트를 훔쳐보기)

```bash
# seed_data.json에서 bob(공격자)과 alice(피해자, note id=1)의 실제 토큰 확인 후
curl -H "X-User-Token: <bob의 토큰>" http://localhost:8000/notes/1
```

flag가 그대로 응답에 담겨 나오면 성공.

### 4-5. 정리

```bash
docker stop demo-run && docker rm demo-run
```

## 5. 플랫폼과 통합 실행 (실제 학생 플로우)

엔진↔플랫폼이 연결돼 있어서, 플랫폼을 띄우면 매 스핀업마다 엔진이 새 인스턴스를 생성한다.

```bash
PYTHONPATH=platform .venv/bin/uvicorn ulsaner_platform.app:app --reload
```

브라우저로 http://localhost:8000 접속 → 챌린지 목록에 `easy-idor-01`(고정 fixture)뿐 아니라 **`easy-idor-live`, `hard-idor-live`**(매번 새로 생성)도 뜬다. 스핀업하면 `.ulsaner-live-bundles/`에 그 인스턴스의 소스가 생성된다 — `seed_data.json`에서 토큰을 확인해 공격하면 된다(위 4장 방식과 동일).

## 6. 자주 겪는 문제

- **`docker-credential-desktop: executable file not found`**: Docker Desktop의 자격증명 헬퍼가 PATH에 없어서 나는 에러. `~/.docker/config.json`을 손대지 말고, 대신 `ln -sf "/Applications/Docker.app/Contents/Resources/bin/docker-credential-desktop" ~/.local/bin/docker-credential-desktop`로 심볼릭 링크만 걸어주면 해결된다.
- **`ModuleNotFoundError: No module named 'fastapi'`**: `engine/requirements-dev.txt`에 fastapi/uvicorn이 포함돼 있는지 확인 (누락되면 fresh venv에서 이 에러가 남).
- **contract/manifest_schema.json의 title이 테스트와 안 맞음**: 이미 두 번 겪은 문제라 `test_manifest.py`는 이제 title의 정확한 문자열을 검증하지 않도록 고쳐뒀다(존재 여부만 확인). 그래도 비슷한 게 또 나오면: 병합 전 `git log -- contract/manifest_schema.json`으로 상대가 이미 손봤는지 먼저 확인하고, 스키마 자체는 되돌리지 말 것(B와 공유 중인 최신 계약이 우선) — 자기 쪽 코드/테스트를 거기 맞춘다.
