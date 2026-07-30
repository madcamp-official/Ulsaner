#!/usr/bin/env bash
# Ulsaner 데모 원커맨드 실행기 (Part B / 플랫폼).
#
# 사전점검(파이썬 venv · Docker 데몬 · 포트) → fixture 이미지 예열 → 앱 임포트 예열
# → uvicorn 기동 → /health 대기 → 브라우저 열기. Ctrl-C 로 종료.
#
# 사용:  ./scripts/demo.sh            (기본 포트 8000)
#        ULSANER_PORT=8099 ./scripts/demo.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PORT="${ULSANER_PORT:-8000}"
PY=".venv/bin/python"
APP="ulsaner_platform.app:app"
URL="http://127.0.0.1:${PORT}"

say()  { printf '\033[1;36m▶ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

open_browser() { command -v open >/dev/null 2>&1 && open "$URL/" 2>/dev/null || true; }

# 1) 파이썬 venv ---------------------------------------------------------------
say "1/6  파이썬 환경 확인"
[ -x "$PY" ] || die ".venv 가 없습니다. 먼저:  python3.11 -m venv .venv && .venv/bin/pip install -e \".[dev]\""

# 2) Docker 데몬 ---------------------------------------------------------------
say "2/6  Docker 데몬 확인"
if ! docker info >/dev/null 2>&1; then
  warn "Docker 가 응답하지 않습니다. colima 기동을 시도합니다..."
  command -v colima >/dev/null 2>&1 && colima start >/dev/null 2>&1 || true
  docker info >/dev/null 2>&1 \
    || die "Docker 데몬을 띄우지 못했습니다. Docker Desktop 실행 또는 'colima start' 후 다시 시도하세요."
fi

# 3) 포트 ----------------------------------------------------------------------
say "3/6  포트 ${PORT} 확인"
if lsof -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  if curl -sf "$URL/health" >/dev/null 2>&1; then
    say "이미 실행 중인 Ulsaner 서버를 재사용합니다 → $URL"
    open_browser
    exit 0
  fi
  die "포트 ${PORT} 를 다른 프로세스가 쓰고 있습니다. ULSANER_PORT=8099 ./scripts/demo.sh 처럼 바꿔 실행하세요."
fi

# 4) fixture 이미지 예열 (첫 스핀업을 빠르게 — docker 레이어 캐시 워밍) ----------
say "4/6  fixture 이미지 예열"
if docker build -t ulsaner-fixture-warm platform/fixtures/easy-idor-01 >/dev/null 2>&1; then
  printf '     ok\n'
else
  warn "예열 실패(무시하고 계속) — 첫 스핀업이 조금 느릴 수 있습니다."
fi

# 5) 앱 임포트 예열 (이 개발 머신은 첫 파일 접근이 매우 느릴 수 있음 → 미리 데워둠) --
say "5/6  앱 임포트 예열 (수십 초 걸릴 수 있음)"
PYTHONPATH=platform:. "$PY" -c "import ulsaner_platform.app" >/dev/null 2>&1 || true

# 6) 서버 기동 -----------------------------------------------------------------
say "6/6  서버 기동 → $URL"
PYTHONPATH=platform:. "$PY" -m uvicorn "$APP" --host 127.0.0.1 --port "$PORT" &
SRV=$!
cleanup() { echo; say "서버 종료 (pid $SRV)"; kill "$SRV" 2>/dev/null || true; }
trap cleanup INT TERM

for _ in $(seq 1 90); do
  curl -sf "$URL/health" >/dev/null 2>&1 && break
  sleep 1
done

if curl -sf "$URL/health" >/dev/null 2>&1; then
  say "준비 완료 — 브라우저를 엽니다. (종료: Ctrl-C)"
  open_browser
else
  warn "서버가 아직 응답하지 않습니다. 위 uvicorn 로그를 확인하세요."
fi

wait "$SRV"
