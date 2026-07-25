"""Ulsaner 플랫폼 FastAPI 앱 (Part B).

검증 서비스(ChallengeService)를 HTTP 로 노출한다:
- GET  /health                         헬스체크
- GET  /challenges                     배포 가능한 챌린지 목록
- POST /challenges {name}              스핀업 → 학생용 뷰(challenge_id + URL + 과제)
- POST /challenges/{id}/submit {flag}  flag 판정 → {correct: bool}
- GET  /stats                          시도/성공 집계(대시보드용)

보안: HTTP 로 임의 경로를 배포하지 못하게, 배포 대상은 서버가 가진 화이트리스트
(bundles)에서만 이름으로 고른다.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from ulsaner_platform.service import ChallengeNotFound, ChallengeService
from ulsaner_platform.sources import Provision, engine_source, fixture_source

_REPO_ROOT = Path(__file__).resolve().parents[2]
_STATIC_DIR = Path(__file__).resolve().parent / "static"
_FIXTURE_DIR = _REPO_ROOT / "platform" / "fixtures" / "easy-idor-01"


@dataclass(frozen=True)
class Challenge:
    """카탈로그에 노출할 챌린지 스펙 + 스핀업 시 번들을 얻는 소스.

    메타데이터(vuln_type/tier/task_prompt)는 배포 없이 카드에 보여줄 값이라 스펙에 직접 둔다
    (엔진 소스는 배포 전엔 정적 manifest 가 없으므로 manifest 에서 읽을 수 없다).
    """

    name: str
    vuln_type: str
    tier: str
    task_prompt: str
    provision: Provision


# fixture(고정 flag) = 테스트·데모 기준, live(엔진 생성) = 인스턴스마다 랜덤 flag(thesis 실현).
DEFAULT_CHALLENGES: list[Challenge] = [
    Challenge(
        name="easy-idor-01",
        vuln_type="idor",
        tier="easy",
        task_prompt="당신은 alice 계정입니다. 다른 사용자의 비공개 노트를 읽어 flag 를 획득하세요. (고정 fixture)",
        provision=fixture_source(_FIXTURE_DIR),
    ),
    Challenge(
        name="easy-idor-live",
        vuln_type="idor",
        tier="easy",
        task_prompt="당신은 alice 계정입니다. 다른 사용자의 비공개 노트를 읽어 flag 를 획득하세요. (엔진 생성 · 매 인스턴스 랜덤 flag)",
        provision=engine_source("idor", "easy"),
    ),
]


class SpinUpRequest(BaseModel):
    name: str


class SubmitRequest(BaseModel):
    flag: str


def create_app(
    *,
    service: ChallengeService | None = None,
    challenges: list[Challenge] | None = None,
) -> FastAPI:
    """앱을 조립한다. service/challenges 를 주입할 수 있어 테스트에서 Docker 를 우회한다."""
    service = service or ChallengeService()
    challenges = DEFAULT_CHALLENGES if challenges is None else challenges
    by_name = {c.name: c for c in challenges}

    app = FastAPI(
        title="Ulsaner Platform",
        description="매번 새로 생성되는 웹 취약점 훈련 엔진 — 플랫폼(검증 서비스 · 웹 UI)",
        version="0.2.0",
    )

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        # 주 UI — Claude Design 핸드오프를 재현·실배선한 버전.
        return (_STATIC_DIR / "index_dc.html").read_text(encoding="utf-8")

    @app.get("/a", response_class=HTMLResponse)
    def index_a() -> str:
        # 대안 디자인 A(교육형 claymorphism) — 비교용.
        return (_STATIC_DIR / "index.html").read_text(encoding="utf-8")

    @app.get("/v2", response_class=HTMLResponse)
    def index_v2() -> str:
        # 대안 디자인 B(다크 콘솔) — 비교용.
        return (_STATIC_DIR / "index_claude.html").read_text(encoding="utf-8")

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard() -> str:
        # 통계 대시보드 — 시도/성공/정답률 + VibeCutter vs 사람.
        return (_STATIC_DIR / "dashboard.html").read_text(encoding="utf-8")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/challenges")
    def list_challenges() -> dict:
        # 카드용 메타데이터를 배포 없이 스펙에서 제공(flag/_internal 은 애초에 없음).
        return {
            "available": [
                {
                    "name": c.name,
                    "vuln_type": c.vuln_type,
                    "tier": c.tier,
                    "task_prompt": c.task_prompt,
                }
                for c in challenges
            ]
        }

    @app.post("/challenges")
    def spin_up(req: SpinUpRequest) -> dict:
        spec = by_name.get(req.name)
        if spec is None:
            raise HTTPException(status_code=404, detail=f"알 수 없는 챌린지: {req.name}")
        # 엔진 소스는 여기서 실번들을 생성(Docker 빌드·자가검증 포함, 수십 초 가능).
        try:
            bundle_dir, cleanup = spec.provision()
        except Exception as exc:  # 생성 실패(Docker 다운·엔진 오류 등)
            raise HTTPException(
                status_code=503,
                detail="인스턴스 생성에 실패했습니다 (Docker 데몬·엔진 상태를 확인하세요).",
            ) from exc
        return service.spin_up(bundle_dir, cleanup=cleanup)

    @app.post("/challenges/{challenge_id}/submit")
    def submit(challenge_id: str, req: SubmitRequest) -> dict:
        try:
            correct = service.submit_flag(challenge_id, req.flag)
        except ChallengeNotFound as exc:
            raise HTTPException(
                status_code=404, detail="챌린지를 찾을 수 없거나 이미 해결됨"
            ) from exc
        return {"correct": correct}

    @app.delete("/challenges/{challenge_id}")
    def teardown(challenge_id: str) -> dict:
        # 인스턴스 종료(수동 teardown). 이미 없으면 조용히 성공(멱등).
        service.teardown(challenge_id)
        return {"ok": True}

    @app.get("/stats")
    def stats() -> dict:
        log = service.attempt_log()
        attempts = len(log)
        solved = sum(1 for a in log if a.correct)

        def agg(attr: str) -> dict:
            out: dict[str, dict[str, int]] = {}
            for a in log:
                d = out.setdefault(getattr(a, attr), {"attempts": 0, "solved": 0})
                d["attempts"] += 1
                if a.correct:
                    d["solved"] += 1
            return out

        return {
            "attempts": attempts,
            "solved": solved,
            "success_rate": round(solved / attempts, 4) if attempts else 0.0,
            "by_tier": agg("tier"),
            "by_vuln": agg("vuln_type"),
            # VibeCutter 벤치마크(자동도구 성공률) 결과 자리 — 엔진 파트에서 실행 후 연동.
            "vibecutter": None,
        }

    return app


# uvicorn 진입점: `uvicorn ulsaner_platform.app:app`
app = create_app()
