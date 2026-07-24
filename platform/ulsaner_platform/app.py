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

from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ulsaner_platform.service import ChallengeNotFound, ChallengeService

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BUNDLES: dict[str, Path] = {
    "easy-idor-01": _REPO_ROOT / "platform" / "fixtures" / "easy-idor-01",
}


class SpinUpRequest(BaseModel):
    name: str


class SubmitRequest(BaseModel):
    flag: str


def create_app(
    *,
    service: ChallengeService | None = None,
    bundles: dict[str, Path] | None = None,
) -> FastAPI:
    """앱을 조립한다. service/bundles 를 주입할 수 있어 테스트에서 Docker 를 우회한다."""
    service = service or ChallengeService()
    bundles = DEFAULT_BUNDLES if bundles is None else bundles

    app = FastAPI(
        title="Ulsaner Platform",
        description="매번 새로 생성되는 웹 취약점 훈련 엔진 — 플랫폼(검증 서비스 · 웹 UI)",
        version="0.2.0",
    )

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/challenges")
    def list_challenges() -> dict:
        return {"available": list(bundles)}

    @app.post("/challenges")
    def spin_up(req: SpinUpRequest) -> dict:
        bundle_dir = bundles.get(req.name)
        if bundle_dir is None:
            raise HTTPException(status_code=404, detail=f"알 수 없는 챌린지: {req.name}")
        return service.spin_up(bundle_dir)

    @app.post("/challenges/{challenge_id}/submit")
    def submit(challenge_id: str, req: SubmitRequest) -> dict:
        try:
            correct = service.submit_flag(challenge_id, req.flag)
        except ChallengeNotFound as exc:
            raise HTTPException(
                status_code=404, detail="챌린지를 찾을 수 없거나 이미 해결됨"
            ) from exc
        return {"correct": correct}

    @app.get("/stats")
    def stats() -> dict:
        log = service.attempt_log()
        return {
            "attempts": len(log),
            "solved": sum(1 for a in log if a.correct),
        }

    return app


# uvicorn 진입점: `uvicorn ulsaner_platform.app:app`
app = create_app()
