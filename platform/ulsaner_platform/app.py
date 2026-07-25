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
from typing import Callable, Union

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from ulsaner_platform.manifest import load_bundle_manifest
from ulsaner_platform.service import ChallengeNotFound, ChallengeService

_REPO_ROOT = Path(__file__).resolve().parents[2]
_STATIC_DIR = Path(__file__).resolve().parent / "static"
_LIVE_WORKDIR = _REPO_ROOT / ".ulsaner-live-bundles"


@dataclass(frozen=True)
class LiveChallenge:
    """엔진이 스핀업 시점마다 새로 생성하는 챌린지 — 고정 fixture와 달리 매번 유니크하다."""

    vuln_type: str
    tier: str
    task_prompt: str
    factory: Callable[[], Path]


BundleSource = Union[Path, LiveChallenge]


def _generate_easy_idor() -> Path:
    from engine.live_bundle import generate_live_bundle
    from engine.slots.easy_idor import build_easy_idor_slot

    return generate_live_bundle(build_easy_idor_slot, _LIVE_WORKDIR)


def _generate_hard_idor() -> Path:
    from engine.live_bundle import generate_live_bundle
    from engine.slots.hard_idor import build_hard_idor_slot

    return generate_live_bundle(build_hard_idor_slot, _LIVE_WORKDIR)


DEFAULT_BUNDLES: dict[str, BundleSource] = {
    "easy-idor-01": _REPO_ROOT / "platform" / "fixtures" / "easy-idor-01",
    "easy-idor-live": LiveChallenge(
        vuln_type="idor",
        tier="easy",
        task_prompt="다른 사용자의 비공개 노트를 읽어 flag를 찾아라",
        factory=_generate_easy_idor,
    ),
    "hard-idor-live": LiveChallenge(
        vuln_type="idor",
        tier="hard",
        task_prompt="다른 사용자의 비공개 노트를 읽어 flag를 찾아라",
        factory=_generate_hard_idor,
    ),
}


class SpinUpRequest(BaseModel):
    name: str


class SubmitRequest(BaseModel):
    flag: str


def create_app(
    *,
    service: ChallengeService | None = None,
    bundles: dict[str, BundleSource] | None = None,
) -> FastAPI:
    """앱을 조립한다. service/bundles 를 주입할 수 있어 테스트에서 Docker 를 우회한다."""
    service = service or ChallengeService()
    bundles = DEFAULT_BUNDLES if bundles is None else bundles

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

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/challenges")
    def list_challenges() -> dict:
        # 카드용 메타데이터. 고정 fixture는 배포 없이 manifest에서 읽고,
        # LiveChallenge는 스핀업 전이라 실제 manifest가 없으므로 고정 메타데이터를 쓴다
        # (task_prompt는 매 생성마다 동일하게 넘기므로 이 메타데이터와 항상 일치한다).
        available = []
        for name, source in bundles.items():
            if isinstance(source, LiveChallenge):
                available.append(
                    {
                        "name": name,
                        "vuln_type": source.vuln_type,
                        "tier": source.tier,
                        "task_prompt": source.task_prompt,
                    }
                )
            else:
                manifest = load_bundle_manifest(source)
                available.append(
                    {
                        "name": name,
                        "vuln_type": manifest.vuln_type,
                        "tier": manifest.tier,
                        "task_prompt": manifest.task_prompt,
                    }
                )
        return {"available": available}

    @app.post("/challenges")
    def spin_up(req: SpinUpRequest) -> dict:
        source = bundles.get(req.name)
        if source is None:
            raise HTTPException(status_code=404, detail=f"알 수 없는 챌린지: {req.name}")
        # LiveChallenge는 요청 시점에 엔진으로 새 인스턴스를 생성한다 — 매번 유니크한 번들.
        bundle_dir = source.factory() if isinstance(source, LiveChallenge) else source
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

    @app.delete("/challenges/{challenge_id}")
    def teardown(challenge_id: str) -> dict:
        # 인스턴스 종료(수동 teardown). 이미 없으면 조용히 성공(멱등).
        service.teardown(challenge_id)
        return {"ok": True}

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
