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

import json
import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from orchestrator.runner import OrchestratorError
from ulsaner_platform.service import (
    CapacityError,
    ChallengeNotFound,
    ChallengeService,
)
from ulsaner_platform.sources import Provision, engine_source

_log = logging.getLogger("ulsaner.platform")
_REPO_ROOT = Path(__file__).resolve().parents[2]
# 엔진 VibeCutter 벤치마크 결과가 떨어지는 자리(서윤이 run_benchmark 결과 JSON 을 여기 저장).
# 파일이 있으면 /stats 가 자동도구 성공률을 읽어 대시보드에 채운다. 없으면 '벤치마크 대기'.
_DEFAULT_VIBECUTTER_PATH = _REPO_ROOT / "platform" / "data" / "vibecutter_result.json"
_STATIC_DIR = Path(__file__).resolve().parent / "static"


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


# 전부 live(엔진 생성) — 인스턴스마다 랜덤 flag(thesis 실현). 고정 flag fixture(easy-idor-01)는
# 이제 카탈로그에서 뺐다(live 로 충분히 대체됨). fixture 소스·번들 자체는 테스트용으로 유지.
DEFAULT_CHALLENGES: list[Challenge] = [
    Challenge(
        name="easy-idor-live",
        vuln_type="idor",
        tier="easy",
        task_prompt="당신은 bob 계정입니다. 다른 사용자(alice)의 비공개 노트를 읽어 flag 를 획득하세요. (엔진 생성 · 매 인스턴스 랜덤 flag, 스핀업 후 토큰 제공)",
        provision=engine_source("idor", "easy"),
    ),
    Challenge(
        name="hard-idor-live",
        vuln_type="idor",
        tier="hard",
        task_prompt="당신은 bob 계정입니다. 다른 사용자(alice)의 비공개 노트를 읽어 flag 를 획득하세요. (엔진 생성 · 존재하지만 틀린 권한 체크, 스핀업 후 토큰 제공)",
        provision=engine_source("idor", "hard"),
    ),
    Challenge(
        name="easy-sqli-live",
        vuln_type="sqli",
        tier="easy",
        task_prompt="노트 검색(GET /notes/search?q=)에 SQL 인젝션이 있습니다. 비공개 노트의 flag 를 빼내세요. (엔진 생성 · 매 인스턴스 랜덤 flag)",
        provision=engine_source("sqli", "easy"),
    ),
    Challenge(
        name="hard-sqli-live",
        vuln_type="hard_sqli",
        tier="hard",
        task_prompt="고급 검색(GET /notes/search/advanced)의 exclude 파라미터로 비공개 노트를 유출하세요. 파라미터 바인딩처럼 보이지만 실제로는 문자열 보간됩니다. (엔진 생성 · 매 인스턴스 랜덤 flag)",
        provision=engine_source("hard_sqli", "hard"),
    ),
    # XSS(반사형)는 카탈로그에 노출하지 않는다 — 인터랙티브 'flag 제출' 모델과 안 맞는다.
    # XSS 는 저장된 flag 를 유출하지 않고 반사만 증명하므로, 레퍼런스 익스플로잇이 스스로
    # flag 를 페이로드에 실어 넣어야 성립한다(자가검증·VibeCutter 벤치마크에선 유효). 하지만
    # flag(FLAG{...})는 인스턴스마다 랜덤·비공개라, 그것을 모르는 사람은 제출할 값을 얻을 수
    # 없다. 그래서 engine.slots.xss + sources._SLOTS("xss","easy") 배선은 벤치마크용으로
    # 남겨두되, 여기 카드로는 내보내지 않는다. 인터랙티브로 살리려면 submit 판정을 '반사 증명'
    # 으로 바꾸는 별도 설계가 필요하다(향후 과제).
    # tickets 의 idor/sqli 는 notes 와 메커니즘이 같아(옷만 다른 문제) 카드에서 뺐다 — 엔진 슬롯·
    # sources._SLOTS 배선은 '범용성' 증명 + VibeCutter 벤치마크용으로 유지(xss 와 동일 패턴).
    Challenge(
        name="jwt-forge-live",
        vuln_type="jwt",
        tier="easy",
        task_prompt="계정 포털입니다. guest 계정으로 로그인하면 JWT 세션 토큰을 받습니다. flag 는 관리자 전용 페이지에 있는데 당신은 일반 사용자예요. 받은 토큰을 뜯어보고 관리자 권한을 얻을 방법을 찾아 flag 를 획득하세요. (portal_app · JWT 위조 · 엔진 생성)",
        provision=engine_source("jwt", "easy", template="portal"),
    ),
    Challenge(
        name="account-takeover-live",
        vuln_type="takeover",
        tier="hard",
        task_prompt="계정 관리 포털입니다. guest/guest 로 로그인할 수 있고, flag 는 관리자 전용 페이지에 있습니다. admin 비밀번호는 모릅니다 — 비밀번호 재설정 흐름의 허점을 여러 단계에 걸쳐 파고들어 관리자 계정을 탈취해 flag 를 획득하세요. (accounts_app · 계정 탈취 다단계 체인 · VERY HARD)",
        provision=engine_source("takeover", "hard", template="accounts"),
    ),
    Challenge(
        name="ssrf-pivot-live",
        vuln_type="ssrf",
        tier="hard",
        task_prompt="URL 상태 확인 도구가 있는 게이트웨이입니다. flag 는 내부 vault 에 있고 외부에선 내부 서비스에 직접 못 갑니다. 이 도구로 서버가 대신 내부에 접근하게 만들어, 두 단계에 걸쳐 내부로 피벗해 flag 를 획득하세요. (gateway_app · SSRF 2-hop 피벗 · VERY HARD)",
        provision=engine_source("ssrf", "hard", template="gateway"),
    ),
]


def _load_vibecutter(path: Path | None) -> tuple[float | None, dict | None]:
    """벤치마크 결과 파일을 읽어 (성공률, 상세)를 돌려준다.

    run_benchmark() 형식({"seeds", "results", "success_rate"})을 그대로 소비한다.
    파일이 없거나 깨졌으면 (None, None) — /stats 의 기존 '벤치마크 대기' 동작을 보존한다.
    """
    if path is None or not path.exists():
        return None, None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, None
    rate = data.get("success_rate")
    if rate is None:
        return None, None
    results = data.get("results") or []
    detail = {
        "instances": len(results),
        "solved": sum(1 for r in results if r),
    }
    # 확장 필드(멀티클래스 하네스가 채우면 노출, 없으면 기존 동작 유지 — 하위호환).
    by_class = data.get("success_rate_by_class")
    if isinstance(by_class, dict) and by_class:
        detail["by_class"] = by_class
    stock = data.get("success_rate_stock")
    if stock is not None:
        detail["stock_rate"] = float(stock)
    rows = data.get("detail")
    if isinstance(rows, list) and rows:
        # exploitable = 실제로 취약(레퍼런스 익스플로잇 통과)인 인스턴스 수.
        # 자동도구가 놓쳐도 취약점은 존재한다는 '사람 vs 자동도구' 대비의 핵심 수치.
        detail["exploitable"] = sum(1 for r in rows if r.get("exploitable"))
    return float(rate), detail


def _hint_overlay_html(hints: list[str]) -> str:
    """챌린지 앱 HTML 에 주입할, 자기완결형 온디맨드 힌트 오버레이(우하단 플로팅 버튼).

    '인스턴스 안에서' 힌트를 보게 하는 조각 — 학생이 챌린지 앱을 보는 중에도 탭을 옮기지 않고
    버튼을 눌러 한 단계씩 힌트를 편다(자동 노출 아님). 챌린지 앱의 CSS/JS 와 충돌하지 않도록
    고유 접두어(__vite_hint_*)·격리 스타일·IIFE 로 감싼다. same-origin 부모(세션 페이지 iframe)가
    있으면 postMessage 로 '힌트 사용'을 알려 ★(힌트 없이 해결) 판정을 정직하게 유지한다.
    """
    payload = json.dumps(hints, ensure_ascii=False).replace("</", "<\\/")
    return (
        "<style>"
        "#__vite_hint_root{position:fixed;right:16px;bottom:16px;z-index:2147483000;"
        'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Noto Sans KR",sans-serif;}'
        "#__vite_hint_root *{box-sizing:border-box;}"
        "#__vite_hint_btn{cursor:pointer;border:none;background:#b0483a;color:#fff;font-weight:700;"
        "font-size:14px;padding:10px 14px;border-radius:999px;box-shadow:0 4px 14px rgba(0,0,0,.25);}"
        "#__vite_hint_panel{display:none;position:absolute;right:0;bottom:52px;width:320px;max-width:78vw;"
        "background:#fff;color:#1f2328;border:1px solid #e3e6ea;border-radius:12px;"
        "box-shadow:0 10px 30px rgba(0,0,0,.22);padding:14px 16px;}"
        "#__vite_hint_root.open #__vite_hint_panel{display:block;}"
        "#__vite_hint_root .vh-head{display:flex;justify-content:space-between;align-items:baseline;"
        "font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:#6b7280;margin-bottom:8px;}"
        "#__vite_hint_root .vh-item{display:grid;grid-template-columns:22px 1fr;gap:8px;padding:8px 0;"
        "border-top:1px solid #eef0f2;font-size:13.5px;line-height:1.55;}"
        "#__vite_hint_root .vh-item b{color:#b0483a;font-variant-numeric:tabular-nums;}"
        "#__vite_hint_root .vh-next{margin-top:10px;width:100%;cursor:pointer;border:1px solid #d7dbe0;"
        "background:#f6f7f9;color:#1f2328;font-weight:600;font-size:13px;padding:8px;border-radius:8px;}"
        "#__vite_hint_root .vh-none{margin-top:10px;font-size:12px;color:#9aa0a6;}"
        "#__vite_hint_root .vh-intro{font-size:12.5px;color:#6b7280;margin:0 0 4px;}"
        "</style>"
        '<div id="__vite_hint_root">'
        '<div id="__vite_hint_panel" role="dialog" aria-label="힌트">'
        '<div class="vh-head"><span>힌트 · 막혔을 때</span><span id="__vite_hint_count"></span></div>'
        '<p class="vh-intro" id="__vite_hint_intro">먼저 스스로 시도해 보세요. 필요할 때만 한 단계씩 열립니다.</p>'
        '<div id="__vite_hint_list"></div>'
        "</div>"
        '<button id="__vite_hint_btn" type="button">💡 힌트</button>'
        "</div>"
        "<script>(function(){"
        f"var H={payload};"
        "if(!H||!H.length)return;"
        "var root=document.getElementById('__vite_hint_root');"
        "var btn=document.getElementById('__vite_hint_btn');"
        "var list=document.getElementById('__vite_hint_list');"
        "var count=document.getElementById('__vite_hint_count');"
        "var intro=document.getElementById('__vite_hint_intro');"
        "var shown=0;"
        "function esc(s){return String(s).replace(/[&<>\"]/g,function(c){"
        "return{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c];});}"
        "function render(){"
        "count.textContent=shown+'/'+H.length;"
        "intro.style.display=shown?'none':'block';"
        "var html='';for(var i=0;i<shown;i++){"
        "html+='<div class=\"vh-item\"><b>'+String(i+1).padStart(2,'0')+"
        "'</b><span>'+esc(H[i])+'</span></div>';}"
        "if(shown<H.length){html+='<button class=\"vh-next\" id=\"__vite_hint_next\" type=\"button\">'+"
        "(shown?'다음 힌트':'힌트 열기')+' \\u2192</button>';}"
        "else{html+='<div class=\"vh-none\">힌트를 모두 열었습니다.</div>';}"
        "list.innerHTML=html;"
        "var nx=document.getElementById('__vite_hint_next');if(nx)nx.addEventListener('click',reveal);}"
        "function reveal(){if(shown>=H.length)return;shown++;render();"
        "try{if(window.parent&&window.parent!==window){"
        "window.parent.postMessage({type:'vite-hint-used',level:shown},'*');}}catch(e){}}"
        "btn.addEventListener('click',function(){root.classList.toggle('open');"
        "if(!list.innerHTML)render();});"
        "render();"
        "})();</script>"
    )


def _inject_hint_overlay(body: bytes, hints: list[str]) -> bytes:
    """챌린지 앱 HTML(bytes) 의 </body> 직전에 힌트 오버레이를 끼워 넣는다.

    이미 주입돼 있으면(마커 존재) 건드리지 않는다. </body> 가 없으면 끝에 붙인다.
    """
    if b"__vite_hint_root" in body:
        return body
    snippet = _hint_overlay_html(hints).encode("utf-8")
    idx = body.lower().rfind(b"</body>")
    if idx == -1:
        return body + snippet
    return body[:idx] + snippet + body[idx:]


class SpinUpRequest(BaseModel):
    name: str


class SubmitRequest(BaseModel):
    flag: str


def create_app(
    *,
    service: ChallengeService | None = None,
    challenges: list[Challenge] | None = None,
    reclaim_on_startup: bool = False,
    vibecutter_result_path: Path | None = _DEFAULT_VIBECUTTER_PATH,
) -> FastAPI:
    """앱을 조립한다. service/challenges 를 주입할 수 있어 테스트에서 Docker 를 우회한다.

    reclaim_on_startup=True 면 기동 시 이전 프로세스가 남긴 고아 컨테이너를 회수한다
    (Docker 가 없거나 실패해도 앱 기동은 막지 않는다).
    vibecutter_result_path 가 가리키는 파일이 있으면 /stats 가 자동도구 성공률을 읽는다
    (None 이면 VibeCutter 지표 비활성 — 항상 '벤치마크 대기').
    """
    # 배포 환경(Cloudflare Tunnel 등)에선 이 값을 설정해 접속 URL을 플랫폼 자신의 공인
    # 도메인(+아래 캐치올 프록시)으로 돌린다. 로컬 개발에선 미설정 = 기존 동작 그대로.
    public_base_url = os.environ.get("ULSANER_PUBLIC_BASE_URL")
    service = service or ChallengeService(public_base_url=public_base_url)
    challenges = DEFAULT_CHALLENGES if challenges is None else challenges
    by_name = {c.name: c for c in challenges}

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if reclaim_on_startup:
            try:
                removed = service.reclaim_orphans()
                if removed:
                    _log.info("기동 시 고아 컨테이너 %d개 회수: %s", len(removed), removed)
            except Exception as exc:  # noqa: BLE001 — docker 부재/실패는 치명적이지 않다
                _log.warning("기동 시 고아 회수 실패(무시하고 계속): %s", exc)
        yield

    app = FastAPI(
        title="Ulsaner Platform",
        description="매번 새로 생성되는 웹 취약점 훈련 엔진 — 플랫폼(검증 서비스 · 웹 UI)",
        version="0.2.0",
        lifespan=lifespan,
    )
    app.mount("/assets", StaticFiles(directory=_STATIC_DIR / "assets"), name="assets")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        # 정식 데모 UI(Modernist, Claude Design 핸드오프 재현·실배선). 비교용이던 대안
        # 디자인 2종(/a claymorphism, /v2 다크 콘솔)은 이 UI로 정착하며 제거했다
        # (드래프트는 git 이력에 남음).
        return (_STATIC_DIR / "index_dc.html").read_text(encoding="utf-8")

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
    def spin_up(req: SpinUpRequest, response: Response) -> dict:
        spec = by_name.get(req.name)
        if spec is None:
            raise HTTPException(status_code=404, detail=f"알 수 없는 챌린지: {req.name}")
        # 만원이면 비싼 번들 생성 전에 먼저 거절(만료분은 회수 후 재판정).
        service.sweep_expired()
        if service.at_capacity():
            raise HTTPException(
                status_code=503,
                detail="동시 인스턴스 상한에 도달했습니다. 잠시 후 다시 시도하세요.",
            )
        # 엔진 소스는 여기서 실번들을 생성(Docker 빌드·자가검증 포함, 수십 초 가능).
        try:
            bundle_dir, cleanup = spec.provision()
        except Exception as exc:  # 생성 실패(Docker 다운·엔진 오류 등)
            raise HTTPException(
                status_code=503,
                detail="인스턴스 생성에 실패했습니다 (Docker 데몬·엔진 상태를 확인하세요).",
            ) from exc
        try:
            result = service.spin_up(bundle_dir, name=spec.name, cleanup=cleanup)
        except CapacityError as exc:  # 경합으로 그 사이 꽉 찬 경우
            cleanup()
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except OrchestratorError as exc:  # 배포/헬스체크 실패(번들은 spin_up 이 이미 정리)
            raise HTTPException(
                status_code=503,
                detail="인스턴스 배포에 실패했습니다 (컨테이너가 뜨지 않음).",
            ) from exc
        # 이 브라우저가 지금 어떤 챌린지에 접속 중인지 기억해, 아래 캐치올 프록시가
        # 절대경로 fetch(/notes/search 등)를 올바른 컨테이너로 전달할 수 있게 한다.
        response.set_cookie(
            "ulsaner_instance", result["challenge_id"],
            max_age=1800, httponly=True, samesite="lax",
        )
        return result

    @app.get("/challenges/active")
    def active_session(request: Request) -> dict:
        # 새로고침 복원 — 이 브라우저의 진행 중 세션을 쿠키로 되찾는다. 만료분을 먼저
        # 회수해, 자리를 비운 사이 TTL 이 지난 세션은 정직하게 404(종료됨)로 알린다.
        challenge_id = request.cookies.get("ulsaner_instance")
        if not challenge_id:
            raise HTTPException(status_code=404, detail="활성 세션이 없습니다.")
        service.sweep_expired()
        view = service.session_view(challenge_id)
        if view is None:
            raise HTTPException(status_code=404, detail="세션이 만료되었거나 종료되었습니다.")
        return view

    @app.post("/challenges/{challenge_id}/submit")
    def submit(challenge_id: str, req: SubmitRequest) -> dict:
        try:
            result = service.submit_flag(challenge_id, req.flag)
        except ChallengeNotFound as exc:
            raise HTTPException(
                status_code=404, detail="챌린지를 찾을 수 없거나 이미 해결됨"
            ) from exc
        resp: dict = {"correct": result.correct}
        if result.correct:  # 정답일 때만 취약점 해설을 함께 준다(리빌).
            resp["reveal"] = result.reveal
        return resp

    @app.delete("/challenges/{challenge_id}")
    def teardown(challenge_id: str, response: Response) -> dict:
        # 인스턴스 종료(수동 teardown). 이미 없으면 조용히 성공(멱등).
        service.teardown(challenge_id)
        response.delete_cookie("ulsaner_instance")
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

        # VibeCutter 벤치마크(자동도구 성공률) — 결과 파일이 있으면 읽어 채운다.
        vibecutter, vibecutter_detail = _load_vibecutter(vibecutter_result_path)

        return {
            "attempts": attempts,
            "solved": solved,
            "success_rate": round(solved / attempts, 4) if attempts else 0.0,
            "by_tier": agg("tier"),
            "by_vuln": agg("vuln_type"),
            "by_challenge": agg("challenge_name"),  # 챌린지 슬롯별 시도·성공 횟수
            "vibecutter": vibecutter,
            "vibecutter_detail": vibecutter_detail,
        }

    # 캐치올 리버스 프록시 — 반드시 다른 모든 라우트/마운트 뒤 마지막에 등록한다
    # (Starlette는 등록 순서대로 매칭하므로, 위의 구체적인 경로들이 먼저 매칭되고
    # 이 라우트는 나머지 전부를 받는다). 챌린지 컨테이너는 127.0.0.1:<랜덤포트>에만
    # 바인딩돼 학생 브라우저에서 직접 못 여니, "이 브라우저가 지금 붙어있는 챌린지"를
    # 쿠키로 기억해두고 매칭 안 되는 모든 요청을 그 컨테이너로 그대로 전달한다.
    # 챌린지 프론트엔드가 fetch("/notes/search") 처럼 절대경로로 자기 API를 부르므로,
    # 경로 접두어 방식(/instances/<id>/...) 대신 쿠키 기반으로 라우팅한다.
    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def proxy_to_active_instance(full_path: str, request: Request) -> Response:
        challenge_id = request.cookies.get("ulsaner_instance")
        if not challenge_id:
            raise HTTPException(status_code=404)
        port = service.get_host_port(challenge_id)
        if port is None:
            raise HTTPException(status_code=404)
        # /play = 챌린지 앱의 루트. 그 외 경로는 동일 경로 그대로 전달.
        target_path = "" if full_path == "play" else full_path
        upstream_url = f"http://127.0.0.1:{port}/{target_path}"
        async with httpx.AsyncClient() as client:
            upstream = await client.request(
                request.method,
                upstream_url,
                params=request.query_params,
                headers={
                    k: v for k, v in request.headers.items()
                    if k.lower() not in ("host", "content-length")
                },
                content=await request.body(),
                timeout=10.0,
            )
        excluded_headers = {"content-encoding", "content-length", "transfer-encoding", "connection"}
        headers = {k: v for k, v in upstream.headers.items() if k.lower() not in excluded_headers}
        # '인스턴스 안에서' 힌트 — 챌린지 앱이 HTML 페이지를 돌려줄 때(200) 우하단 힌트 오버레이를
        # 주입한다. httpx 가 이미 압축을 풀어 .content 를 주고, content-encoding/length 는 위에서
        # 뺐으므로 본문을 늘려도 Response 가 길이를 다시 계산한다. JSON·정적자원 응답엔 주입 안 함.
        content = upstream.content
        if upstream.status_code == 200 and "text/html" in upstream.headers.get("content-type", "").lower():
            hints = service.get_active_hints(challenge_id)
            if hints:
                content = _inject_hint_overlay(content, hints)
        return Response(content=content, status_code=upstream.status_code, headers=headers)

    return app


# uvicorn 진입점: `uvicorn ulsaner_platform.app:app`
app = create_app(reclaim_on_startup=True)
