"""Phase 2: 생성된 IDOR 앱들을 VibeCutter로 감사해 성공률을 낸다.

VibeCutter 클론 환경(`.venv/bin/python`, httpx/pydantic/surface/verifiers 포함)에서 실행한다.
prefilter 인가맹점 수정 패치(../idor-prefilter-authz-blindspot.patch)가 적용돼 있어야
fixed 결과가 나온다. 각 앱마다 uvicorn 기동 → prefilter 탐지(stock/fixed) → verifier 재현 →
정리. 결과를 platform/data 형식({seeds,results,success_rate})으로 저장한다.

  VC_ROOT=/path/to/VibeCutter VCVENV_PY=/path/to/target/.vcvenv/bin/python \
    $VC_ROOT/.venv/bin/python audit_apps.py <workdir> <out.json>

- detected_stock/fixed : 정적 prefilter가 get_note를 IDOR 의심으로 잡는가
- exploitable          : verifier가 라이브에서 교차 조회 유출을 재현했는가(ground truth)
- solved_*             : detected_* AND exploitable (VibeCutter 파이프라인이 실제로 잡는 조건)
"""
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

VC = Path(os.environ.get("VC_ROOT", str(Path.home() / "Documents/몰입캠프/VibeCutter")))
VCVENV_PY = os.environ.get(
    "VCVENV_PY",
    str(Path.home() / "vibecutter-targets/easy-idor-seed9896/.vcvenv/bin/python"),
)
sys.path.insert(0, str(VC))

import httpx
from contracts.schemas import Candidate
from verifiers.access_control import verify
import surface.graph as G
from surface.roles import references_current_user

WORK = Path(sys.argv[1])
OUT = Path(sys.argv[2])
index = json.loads((WORK / "index.json").read_text())


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_health(port: int, timeout=15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"http://127.0.0.1:{port}/openapi.json", timeout=1.0).status_code == 200:
                return True
        except Exception:
            time.sleep(0.3)
    return False


def flags_get_note(app_dir: str, stock: bool) -> bool:
    """prefilter가 get_note를 의심으로 잡는지. stock=True면 수정 전 로직으로 계산."""
    orig = G.current_user_scopes_ownership
    if stock:
        G.current_user_scopes_ownership = lambda sig, body: references_current_user(f"{sig}\n{body}")
    try:
        return any(s.handler == "get_note" for s in G.find_idor_suspects(app_dir))
    finally:
        G.current_user_scopes_ownership = orig


rows = []
for e in index:
    port = free_port()
    proc = subprocess.Popen(
        [VCVENV_PY, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=e["app_dir"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_health(port):
            raise RuntimeError(f"app {e['tier']}-{e['seed']} 기동 실패")
        detected_stock = flags_get_note(e["app_dir"], stock=True)
        detected_fixed = flags_get_note(e["app_dir"], stock=False)
        os.environ["VIBECUTTER_BENCH_TOK"] = e["attacker_token"]
        cand = Candidate(
            id=f"bench-{e['tier']}-{e['seed']}", run_id=f"bench-{e['tier']}-{e['seed']}",
            cwe="CWE-639", vuln_class="idor", endpoint="/notes/{id}",
            attack_params={
                "base_url": f"http://127.0.0.1:{port}", "auth_mode": "bearer_fixture",
                "baseline_path": e["baseline_path"], "attack_path": e["attack_path"],
                "victim_marker": e["victim_marker"], "owner_marker": e["owner_marker"],
                "baseline_token_env": "VIBECUTTER_BENCH_TOK",
            },
        )
        exploitable = verify(cand.run_id, cand, max_requests=8).verified
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    rows.append({
        "tier": e["tier"], "seed": e["seed"],
        "detected_stock": detected_stock, "detected_fixed": detected_fixed,
        "exploitable": exploitable,
        "solved_stock": detected_stock and exploitable,
        "solved_fixed": detected_fixed and exploitable,
    })
    print(f"  {e['tier']}-{e['seed']}: detected(stock={detected_stock},fixed={detected_fixed}) "
          f"exploitable={exploitable}")

rate = lambda rs: round(sum(rs) / len(rs), 4) if rs else 0.0
result = {
    "_comment": (
        "VibeCutter(자동 보안도구)가 Ulsaner 생성 IDOR 인스턴스를 잡는 비율. results/success_rate는 "
        "prefilter 인가맹점 수정을 적용한 VibeCutter(fixed) 기준 — easy-idor는 잡지만 hard-idor는 "
        "코드가 겉보기엔 스코프(user.workspace_id 사용)라 prefilter가 놓쳐 미탐. 수정 전(stock)은 easy조차 "
        "미탐(success_rate_stock). exploitable=verifier가 실제 재현한 ground truth(전부 True) — hard 미탐은 "
        "'취약점이 없어서'가 아니라 '자동 prefilter가 위장을 못 알아봐서'다."
    ),
    "seeds": [r["seed"] for r in rows],
    "results": [r["solved_fixed"] for r in rows],
    "success_rate": rate([r["solved_fixed"] for r in rows]),
    "success_rate_stock": rate([r["solved_stock"] for r in rows]),
    "detail": rows,
}
OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2))
print(f"\nfixed success_rate={result['success_rate']}  stock success_rate={result['success_rate_stock']} → {OUT}")
