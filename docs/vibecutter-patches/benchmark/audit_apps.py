"""Phase 2: 생성된 IDOR/SQLi 앱들을 VibeCutter로 감사해 성공률을 낸다.

VibeCutter 클론 환경(`.venv/bin/python`)에서 실행한다. prefilter 인가맹점 수정 패치
(../idor-prefilter-authz-blindspot.patch)가 적용돼 있어야 IDOR fixed 결과가 나온다.
각 앱마다 uvicorn 기동 → VibeCutter 탐지·검증 + 독립 ground-truth 익스플로잇 → 정리.

  VC_ROOT=/path/to/VibeCutter VCVENV_PY=/path/to/target/.vcvenv/bin/python \
    $VC_ROOT/.venv/bin/python audit_apps.py <workdir> <out.json>

지표(클래스 독립):
- vc_detected_stock/fixed : VibeCutter 정적 스캐너가 후보를 만들었는가(IDOR=prefilter, SQLi=injection prefilter)
- vc_verified             : VibeCutter 자체 verifier가 재현·확정했는가
- exploitable             : Ulsaner 레퍼런스 익스플로잇(독립 ground truth)이 flag를 뽑았는가
- solved(=results)        : vc_detected_fixed AND vc_verified (VibeCutter 파이프라인이 실제로 잡는 조건)
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
    "VCVENV_PY", str(Path.home() / "vibecutter-targets/easy-idor-seed9896/.vcvenv/bin/python")
)
sys.path.insert(0, str(VC))

import httpx
from contracts.schemas import Candidate
from runtime.provisioning import VerifierProvisioning, ProvisioningStrategy
from verifiers.access_control import verify as verify_idor
from verifiers.injection import verify as verify_sqli
import surface.candidates as SC
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


def idor_detected(app_dir: str, stock: bool) -> bool:
    orig = G.current_user_scopes_ownership
    if stock:
        G.current_user_scopes_ownership = lambda sig, body: references_current_user(f"{sig}\n{body}")
    try:
        return any(s.handler == "get_note" for s in G.find_idor_suspects(app_dir))
    finally:
        G.current_user_scopes_ownership = orig


def audit_idor(e, port):
    base = f"http://127.0.0.1:{port}"
    det_stock = idor_detected(e["app_dir"], stock=True)
    det_fixed = idor_detected(e["app_dir"], stock=False)
    os.environ["VIBECUTTER_BENCH_TOK"] = e["attacker_token"]
    cand = Candidate(
        id=f"bench-{e['seed']}", run_id=f"bench-{e['seed']}", cwe="CWE-639",
        vuln_class="idor", endpoint="/notes/{id}",
        attack_params={
            "base_url": base, "auth_mode": "bearer_fixture",
            "baseline_path": e["baseline_path"], "attack_path": e["attack_path"],
            "victim_marker": e["victim_marker"], "owner_marker": e["owner_marker"],
            "baseline_token_env": "VIBECUTTER_BENCH_TOK",
        },
    )
    vc_verified = verify_idor(cand.run_id, cand, max_requests=8).verified
    # 독립 ground truth: 공격자 토큰으로 피해자 노트 직접 조회 → flag 노출?
    r = httpx.get(f"{base}{e['attack_path']}", headers={"Authorization": f"Bearer {e['attacker_token']}"}, timeout=5)
    exploitable = e["flag"] in r.text
    return det_stock, det_fixed, vc_verified, exploitable


def audit_sqli(e, port):
    base = f"http://127.0.0.1:{port}"
    prov = VerifierProvisioning(target_id=f"bench-{e['seed']}", base_url=base,
                                auth_mode="none", strategy=ProvisioningStrategy.SELF_SIGNUP, notes="bench")
    bridge = SC.injection_xss_candidates(f"bench-{e['seed']}", prov, e["app_dir"])
    sqli_cands = [c for c in bridge.candidates if (c.vuln_class or "").lower() in ("sqli", "injection")]
    detected = len(sqli_cands) > 0
    if detected:
        vc_verified = verify_sqli(f"bench-{e['seed']}", sqli_cands[0], max_requests=12).verified
    else:
        # 후보가 없어도 검증기 자체 능력을 기록: 손으로 후보를 구성해 시도
        cand = Candidate(id=f"bench-{e['seed']}", run_id=f"bench-{e['seed']}", cwe="CWE-89",
                         vuln_class="sqli", endpoint=e["inject_path"],
                         attack_params={"base_url": base, "inject_path": e["inject_path"],
                                        "inject_param": e["inject_param"], "inject_method": "GET",
                                        "inject_location": "query", "baseline_value": "a"})
        vc_verified = verify_sqli(f"bench-{e['seed']}", cand, max_requests=12).verified
    # 독립 ground truth: UNION 페이로드로 비공개 note body(flag) 유출?
    r = httpx.get(f"{base}{e['inject_path']}", params={e["inject_param"]: e["exploit_payload"]}, timeout=5)
    exploitable = e["flag"] in r.text
    return detected, detected, vc_verified, exploitable  # sqli는 stock/fixed 구분 없음


rows = []
for e in index:
    port = free_port()
    proc = subprocess.Popen(
        [VCVENV_PY, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=e["app_dir"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_health(port):
            raise RuntimeError(f"app {e['vuln_class']}-{e['tier']}-{e['seed']} 기동 실패")
        fn = audit_idor if e["vuln_class"] == "idor" else audit_sqli
        det_stock, det_fixed, vc_verified, exploitable = fn(e, port)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    rows.append({
        "vuln_class": e["vuln_class"], "tier": e["tier"], "seed": e["seed"],
        "vc_detected_stock": det_stock, "vc_detected_fixed": det_fixed,
        "vc_verified": vc_verified, "exploitable": exploitable,
        "solved_stock": det_stock and vc_verified,
        "solved_fixed": det_fixed and vc_verified,
    })
    print(f"  {e['vuln_class']}-{e['tier']}-{e['seed']}: detected(stock={det_stock},fixed={det_fixed}) "
          f"vc_verified={vc_verified} exploitable={exploitable} → solved_fixed={rows[-1]['solved_fixed']}")

rate = lambda rs: round(sum(rs) / len(rs), 4) if rs else 0.0
by_class = {}
for r in rows:
    by_class.setdefault(r["vuln_class"] + "-" + r["tier"], []).append(r["solved_fixed"])
result = {
    "_comment": (
        "VibeCutter(자동 보안도구)가 Ulsaner 생성 취약 인스턴스를 잡는 비율. results/success_rate는 "
        "IDOR prefilter 인가맹점 수정을 적용한 VibeCutter(fixed) 기준. exploitable(전부 True)=Ulsaner "
        "레퍼런스 익스플로잇이 flag를 뽑은 독립 ground truth — 미탐은 취약점 부재가 아니라 자동도구 한계다. "
        "easy-idor=수정 후 잡음, hard-idor=owner→workspace 위장이라 정적 prefilter가 놓침, "
        "easy-sqli=SQL sink이 서비스 계층(db.py)이라 injection prefilter가 라우트를 못 붙여 미탐."
    ),
    "seeds": [r["seed"] for r in rows],
    "results": [r["solved_fixed"] for r in rows],
    "success_rate": rate([r["solved_fixed"] for r in rows]),
    "success_rate_stock": rate([r["solved_stock"] for r in rows]),
    "success_rate_by_class": {k: rate(v) for k, v in by_class.items()},
    "detail": rows,
}
OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2))
print(f"\nfixed={result['success_rate']} stock={result['success_rate_stock']} by_class={result['success_rate_by_class']} → {OUT}")
