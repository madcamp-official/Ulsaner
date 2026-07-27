"""easy-idor-seed9896에서 VibeCutter scan→verify 전체를 재현하는 드라이버.

VibeCutter는 vendoring 대상이 아니라 별도 클론이라, 이 스크립트는 그 클론 경로를
sys.path에 넣어 VibeCutter의 실제 candidate 빌더 + access-control verifier를 그대로
호출한다. prefilter 버그 수정(idor-prefilter-authz-blindspot.patch)이 적용돼 있으면
scan이 후보 1개를 만들고, verifier가 라이브 타깃에서 IDOR를 재현해 verified=True를 낸다.

사용 전 환경변수로 경로를 맞춘다(기본값은 개발 셋업 기준):
    VC_ROOT   VibeCutter 클론 경로
    VC_PY     그 클론의 venv 파이썬
    TARGET_SRC 감사 타깃(easy-idor-seed9896) 소스 경로
그리고 타깃 앱이 http://127.0.0.1:8000 에 떠 있어야 한다.

    $VC_PY docs/vibecutter-patches/reproduce_seed9896.py
"""
import os
import sys
from pathlib import Path

VC_ROOT = Path(os.environ.get("VC_ROOT", str(Path.home() / "Documents/몰입캠프/VibeCutter")))
TARGET_SRC = os.environ.get("TARGET_SRC", str(Path.home() / "vibecutter-targets/easy-idor-seed9896"))
sys.path.insert(0, str(VC_ROOT))

from runtime.provisioning import VerifierProvisioning, ProvisioningStrategy
import surface.candidates as C
from verifiers.access_control import verify

RUN_ID = "repro-seed9896"

prov = VerifierProvisioning(
    target_id="easy-idor-seed9896",
    base_url="http://127.0.0.1:8000",
    auth_mode="bearer",
    strategy=ProvisioningStrategy.SELF_SIGNUP,
    notes="Ulsaner IDOR 벤치마크 재현",
)

stock = C.find_idor_suspects(TARGET_SRC)
print(f"[prefilter] IDOR suspects = {len(stock)}  (수정 전=0, 수정 후=1 이어야 함)")

bridge = C.candidates_for_target(
    RUN_ID, prov, TARGET_SRC,
    self_signup_hints=C._SELF_SIGNUP_HINTS.get("easy-idor-seed9896"),
)
print(f"[scan] candidates={len(bridge.candidates)} blocked={len(bridge.blocked)}")
for b in bridge.blocked:
    print("   blocked:", b)
if not bridge.candidates:
    sys.exit("FAIL: 후보 없음 — prefilter 패치가 적용됐는지 확인")

cand = next((c for c in bridge.candidates if c.vuln_class == "idor"), None)
print(f"[candidate] id={cand.id} cwe={cand.cwe} endpoint={cand.endpoint}")

out = verify(RUN_ID, cand, max_requests=12)
print(f"\n[VERIFY] verified={out.verified}")
print(f"[VERIFY] reason={out.reason}")
sys.exit(0 if out.verified else 2)
