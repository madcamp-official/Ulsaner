"""JWT 위조(서명 미검증) 슬롯·익스플로잇 단위 테스트 (Docker 불필요).

verify_token 의 서명 비교가 빠지면 서명값과 무관하게 payload(role:"admin")를 위조한 토큰이
통과 → 관리자 전용 /admin/flag 접근. 토큰 구조 분석·위조의 다단계 추론이 필요한 클래스.
"""

import base64
import json
import random

import libcst as cst

from engine.bundle import PORTAL_EXPLOIT_BUILDERS
from engine.exploit_gen import build_jwt_forge_exploit
from engine.portal_params import build_seed_data
from engine.slots.jwt_forge import build_jwt_forge_slot

_CLEAN_VERIFY = '''\
import hmac
from fastapi import HTTPException


def verify_token(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(401, "malformed token")
    header_b64, payload_b64, signature = parts
    if not hmac.compare_digest(signature, _sign(f"{header_b64}.{payload_b64}")):
        raise HTTPException(401, "invalid signature")
    return json.loads(_b64url_decode(payload_b64))
'''


def test_slot_metadata():
    slot = build_jwt_forge_slot()
    assert slot.vuln_type == "jwt"
    assert slot.tier == "easy"
    assert slot.target_file == "db.py"
    assert slot.target_function == "verify_token"


def test_slot_removes_signature_check_only():
    out = build_jwt_forge_slot().transform(cst.parse_module(_CLEAN_VERIFY)).code
    assert "compare_digest" not in out       # 서명 검증 제거됨
    assert "invalid signature" not in out
    assert "malformed token" in out          # 형식 검사(len==3)는 그대로
    assert "json.loads" in out               # payload 디코드는 그대로


def test_exploit_forges_admin_role_with_any_signature():
    seed, flag = build_seed_data(random.Random(1))
    exploit = build_jwt_forge_exploit(seed, flag)
    assert exploit.method == "GET"
    assert exploit.path == "/admin/flag"
    token = exploit.headers["Authorization"].removeprefix("Bearer ")
    header_b64, payload_b64, _sig = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    assert payload["role"] == "admin"        # 위조한 관리자 클레임
    assert exploit.expected_flag == flag


def test_jwt_registered_in_portal_exploit_builders():
    assert PORTAL_EXPLOIT_BUILDERS["jwt"] is build_jwt_forge_exploit


def test_seed_secret_is_strong_and_user_is_not_admin():
    seed, _ = build_seed_data(random.Random(1))
    assert len(seed["secret"]) >= 16              # 추측 불가한 서명키 → 정상 위조 불가
    assert all(u["role"] != "admin" for u in seed["users"])  # 관리자로 로그인은 못 한다
