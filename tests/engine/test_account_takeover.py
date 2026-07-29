"""계정 탈취 다단계 체인 — 슬롯·다단계 익스플로잇·검증 엔진 단위 테스트 (Docker 불필요).

예측 가능한 재설정 토큰(md5(username+salt))으로 관리자 계정을 탈취하는 4단계 체인. 다단계
자가검증 엔진(_run_chain: 값 추출·치환)이 이 체인을 스크립트로 재현한다.
"""

import hashlib
import random

import libcst as cst

from engine.bundle import ACCOUNTS_EXPLOIT_BUILDERS
from engine.exploit_gen import ExploitStep, ReferenceExploit, build_account_takeover_exploit
from engine.accounts_params import build_seed_data
from engine.slots.reset_token import build_reset_token_slot
from engine.verifier import _subst

_CLEAN_MAKE_TOKEN = '''\
import secrets


def _make_reset_token(username: str) -> str:
    return secrets.token_hex(16)
'''


def test_slot_makes_reset_token_predictable():
    out = build_reset_token_slot().transform(cst.parse_module(_CLEAN_MAKE_TOKEN)).code
    assert "secrets.token_hex" not in out            # 강한 랜덤 제거
    assert "hashlib.md5((username + _SALT)" in out    # 예측 가능(md5(username+salt))으로 대체


def test_slot_metadata():
    slot = build_reset_token_slot()
    assert slot.vuln_type == "takeover"
    assert slot.tier == "hard"
    assert slot.target_file == "db.py"
    assert slot.target_function == "_make_reset_token"


def test_exploit_is_multistep_chain_targeting_admin_reset():
    seed, flag = build_seed_data(random.Random(1))
    exploit = build_account_takeover_exploit(seed, flag)
    assert exploit.expected_flag == flag
    assert exploit.steps is not None and len(exploit.steps) == 4
    salt = seed["reset_salt"]
    admin_token = hashlib.md5(("admin" + salt).encode()).hexdigest()
    # 2번째 스텝(reset/confirm)이 계산한 admin 토큰을 쓴다
    confirm = exploit.steps[1]
    assert confirm.path == "/reset/confirm"
    assert confirm.body["username"] == "admin"
    assert confirm.body["token"] == admin_token
    # 3번째(login)에서 세션을 추출해 4번째(admin/flag)에서 쓴다
    assert exploit.steps[2].extract and "session" in exploit.steps[2].extract
    assert "{session}" in exploit.steps[3].headers["Authorization"]


def test_takeover_registered_in_accounts_exploit_builders():
    assert ACCOUNTS_EXPLOIT_BUILDERS["takeover"] is build_account_takeover_exploit


def test_verifier_subst_replaces_extracted_vars():
    assert _subst("Bearer {session}", {"session": "abc123"}) == "Bearer abc123"
    assert _subst("no placeholder", {"x": "y"}) == "no placeholder"


def test_reference_exploit_single_request_still_supported():
    # steps 없는 단일 요청 형태는 그대로 동작(하위호환).
    ex = ReferenceExploit(method="GET", path="/x", headers={}, expected_flag="F")
    assert ex.steps is None
    step = ExploitStep("GET", "/y")
    assert step.method == "GET" and step.extract is None
