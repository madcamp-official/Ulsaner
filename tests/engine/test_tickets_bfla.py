"""BFLA(Broken Function Level Authorization) 슬롯·익스플로잇 단위 테스트 (Docker 불필요).

tickets 를 notes 와 다른 취약 클래스로 차별화한 것: 관리자 전용 대량조회(/tickets/export)의
함수 레벨 인가가 빠져, 일반 사용자가 전체 기밀 티켓을 덤프한다. IDOR(객체 id 열거)이 아니라
'숨은 특권 엔드포인트 발견'이 관건.
"""

import random

import libcst as cst

from engine.bundle import TICKETS_EXPLOIT_BUILDERS
from engine.exploit_gen import build_tickets_bfla_exploit
from engine.slots.tickets import build_tickets_bfla_slot
from engine.tickets_params import build_seed_data

_CLEAN_EXPORT = '''\
from fastapi import APIRouter, HTTPException, Depends
from db import get_current_user, list_tickets_in_workspace

router = APIRouter()


@router.get("/tickets/export")
def export_tickets(user=Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(403)
    return [{"id": t.id, "description": t.description} for t in list_tickets_in_workspace(user.workspace_id)]
'''


def test_slot_metadata():
    slot = build_tickets_bfla_slot()
    assert slot.vuln_type == "bfla"
    assert slot.tier == "easy"
    assert slot.target_file == "routes/reports.py"
    assert slot.target_function == "export_tickets"


def test_slot_removes_admin_guard():
    out = build_tickets_bfla_slot().transform(cst.parse_module(_CLEAN_EXPORT)).code
    assert "is_admin" not in out  # 관리자 가드 제거됨
    assert "403" not in out       # 403 raise 도 함께 사라짐
    assert "list_tickets_in_workspace" in out  # 본문(덤프)은 그대로


def test_exploit_targets_hidden_export_with_non_admin_token():
    seed, flag = build_seed_data(random.Random(1))
    exploit = build_tickets_bfla_exploit(seed, flag)
    assert exploit.method == "GET"
    assert exploit.path == "/tickets/export"
    # 공격자 = 일반 사용자(bob, users[1]) — 관리자 아님
    assert exploit.headers["X-User-Token"] == seed["users"][1]["token"]
    assert exploit.expected_flag == flag


def test_bfla_registered_in_tickets_exploit_builders():
    assert TICKETS_EXPLOIT_BUILDERS["bfla"] is build_tickets_bfla_exploit
