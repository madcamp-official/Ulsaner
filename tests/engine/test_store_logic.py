"""store 비즈니스 로직 결함 슬롯·익스플로잇 단위 테스트 (Docker 불필요).

수량 양수 검증이 빠지면 음수 수량으로 총액을 음수로 만들어 잔액 검사를 우회 → 프리미엄
상품(리워드=flag) 획득. IDOR/SQLi/BFLA 와 다른 클래스(앱 규칙 자체의 논리 허점).
"""

import random

import libcst as cst

from engine.bundle import STORE_EXPLOIT_BUILDERS
from engine.exploit_gen import build_store_logic_exploit
from engine.slots.store import build_store_logic_slot
from engine.store_params import build_seed_data

_CLEAN_PURCHASE = '''\
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from db import get_current_user, get_item_by_id

router = APIRouter()


class PurchaseReq(BaseModel):
    item_id: int
    quantity: int


@router.post("/store/purchase")
def purchase(req: PurchaseReq, user=Depends(get_current_user)):
    item = get_item_by_id(req.item_id)
    if item is None:
        raise HTTPException(404)
    if req.quantity < 1:
        raise HTTPException(400)
    total = item.price * req.quantity
    if total > user.balance:
        raise HTTPException(402)
    return {"purchased": item.name, "reward": item.secret}
'''


def test_slot_metadata():
    slot = build_store_logic_slot()
    assert slot.vuln_type == "logic"
    assert slot.tier == "easy"
    assert slot.target_file == "routes/store.py"
    assert slot.target_function == "purchase"


def test_slot_removes_quantity_guard_only():
    out = build_store_logic_slot().transform(cst.parse_module(_CLEAN_PURCHASE)).code
    assert "quantity < 1" not in out          # 수량 양수 검증 제거됨
    assert "total > user.balance" in out      # 잔액 검사는 그대로(음수 총액이 통과)
    assert "item is None" in out              # 404 검사도 그대로
    assert "reward" in out                    # 본문 유지


def test_exploit_is_post_with_negative_quantity_on_premium():
    seed, flag = build_seed_data(random.Random(1))
    exploit = build_store_logic_exploit(seed, flag)
    assert exploit.method == "POST"
    assert exploit.path == "/store/purchase"
    assert exploit.body["quantity"] == -1
    # 표적은 secret(=flag) 이 있는 프리미엄 상품
    premium = next(i for i in seed["items"] if i["secret"])
    assert exploit.body["item_id"] == premium["id"]
    assert exploit.expected_flag == flag


def test_logic_registered_in_store_exploit_builders():
    assert STORE_EXPLOIT_BUILDERS["logic"] is build_store_logic_exploit


def test_premium_unaffordable_at_seed_balance():
    seed, _ = build_seed_data(random.Random(1))
    premium = next(i for i in seed["items"] if i["secret"])
    balance = seed["users"][0]["balance"]
    assert premium["price"] > balance  # 정상 수량으론 못 산다 → 로직 결함이 유일한 경로
