from db import get_current_user, get_item_by_id, list_items
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

router = APIRouter()


@router.get("/me")
def me(user=Depends(get_current_user)):
    return {"id": user.id, "name": user.name, "balance": user.balance}


@router.get("/store/items")
def items():
    # 공개 카탈로그(비밀 제외). 프리미엄 상품도 목록엔 보이지만 reward 는 '구매 성공'해야 나온다.
    return [{"id": i.id, "name": i.name, "price": i.price} for i in list_items()]


class PurchaseReq(BaseModel):
    item_id: int
    quantity: int


@router.post("/store/purchase")
def purchase(req: PurchaseReq, user=Depends(get_current_user)):
    item = get_item_by_id(req.item_id)
    if item is None:
        raise HTTPException(404, "no such item")
    if req.quantity < 1:
        raise HTTPException(400, "quantity must be at least 1")
    total = item.price * req.quantity
    if total > user.balance:
        raise HTTPException(402, "insufficient balance")
    # 구매 성공 — 구매한 상품의 리워드(프리미엄이면 flag)를 준다.
    return {"purchased": item.name, "quantity": req.quantity, "total": total, "reward": item.secret}
