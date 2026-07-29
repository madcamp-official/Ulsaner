from db import get_current_user, get_flag, get_user, make_token
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

router = APIRouter()


class LoginReq(BaseModel):
    username: str


@router.post("/login")
def login(req: LoginReq):
    user = get_user(req.username)
    if user is None:
        raise HTTPException(401, "unknown user")
    token = make_token({"sub": user["username"], "role": user["role"]})
    return {"token": token}


@router.get("/me")
def me(user=Depends(get_current_user)):
    return {"sub": user.sub, "role": user.role}


@router.get("/admin/flag")
def admin_flag(user=Depends(get_current_user)):
    # 관리자 전용. 토큰의 role 클레임으로 판정 — 서명이 검증되지 않으면 위조된 admin 토큰이 통과한다.
    if user.role != "admin":
        raise HTTPException(403, "admin only")
    return {"flag": get_flag()}
