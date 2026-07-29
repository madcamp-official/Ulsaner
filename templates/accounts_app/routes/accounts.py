from db import (
    check_password,
    confirm_reset,
    create_session,
    get_current_user,
    get_flag,
    get_inbox,
    issue_reset,
    list_users,
)
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

router = APIRouter()


@router.get("/users")
def users():
    # 공개 디렉터리 — 어떤 계정이 있는지(admin 포함) 드러난다.
    return list_users()


class LoginReq(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(req: LoginReq):
    if not check_password(req.username, req.password):
        raise HTTPException(401, "invalid credentials")
    return {"token": create_session(req.username)}


class ResetRequestReq(BaseModel):
    username: str


@router.post("/reset/request")
def reset_request(req: ResetRequestReq):
    # 공개 '비밀번호 찾기' — 해당 계정 인박스로 토큰을 보낸다(응답엔 노출 안 함).
    issue_reset(req.username)
    return {"sent": True}


class ResetConfirmReq(BaseModel):
    username: str
    token: str
    new_password: str


@router.post("/reset/confirm")
def reset_confirm(req: ResetConfirmReq):
    if not confirm_reset(req.username, req.token, req.new_password):
        raise HTTPException(400, "invalid or expired token")
    return {"reset": True}


@router.get("/inbox")
def inbox(user=Depends(get_current_user)):
    # 로그인한 사용자 '본인'의 메일함만 본다.
    return {"messages": get_inbox(user["username"])}


@router.get("/admin/flag")
def admin_flag(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "admin only")
    return {"flag": get_flag()}
