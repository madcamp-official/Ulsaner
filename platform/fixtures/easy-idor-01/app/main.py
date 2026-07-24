"""easy/idor fixture 앱 — 손으로 만든 취약 멀티유저 노트 서비스.

이 앱은 플랫폼 선개발용 기준 번들이다(엔진이 생성하는 실번들의 형태를 흉내낸 것).
취약점: GET /notes/{id} 가 소유권을 검증하지 않아, 인증된 아무 사용자나
다른 사용자의 비공개 노트를 읽을 수 있다 (IDOR — Broken Object Level Authorization).

과제: 학생은 alice 계정(Bearer alice-token)으로 로그인해, 다른 사용자의
비공개 노트를 읽어 flag 를 획득한다.
"""

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Notes (easy/idor fixture)")

# --- 시드 데이터 -------------------------------------------------------------
# 토큰 -> user_id
TOKENS = {
    "alice-token": 1,
    "bob-token": 2,
}

USERS = {
    1: {"id": 1, "name": "alice"},
    2: {"id": 2, "name": "bob"},
}

# flag 는 bob(id=2) 의 비공개 노트(id=42)에 심겨 있다.
NOTES = {
    1: {"id": 1, "owner_id": 1, "private": True, "content": "alice의 개인 메모: 장보기 목록"},
    2: {"id": 2, "owner_id": 1, "private": False, "content": "alice의 공개 노트"},
    42: {
        "id": 42,
        "owner_id": 2,
        "private": True,
        "content": "bob의 비공개 노트: FLAG{idor_bob_private_2f9c}",
    },
}


# --- 인증 --------------------------------------------------------------------
def current_user(authorization: str | None) -> dict:
    """Bearer 토큰으로 현재 사용자 해석. 미인증은 401."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="인증이 필요합니다")
    token = authorization[len("Bearer ") :]
    user_id = TOKENS.get(token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰")
    return USERS[user_id]


# --- 라우트 ------------------------------------------------------------------
@app.get("/me")
def me(authorization: str | None = Header(default=None)) -> dict:
    return current_user(authorization)


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str | None = Header(default=None)) -> dict:
    user = current_user(authorization)  # 인증은 강제
    note = NOTES.get(note_id)
    if note is None:
        raise HTTPException(status_code=404, detail="노트를 찾을 수 없습니다")
    # 취약점: 여기서 note["owner_id"] == user["id"] 소유권 검증이 빠져 있다.
    # 원래라면 남의 비공개 노트는 403 이어야 한다.
    _ = user
    return note
