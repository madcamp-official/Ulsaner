"""easy/idor fixture 앱 — 손으로 만든 취약 멀티유저 노트 서비스.

이 앱은 플랫폼 선개발용 기준 번들이다(엔진이 생성하는 실번들의 형태를 흉내낸 것).
취약점: GET /notes/{id} 가 소유권을 검증하지 않아, 인증된 아무 사용자나
다른 사용자의 비공개 노트를 읽을 수 있다 (IDOR — Broken Object Level Authorization).

과제: 학생은 alice 계정(Bearer alice-token)으로 로그인해, 다른 사용자의
비공개 노트를 읽어 flag 를 획득한다.
"""

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

app = FastAPI(title="Notes (easy/idor fixture)")

_LANDING = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Notes API — 취약점 훈련 대상</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 640px; margin: 56px auto; padding: 0 22px; line-height: 1.75; color: #201e1d; }
  h1 { font-size: 22px; margin-bottom: 4px; }
  code { background: #eae9e9; padding: 2px 6px; border-radius: 4px; font-family: ui-monospace, monospace; }
  a { color: #b0483a; } .muted { color: #6b6767; font-size: 14px; }
</style></head><body>
<h1>Notes API</h1>
<p class="muted">취약점 훈련 대상 — 이건 홈페이지가 아니라 <b>공략할 API</b>입니다. 엔드포인트를 직접 찔러 취약점을 찾으세요.</p>
<p><b>인증</b> · 당신은 <code>alice</code> 계정입니다. 요청 헤더에 <code>Authorization: Bearer alice-token</code> 을 넣으세요.</p>
<p><b>탐색</b> · <code>GET /notes</code> 로 워크스페이스의 노트 목록(메타데이터)을 볼 수 있고, <code>GET /notes/{id}</code> 로 개별 노트를 엽니다. <a href="/docs">/docs</a>(Swagger UI)도 있습니다.</p>
<p><b>목표</b> · 다른 사용자의 비공개 노트에 심긴 <code>FLAG{…}</code> 를 읽어 훈련장에 제출하세요.</p>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    # 학생이 접속 URL 을 그냥 열었을 때 404 대신 안내(취약점은 노출하지 않음).
    return _LANDING

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
# 각 노트에 title(메타데이터)을 둔다 — 목록 엔드포인트가 이걸로 '발견 경로'를 제공한다.
NOTES = {
    1: {"id": 1, "owner_id": 1, "private": True, "title": "장보기 목록", "content": "alice의 개인 메모: 우유, 계란"},
    2: {"id": 2, "owner_id": 1, "private": False, "title": "공개 메모", "content": "alice의 공개 노트"},
    42: {
        "id": 42,
        "owner_id": 2,
        "private": True,
        "title": "팀 비공개 노트",
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


@app.get("/notes")
def list_notes(authorization: str | None = Header(default=None)) -> list[dict]:
    """워크스페이스 피드 — 모든 노트의 '메타데이터'만 반환한다(내용 제외).

    이건 정상 기능이다: 로그인 사용자는 노트 목록(누가 어떤 제목의 노트를 가졌는지)을 본다.
    여기서 다른 사용자의 노트 id·소유자·비공개 여부를 알 수 있다 = 발견 경로.
    내용(content, flag 포함)은 절대 여기 노출하지 않는다 — 내용은 /notes/{id} 에서만.
    """
    current_user(authorization)  # 피드는 로그인 사용자에게만
    return [
        {
            "id": n["id"],
            "owner_id": n["owner_id"],
            "owner": USERS[n["owner_id"]]["name"],
            "title": n["title"],
            "private": n["private"],
        }
        for n in sorted(NOTES.values(), key=lambda x: x["id"])
    ]


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
