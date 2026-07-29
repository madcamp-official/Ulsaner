import hashlib  # noqa: F401 — 취약 버전(_make_reset_token 슬롯)이 주입하는 md5 가 사용
import json
import pathlib
import secrets

from fastapi import Header, HTTPException

_SEED_PATH = pathlib.Path(__file__).parent / "seed_data.json"


def _load_seed() -> dict:
    with open(_SEED_PATH) as f:
        return json.load(f)


_SEED = _load_seed()
_SALT = _SEED["reset_salt"]
_FLAG = _SEED["flag"]

# 가변 상태(인메모리) — 한 인스턴스 수명 동안 유지.
_users = {u["username"]: dict(u) for u in _SEED["users"]}   # username -> {password, role}
_sessions: dict[str, str] = {}                              # session token -> username
_reset_tokens: dict[str, str] = {}                          # username -> 발급된 재설정 토큰
_inboxes: dict[str, list[str]] = {u: [] for u in _users}    # username -> 메일 목록


def _make_reset_token(username: str) -> str:
    return secrets.token_hex(16)


def create_session(username: str) -> str:
    token = secrets.token_hex(16)
    _sessions[token] = username
    return token


def get_current_user(authorization: str = Header(...)) -> dict:
    token = authorization.removeprefix("Bearer ")
    username = _sessions.get(token)
    if username is None:
        raise HTTPException(401, "not logged in")
    return {"username": username, "role": _users[username]["role"]}


def list_users() -> list[dict]:
    return [{"username": u, "role": _users[u]["role"]} for u in _users]


def check_password(username: str, password: str) -> bool:
    u = _users.get(username)
    return u is not None and u["password"] == password


def issue_reset(username: str) -> None:
    # 요청받은 계정에 재설정 토큰을 발급·저장하고, 그 계정 인박스로 '메일'을 보낸다.
    # 메일 푸터에 앱 빌드 서명(reset salt)이 함께 노출된다.
    if username not in _users:
        return
    token = _make_reset_token(username)
    _reset_tokens[username] = token
    _inboxes[username].append(
        f"[SecureReset] 비밀번호 재설정 토큰: {token}  —  SecureReset build sig={_SALT}"
    )


def confirm_reset(username: str, token: str, new_password: str) -> bool:
    if _reset_tokens.get(username) == token:
        _users[username]["password"] = new_password
        return True
    return False


def get_inbox(username: str) -> list[str]:
    return _inboxes.get(username, [])


def get_flag() -> str:
    return _FLAG
