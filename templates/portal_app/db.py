import base64
import hashlib
import hmac
import json
import pathlib

from fastapi import Header, HTTPException

_SEED_PATH = pathlib.Path(__file__).parent / "seed_data.json"


def _load_seed() -> dict:
    with open(_SEED_PATH) as f:
        return json.load(f)


_SEED = _load_seed()
_SECRET = _SEED["secret"]
_FLAG = _SEED["flag"]
_USERS = {u["username"]: u for u in _SEED["users"]}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(signing_input: str) -> str:
    digest = hmac.new(_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
    return _b64url_encode(digest)


def make_token(claims: dict) -> str:
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url_encode(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}"
    return f"{signing_input}.{_sign(signing_input)}"


def verify_token(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(401, "malformed token")
    header_b64, payload_b64, signature = parts
    if not hmac.compare_digest(signature, _sign(f"{header_b64}.{payload_b64}")):
        raise HTTPException(401, "invalid signature")
    return json.loads(_b64url_decode(payload_b64))


class CurrentUser:
    def __init__(self, sub, role):
        self.sub = sub
        self.role = role


def get_current_user(authorization: str = Header(...)) -> CurrentUser:
    token = authorization.removeprefix("Bearer ")
    claims = verify_token(token)
    return CurrentUser(sub=claims.get("sub"), role=claims.get("role"))


def get_user(username: str) -> dict | None:
    return _USERS.get(username)


def get_flag() -> str:
    return _FLAG
