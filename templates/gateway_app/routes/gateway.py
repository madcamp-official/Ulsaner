import urllib.error
import urllib.request

from db import FLAG, INTERNAL_TOKEN, VAULT_TOKEN
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

router = APIRouter()


@router.get("/status")
def status():
    # 공개 상태 페이지. 내부 서비스의 존재를 흘린다(정찰 단서).
    return {
        "service": "gateway",
        "public": ["/fetch", "/status"],
        "note": "내부 서비스 디렉터리는 내부망에서만 접근됩니다: http://localhost:8000/internal/services",
    }


def _is_internal(url: str) -> bool:
    low = url.lower()
    return any(x in low for x in ("localhost", "127.0.0.1", "/internal", "169.254.169.254"))


def _do_fetch(url: str) -> tuple[int, str]:
    # 서버가 대신 요청한다 — 내부 서비스가 신뢰하는 인증 헤더를 붙여서(내부망 신뢰).
    req = urllib.request.Request(url, headers={"X-Internal-Auth": INTERNAL_TOKEN})
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:  # noqa: BLE001
        return 0, f"fetch error: {e}"


class FetchReq(BaseModel):
    url: str


@router.post("/fetch")
def fetch(req: FetchReq):
    # URL 상태 확인 도구 — 서버가 그 URL 을 대신 요청해 결과를 돌려준다.
    if _is_internal(req.url):
        raise HTTPException(400, "internal URLs are not allowed")
    status_code, body = _do_fetch(req.url)
    return {"status": status_code, "body": body}


@router.get("/internal/services")
def internal_services(x_internal_auth: str = Header(default="")):
    if x_internal_auth != INTERNAL_TOKEN:
        raise HTTPException(403, "internal only")
    return {
        "services": ["vault"],
        "vault_url": "http://localhost:8000/internal/vault",
        "vault_token": VAULT_TOKEN,
    }


@router.get("/internal/vault")
def internal_vault(token: str = "", x_internal_auth: str = Header(default="")):
    if x_internal_auth != INTERNAL_TOKEN:
        raise HTTPException(403, "internal only")
    if token != VAULT_TOKEN:
        raise HTTPException(401, "invalid vault token")
    return {"flag": FLAG}
