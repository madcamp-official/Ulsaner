from db import get_current_user, list_tickets_in_workspace
from fastapi import APIRouter, Depends, HTTPException

router = APIRouter()


@router.get("/tickets/export")
def export_tickets(user=Depends(get_current_user)):
    # 관리자 전용 대량 조회: 워크스페이스 전체 티켓 원문(기밀 description 포함)을 덤프한다.
    # 함수 레벨 인가 — 일반 사용자(is_admin=False)는 여기 도달하면 안 된다.
    if not user.is_admin:
        raise HTTPException(403)
    return [
        {
            "id": t.id,
            "owner_id": t.owner_id,
            "subject": t.subject,
            "description": t.description,
            "is_confidential": t.is_confidential,
        }
        for t in list_tickets_in_workspace(user.workspace_id)
    ]
