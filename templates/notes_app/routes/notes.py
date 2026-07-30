from fastapi import APIRouter, HTTPException, Depends
from db import get_current_user, get_note_by_id, list_notes_in_workspace

router = APIRouter()


@router.get("/notes")
def list_notes(user=Depends(get_current_user)):
    # 워크스페이스 피드: 메타데이터만 반환한다. body(=flag)는 절대 노출 금지.
    return [
        {"id": n.id, "owner_id": n.owner_id, "title": n.title, "is_private": n.is_private}
        for n in list_notes_in_workspace(user.workspace_id)
    ]


@router.get("/me")
def whoami(user=Depends(get_current_user)):
    # 현재 로그인 사용자 신원(프론트가 '내 노트 vs 남의 노트'를 구분하는 용도).
    # 자기 자신의 id/name 만 노출한다 — 자격증명·flag 는 포함하지 않는다.
    return {"id": user.id, "name": user.name}


@router.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(get_current_user)):
    note = get_note_by_id(note_id)
    if note is None:
        raise HTTPException(404)
    if note.owner_id != user.id:
        raise HTTPException(403)
    return {"id": note.id, "title": note.title, "body": note.body}
