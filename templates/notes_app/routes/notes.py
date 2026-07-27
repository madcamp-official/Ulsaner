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


@router.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(get_current_user)):
    note = get_note_by_id(note_id)
    if note is None:
        raise HTTPException(404)
    if note.owner_id != user.id:
        raise HTTPException(403)
    return {"id": note.id, "title": note.title, "body": note.body}
