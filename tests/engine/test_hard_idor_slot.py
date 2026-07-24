import libcst as cst
from engine.slots.hard_idor import build_hard_idor_slot

CLEAN_SOURCE = '''
from fastapi import APIRouter, HTTPException, Depends
from db import get_current_user, get_note_by_id

router = APIRouter()

@router.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(get_current_user)):
    note = get_note_by_id(note_id)
    if note is None:
        raise HTTPException(404)
    if note.owner_id != user.id:
        raise HTTPException(403)
    return {"id": note.id, "title": note.title, "body": note.body}
'''


def test_hard_idor_slot_swaps_to_workspace_scope_check():
    slot = build_hard_idor_slot()
    module = cst.parse_module(CLEAN_SOURCE)
    transformed = slot.transform(module)
    code = transformed.code
    assert "note.workspace_id != user.workspace_id" in code
    assert "note.owner_id" not in code
    assert "note is None" in code  # unrelated check preserved


def test_hard_idor_transformed_code_is_valid_python():
    slot = build_hard_idor_slot()
    module = cst.parse_module(CLEAN_SOURCE)
    transformed = slot.transform(module)
    compile(transformed.code, "<generated>", "exec")
