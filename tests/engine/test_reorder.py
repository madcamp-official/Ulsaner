import libcst as cst
from engine.reorder import rename_local_variable

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

TWO_FUNCTION_SOURCE = '''
def get_note(note_id: int):
    note = fetch(note_id)
    return note


def get_other_thing(thing_id: int):
    note = fetch_other(thing_id)
    return note
'''


def test_rename_local_variable_renames_all_occurrences_in_function():
    module = cst.parse_module(CLEAN_SOURCE)
    renamed = rename_local_variable(module, "get_note", "note", "n7x2")
    code = renamed.code
    assert "n7x2 = get_note_by_id(note_id)" in code
    assert "if n7x2 is None" in code
    assert "n7x2.owner_id != user.id" in code
    assert "note = get_note_by_id(note_id)" not in code


def test_rename_local_variable_produces_valid_python():
    module = cst.parse_module(CLEAN_SOURCE)
    renamed = rename_local_variable(module, "get_note", "note", "n7x2")
    compile(renamed.code, "<generated>", "exec")


def test_rename_local_variable_does_not_touch_sibling_function():
    module = cst.parse_module(TWO_FUNCTION_SOURCE)
    renamed = rename_local_variable(module, "get_note", "note", "n7x2")
    code = renamed.code
    # Target function should have its variable renamed
    assert "n7x2 = fetch(note_id)" in code
    assert "return n7x2" in code
    # Sibling function should be completely untouched
    assert "note = fetch_other(thing_id)" in code
    assert "def get_other_thing(thing_id: int):" in code
