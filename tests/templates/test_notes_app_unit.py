import sys
import pathlib
import pytest
from fastapi import HTTPException

APP_DIR = pathlib.Path(__file__).parent.parent.parent / "templates" / "notes_app"
sys.path.insert(0, str(APP_DIR))

import db  # noqa: E402

def test_get_current_user_returns_user_for_valid_token():
    user = db.get_current_user("token-alice")
    assert user.id == 1
    assert user.workspace_id == 100

def test_get_current_user_rejects_unknown_token():
    with pytest.raises(HTTPException) as exc_info:
        db.get_current_user("not-a-real-token")
    assert exc_info.value.status_code == 401

def test_get_note_by_id_returns_none_for_missing_note():
    assert db.get_note_by_id(999) is None


def test_search_notes_by_title_returns_only_public_matches():
    rows = db.search_notes_by_title("public")
    assert rows == [(2, "public")]


def test_search_notes_by_title_excludes_private_notes_even_when_title_matches():
    rows = db.search_notes_by_title("private")
    assert rows == []


def test_list_notes_in_workspace_returns_every_note_sharing_the_workspace():
    notes = db.list_notes_in_workspace(100)
    ids = sorted(n.id for n in notes)
    assert ids == [1, 2]


def test_list_notes_in_workspace_returned_notes_are_real_note_objects():
    notes = db.list_notes_in_workspace(100)
    private_note = next(n for n in notes if n.id == 1)
    assert private_note.owner_id == 1
    assert private_note.is_private is True
    assert private_note.title == "private"
    # the Note object itself still carries body (db-layer has no reason to strip
    # data); redacting body/flag is the route layer's job (Step 3), not db.py's.
    assert private_note.body == "FLAG{example}"


def test_list_notes_in_workspace_returns_empty_list_for_an_unknown_workspace():
    assert db.list_notes_in_workspace(999) == []
