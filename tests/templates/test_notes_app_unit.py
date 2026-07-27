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
