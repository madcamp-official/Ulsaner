import sys
import pathlib
import pytest
from fastapi import HTTPException

APP_DIR = pathlib.Path(__file__).parent.parent.parent / "templates" / "tickets_app"
sys.path.insert(0, str(APP_DIR))

import db  # noqa: E402


def test_get_current_user_returns_user_for_valid_token():
    user = db.get_current_user("token-alice")
    assert user.id == 1
    assert user.workspace_id == 100


def test_get_current_user_rejects_unknown_token():
    with pytest.raises(HTTPException) as exc_info:
        db.get_current_user("nope")
    assert exc_info.value.status_code == 401


def test_get_ticket_by_id_returns_none_for_missing_ticket():
    assert db.get_ticket_by_id(999) is None


def test_search_tickets_by_subject_returns_only_public_matches():
    assert db.search_tickets_by_subject("public") == [(2, "public")]


def test_search_tickets_by_subject_excludes_confidential_even_on_match():
    assert db.search_tickets_by_subject("private") == []


def test_list_tickets_in_workspace_returns_both_tickets():
    ids = sorted(t.id for t in db.list_tickets_in_workspace(100))
    assert ids == [1, 2]


def test_confidential_ticket_carries_flag_in_description():
    t = db.get_ticket_by_id(1)
    assert t.owner_id == 1
    assert t.is_confidential is True
    assert t.description == "FLAG{example}"
