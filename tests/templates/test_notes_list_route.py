import sys
import pathlib
from fastapi.testclient import TestClient

APP_DIR = pathlib.Path(__file__).parent.parent.parent / "templates" / "notes_app"
sys.path.insert(0, str(APP_DIR))

from app_factory import create_app  # noqa: E402

client = TestClient(create_app())


def test_list_notes_requires_the_auth_header():
    resp = client.get("/notes")
    assert resp.status_code == 422  # FastAPI's required Header(...) validation, not our 401


def test_list_notes_rejects_an_unknown_token():
    resp = client.get("/notes", headers={"X-User-Token": "not-a-real-token"})
    assert resp.status_code == 401


def test_list_notes_reveals_the_victims_note_metadata_to_a_different_workspace_member():
    # alice and bob share workspace_id=100; this is the "discovery" step of the
    # IDOR challenge: alice must be able to see that note id=1 exists, is
    # owned by someone else, and is private — without brute-forcing ids.
    resp = client.get("/notes", headers={"X-User-Token": "token-alice"})
    assert resp.status_code == 200
    results = resp.json()
    ids = sorted(row["id"] for row in results)
    assert ids == [1, 2]
    victim_row = next(row for row in results if row["id"] == 1)
    assert victim_row == {"id": 1, "owner_id": 1, "title": "private", "is_private": True}


def test_list_notes_never_exposes_body_or_the_flag_value():
    resp = client.get("/notes", headers={"X-User-Token": "token-alice"})
    assert "FLAG" not in resp.text
    for row in resp.json():
        assert "body" not in row


def test_note_by_id_and_search_routes_still_reachable_after_adding_notes_list():
    # regression guard, same house style as test_search_route.py's
    # test_note_by_id_route_is_still_reachable_after_adding_search: adding a new
    # GET /notes (no path param) must not shadow /notes/{note_id} or /notes/search.
    detail_resp = client.get("/notes/1", headers={"X-User-Token": "token-alice"})
    assert detail_resp.status_code == 200

    search_resp = client.get("/notes/search", params={"q": "public"})
    assert search_resp.status_code == 200
    assert search_resp.json() == {"results": [{"id": 2, "title": "public"}]}
