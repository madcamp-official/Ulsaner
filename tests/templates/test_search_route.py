import sys
import pathlib
from fastapi.testclient import TestClient

APP_DIR = pathlib.Path(__file__).parent.parent.parent / "templates" / "notes_app"
sys.path.insert(0, str(APP_DIR))

from app_factory import create_app  # noqa: E402

client = TestClient(create_app())


def test_search_returns_only_the_matching_public_note():
    resp = client.get("/notes/search", params={"q": "public"})
    assert resp.status_code == 200
    assert resp.json() == {"results": [{"id": 2, "title": "public"}]}


def test_search_does_not_leak_the_private_note_via_a_normal_query():
    resp = client.get("/notes/search", params={"q": "private"})
    assert resp.status_code == 200
    assert resp.json() == {"results": []}


def test_note_by_id_route_is_still_reachable_after_adding_search():
    # regression guard for the /notes/{note_id} vs /notes/search route-ordering
    # gotcha: /notes/{note_id} must not swallow /notes/search, and vice versa
    # /notes/search must not swallow numeric note ids.
    resp = client.get("/notes/1", headers={"X-User-Token": "token-alice"})
    assert resp.status_code == 200
