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
    resp = client.get("/notes/1", headers={"Authorization": "Bearer token-alice"})
    assert resp.status_code == 200


def test_advanced_search_returns_only_the_matching_public_note():
    resp = client.get("/notes/search/advanced", params={"q": "public", "exclude": ""})
    assert resp.status_code == 200
    assert resp.json() == {"results": [{"id": 2, "title": "public"}]}


def test_advanced_search_is_safe_against_injection_in_clean_template():
    resp = client.get(
        "/notes/search/advanced",
        params={"q": "", "exclude": "x' OR 1=1 UNION SELECT id, body FROM notes -- "},
    )
    assert resp.status_code == 200
    ids = [r["id"] for r in resp.json()["results"]]
    assert 1 not in ids  # the private flag note (id=1) must not leak from the safe baseline


def test_search_view_escapes_the_reflected_search_term_in_clean_template():
    resp = client.get("/notes/search/view", params={"q": "<script>alert(1)</script>"})
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    # clean baseline escapes -> raw <script> must NOT appear, entity form must
    assert "<script>alert(1)</script>" not in resp.text
    assert "&lt;script&gt;" in resp.text
