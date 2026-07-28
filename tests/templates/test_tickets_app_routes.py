import sys
import pathlib
from fastapi.testclient import TestClient

APP_DIR = pathlib.Path(__file__).parent.parent.parent / "templates" / "tickets_app"
sys.path.insert(0, str(APP_DIR))

from app_factory import create_app  # noqa: E402

client = TestClient(create_app())


def test_owner_can_read_own_ticket():
    resp = client.get("/tickets/1", headers={"X-User-Token": "token-alice"})
    assert resp.status_code == 200
    assert resp.json()["description"] == "FLAG{example}"


def test_non_owner_is_forbidden_from_confidential_ticket():
    resp = client.get("/tickets/1", headers={"X-User-Token": "token-bob"})
    assert resp.status_code == 403


def test_search_returns_only_matching_public_ticket():
    resp = client.get("/tickets/search", params={"q": "public"})
    assert resp.status_code == 200
    assert resp.json() == {"results": [{"id": 2, "subject": "public"}]}


def test_ticket_by_id_route_survives_search_route_ordering():
    resp = client.get("/tickets/2", headers={"X-User-Token": "token-bob"})
    assert resp.status_code == 200
