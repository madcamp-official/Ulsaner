import json
import pathlib
import sqlite3

from fastapi import Header, HTTPException

_SEED_PATH = pathlib.Path(__file__).parent / "seed_data.json"


def _load_seed() -> dict:
    with open(_SEED_PATH) as f:
        return json.load(f)


_SEED = _load_seed()
_USERS_BY_TOKEN = {u["token"]: u for u in _SEED["users"]}
_TICKETS_BY_ID = {t["id"]: t for t in _SEED["tickets"]}


class User:
    def __init__(self, id, token, name, workspace_id):
        self.id = id
        self.token = token
        self.name = name
        self.workspace_id = workspace_id


class Ticket:
    def __init__(self, id, owner_id, workspace_id, subject, description, is_confidential):
        self.id = id
        self.owner_id = owner_id
        self.workspace_id = workspace_id
        self.subject = subject
        self.description = description
        self.is_confidential = is_confidential


def get_current_user(x_user_token: str = Header(...)) -> User:
    raw = _USERS_BY_TOKEN.get(x_user_token)
    if raw is None:
        raise HTTPException(401, "invalid token")
    return User(**raw)


def get_ticket_by_id(ticket_id: int) -> Ticket | None:
    raw = _TICKETS_BY_ID.get(ticket_id)
    if raw is None:
        return None
    return Ticket(**raw)


def list_tickets_in_workspace(workspace_id: int) -> list[Ticket]:
    return [Ticket(**raw) for raw in _TICKETS_BY_ID.values() if raw["workspace_id"] == workspace_id]


def _build_tickets_db(seed: dict) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute(
        "CREATE TABLE tickets (id INTEGER, owner_id INTEGER, workspace_id INTEGER, "
        "subject TEXT, description TEXT, is_confidential INTEGER)"
    )
    conn.executemany(
        "INSERT INTO tickets (id, owner_id, workspace_id, subject, description, is_confidential) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            (t["id"], t["owner_id"], t["workspace_id"], t["subject"], t["description"], int(t["is_confidential"]))
            for t in seed["tickets"]
        ],
    )
    conn.commit()
    return conn


_TICKETS_DB = _build_tickets_db(_SEED)


def search_tickets_by_subject(q: str) -> list[tuple]:
    cursor = _TICKETS_DB.execute(
        "SELECT id, subject FROM tickets WHERE is_confidential = 0 AND subject LIKE ?",
        (f"%{q}%",),
    )
    return cursor.fetchall()
