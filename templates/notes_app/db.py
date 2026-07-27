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
_NOTES_BY_ID = {n["id"]: n for n in _SEED["notes"]}


class User:
    def __init__(self, id: int, token: str, name: str, workspace_id: int):
        self.id = id
        self.token = token
        self.name = name
        self.workspace_id = workspace_id


class Note:
    def __init__(self, id: int, owner_id: int, workspace_id: int, title: str, body: str, is_private: bool):
        self.id = id
        self.owner_id = owner_id
        self.workspace_id = workspace_id
        self.title = title
        self.body = body
        self.is_private = is_private


def get_current_user(authorization: str = Header(...)) -> User:
    token = authorization[7:] if authorization.startswith("Bearer ") else authorization
    raw = _USERS_BY_TOKEN.get(token)
    if raw is None:
        raise HTTPException(401, "invalid token")
    return User(**raw)


def get_note_by_id(note_id: int) -> Note | None:
    raw = _NOTES_BY_ID.get(note_id)
    if raw is None:
        return None
    return Note(**raw)


def list_notes_in_workspace(workspace_id: int) -> list[Note]:
    return [Note(**raw) for raw in _NOTES_BY_ID.values() if raw["workspace_id"] == workspace_id]


def _build_notes_db(seed: dict) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute(
        "CREATE TABLE notes ("
        "id INTEGER, owner_id INTEGER, workspace_id INTEGER, "
        "title TEXT, body TEXT, is_private INTEGER)"
    )
    conn.executemany(
        "INSERT INTO notes (id, owner_id, workspace_id, title, body, is_private) VALUES (?, ?, ?, ?, ?, ?)",
        [
            (n["id"], n["owner_id"], n["workspace_id"], n["title"], n["body"], int(n["is_private"]))
            for n in seed["notes"]
        ],
    )
    conn.commit()
    return conn


_NOTES_DB = _build_notes_db(_SEED)


def search_notes_by_title(q: str) -> list[tuple]:
    cursor = _NOTES_DB.execute(
        "SELECT id, title FROM notes WHERE is_private = 0 AND title LIKE ?",
        (f"%{q}%",),
    )
    return cursor.fetchall()
