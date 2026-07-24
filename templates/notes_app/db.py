import json
import pathlib
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


def get_current_user(x_user_token: str = Header(...)) -> User:
    raw = _USERS_BY_TOKEN.get(x_user_token)
    if raw is None:
        raise HTTPException(401, "invalid token")
    return User(**raw)


def get_note_by_id(note_id: int) -> Note | None:
    raw = _NOTES_BY_ID.get(note_id)
    if raw is None:
        return None
    return Note(**raw)
