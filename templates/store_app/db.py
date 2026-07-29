import json
import pathlib

from fastapi import Header, HTTPException

_SEED_PATH = pathlib.Path(__file__).parent / "seed_data.json"


def _load_seed() -> dict:
    with open(_SEED_PATH) as f:
        return json.load(f)


_SEED = _load_seed()
_USERS_BY_TOKEN = {u["token"]: u for u in _SEED["users"]}
_ITEMS_BY_ID = {i["id"]: i for i in _SEED["items"]}


class User:
    def __init__(self, id, token, name, balance):
        self.id = id
        self.token = token
        self.name = name
        self.balance = balance


class Item:
    def __init__(self, id, name, price, secret):
        self.id = id
        self.name = name
        self.price = price
        self.secret = secret  # 프리미엄 상품이면 flag, 아니면 빈 문자열


def get_current_user(authorization: str = Header(...)) -> User:
    token = authorization.removeprefix("Bearer ")
    raw = _USERS_BY_TOKEN.get(token)
    if raw is None:
        raise HTTPException(401, "invalid token")
    return User(**raw)


def get_item_by_id(item_id: int) -> Item | None:
    raw = _ITEMS_BY_ID.get(item_id)
    return Item(**raw) if raw else None


def list_items() -> list[Item]:
    return [Item(**raw) for raw in _ITEMS_BY_ID.values()]
