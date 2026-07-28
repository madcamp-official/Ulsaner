import random


def build_seed_data(rng: random.Random) -> tuple[dict, str]:
    flag = f"FLAG{{{rng.getrandbits(64):016x}}}"
    token_alice = f"token-{rng.getrandbits(32):08x}"
    token_bob = f"token-{rng.getrandbits(32):08x}"
    shared_workspace = rng.getrandbits(16)
    seed_data = {
        "users": [
            {"id": 1, "token": token_alice, "name": "alice", "workspace_id": shared_workspace},
            {"id": 2, "token": token_bob, "name": "bob", "workspace_id": shared_workspace},
        ],
        "tickets": [
            {"id": 1, "owner_id": 1, "workspace_id": shared_workspace, "subject": "private", "description": flag, "is_confidential": True},
            {"id": 2, "owner_id": 2, "workspace_id": shared_workspace, "subject": "public", "description": "hello", "is_confidential": False},
        ],
    }
    return seed_data, flag
