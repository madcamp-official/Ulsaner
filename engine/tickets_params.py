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


def build_hard_seed_data(rng: random.Random) -> tuple[dict, str]:
    """하드 IDOR용 tickets seed — 티켓 id 가 추측 불가한 랜덤 큰 정수다(순차 열거 불가).

    easy 는 id 가 1,2 라 눈먼 열거로 풀리지만, 하드는 못 찍는다. 학생은 GET /tickets
    (워크스페이스 전체 티켓 id 를 흘리는 목록)에서 피해자(alice) 티켓 id 를 알아낸 뒤에야
    IDOR(get_ticket 의 잘못된 스코프 체크)로 본문을 읽을 수 있다 — '유출 발견 → 악용' 2단계.
    tickets[0] 은 반드시 flag 를 가진 피해자 티켓이어야 한다(build_tickets_idor_exploit 이 tickets[0].id 를 표적으로 씀).
    """
    flag = f"FLAG{{{rng.getrandbits(64):016x}}}"
    token_alice = f"token-{rng.getrandbits(32):08x}"
    token_bob = f"token-{rng.getrandbits(32):08x}"
    shared_workspace = rng.getrandbits(16)
    id_alice = rng.randint(10_000_000, 999_999_999)
    id_bob = rng.randint(10_000_000, 999_999_999)
    while id_bob == id_alice:
        id_bob = rng.randint(10_000_000, 999_999_999)
    seed_data = {
        "users": [
            {"id": 1, "token": token_alice, "name": "alice", "workspace_id": shared_workspace},
            {"id": 2, "token": token_bob, "name": "bob", "workspace_id": shared_workspace},
        ],
        "tickets": [
            {"id": id_alice, "owner_id": 1, "workspace_id": shared_workspace, "subject": "private", "description": flag, "is_confidential": True},
            {"id": id_bob, "owner_id": 2, "workspace_id": shared_workspace, "subject": "public", "description": "hello", "is_confidential": False},
        ],
    }
    return seed_data, flag
