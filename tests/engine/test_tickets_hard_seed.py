"""하드 IDOR용 tickets 랜덤-id seed 빌더 단위 테스트 (Docker 불필요).

tickets[0] 은 flag 를 가진 피해자(alice) 티켓이어야 한다(build_tickets_idor_exploit 이
tickets[0].id 를 표적으로 씀). id 는 추측 불가한 큰 정수(순차 열거 방지).
"""

import random

from engine.tickets_params import build_hard_seed_data


def test_ticket_ids_are_large_and_not_sequential():
    seed, _ = build_hard_seed_data(random.Random(1))
    ids = [t["id"] for t in seed["tickets"]]
    assert all(i >= 10_000_000 for i in ids)
    assert ids[0] != ids[1]
    assert 1 not in ids and 2 not in ids


def test_victim_ticket_is_first_and_holds_flag():
    seed, flag = build_hard_seed_data(random.Random(7))
    victim = seed["tickets"][0]
    assert victim["owner_id"] == 1
    assert victim["is_confidential"] is True
    assert victim["description"] == flag


def test_attacker_and_victim_share_workspace():
    seed, _ = build_hard_seed_data(random.Random(3))
    assert len({u["workspace_id"] for u in seed["users"]}) == 1


def test_deterministic_for_same_seed():
    a, fa = build_hard_seed_data(random.Random(42))
    b, fb = build_hard_seed_data(random.Random(42))
    assert a == b and fa == fb
