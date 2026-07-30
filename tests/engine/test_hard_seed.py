"""하드 IDOR용 랜덤-id seed 빌더 단위 테스트 (Docker 불필요).

핵심 계약: 노트 id 가 추측 불가한 큰 정수여야(순차 열거 방지) 하고, notes[0] 은 flag 를
가진 피해자(alice, owner_id 1) 노트여야 한다(build_idor_exploit 이 notes[0].id 를 표적으로 씀).
"""

import random

from engine.params import build_hard_seed_data


def test_note_ids_are_large_and_not_sequential():
    seed, _flag = build_hard_seed_data(random.Random(1))
    ids = [n["id"] for n in seed["notes"]]
    assert all(i >= 10_000_000 for i in ids)  # 큰 값 → 1,2,3 눈먼 열거로 못 찾음
    assert ids[0] != ids[1]
    assert 1 not in ids and 2 not in ids


def test_victim_note_is_first_and_holds_flag():
    seed, flag = build_hard_seed_data(random.Random(7))
    victim = seed["notes"][0]
    assert victim["owner_id"] == 1  # alice(피해자)
    assert victim["is_private"] is True
    assert victim["body"] == flag  # notes[0].id 를 표적으로 하는 익스플로잇이 flag 를 얻는다


def test_attacker_and_victim_share_workspace():
    # 하드 슬롯이 소유권 검증을 workspace 스코프로 바꾸므로, 같은 workspace 여야 뚫린다.
    seed, _ = build_hard_seed_data(random.Random(3))
    ws = {u["workspace_id"] for u in seed["users"]}
    assert len(ws) == 1


def test_deterministic_for_same_seed():
    a, fa = build_hard_seed_data(random.Random(42))
    b, fb = build_hard_seed_data(random.Random(42))
    assert a == b and fa == fb


def test_flag_format():
    _, flag = build_hard_seed_data(random.Random(9))
    assert flag.startswith("FLAG{") and flag.endswith("}")
