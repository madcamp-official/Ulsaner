import random
from engine.tickets_params import build_seed_data


def test_build_seed_data_shape_and_flag_placement():
    seed_data, flag = build_seed_data(random.Random(1))
    assert set(seed_data) == {"users", "tickets"}
    assert flag.startswith("FLAG{") and flag.endswith("}")
    assert len(seed_data["users"]) == 2
    ws = {u["workspace_id"] for u in seed_data["users"]}
    assert len(ws) == 1
    t1 = seed_data["tickets"][0]
    assert t1["id"] == 1 and t1["owner_id"] == 1 and t1["is_confidential"] is True
    assert t1["description"] == flag
    assert seed_data["tickets"][1]["is_confidential"] is False


def test_build_seed_data_is_deterministic_for_a_given_rng_seed():
    a, fa = build_seed_data(random.Random(42))
    b, fb = build_seed_data(random.Random(42))
    assert a == b and fa == fb
