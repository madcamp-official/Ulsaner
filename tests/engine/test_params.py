import random
import json
from engine.params import build_seed_data, write_seed_data


def test_build_seed_data_is_deterministic_for_same_rng_seed():
    data_a, flag_a = build_seed_data(random.Random(42))
    data_b, flag_b = build_seed_data(random.Random(42))
    assert data_a == data_b
    assert flag_a == flag_b


def test_build_seed_data_differs_across_seeds():
    _, flag_a = build_seed_data(random.Random(1))
    _, flag_b = build_seed_data(random.Random(2))
    assert flag_a != flag_b


def test_build_seed_data_shape_matches_notes_app_contract():
    data, flag = build_seed_data(random.Random(1))
    assert len(data["users"]) == 2
    assert len(data["notes"]) == 2
    assert data["notes"][0]["body"] == flag
    assert data["notes"][0]["is_private"] is True
    assert data["users"][0]["workspace_id"] == data["users"][1]["workspace_id"]


def test_write_seed_data_writes_valid_json(tmp_path):
    data, _ = build_seed_data(random.Random(1))
    write_seed_data(tmp_path, data)
    written = json.loads((tmp_path / "seed_data.json").read_text())
    assert written == data
