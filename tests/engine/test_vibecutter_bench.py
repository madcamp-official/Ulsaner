import json
from pathlib import Path

import pytest

from engine.vibecutter_bench import generate_apps


def test_gen_sqli_easy_index_shape(tmp_path):
    index = generate_apps(tmp_path, ["sqli-easy"], seeds_per_class=1)

    idx_file = tmp_path / "index.json"
    assert idx_file.exists()
    assert json.loads(idx_file.read_text()) == index

    assert len(index) == 1
    e = index[0]
    assert e["vuln_class"] == "sqli"
    assert e["tier"] == "easy"
    assert e["seed"] == 3301  # sqli-easy base seed, first index
    assert e["flag"].startswith("FLAG{")
    assert e["exploit_path"].startswith("/notes/search?q=")
    assert e["inject_path"] == "/notes/search"
    assert e["inject_param"] == "q"
    assert (Path(e["app_dir"]) / "main.py").exists()
    assert (Path(e["app_dir"]) / "seed_data.json").exists()


def test_gen_sqli_hard_uses_advanced_endpoint(tmp_path):
    index = generate_apps(tmp_path, ["sqli-hard"], seeds_per_class=1)

    e = index[0]
    assert e["vuln_class"] == "sqli"
    assert e["tier"] == "hard"
    assert e["seed"] == 4401  # sqli-hard base seed (new, non-colliding block)
    assert e["exploit_path"].startswith("/notes/search/advanced?q=&exclude=")
    assert e["inject_path"] == "/notes/search/advanced"
    assert e["inject_param"] == "q"


def test_gen_idor_index_shape(tmp_path):
    index = generate_apps(tmp_path, ["idor-easy"], seeds_per_class=1)

    e = index[0]
    assert e["vuln_class"] == "idor"
    assert e["tier"] == "easy"
    assert e["seed"] == 1101
    assert e["attacker_token"].startswith("token-")
    assert e["baseline_path"] == "/notes/2"
    assert e["attack_path"] == "/notes/1"
    assert e["victim_marker"] == e["flag"]
    assert e["owner_marker"] == "hello"
    assert "exploit_path" not in e


def test_gen_multiple_classes_and_seed_count(tmp_path):
    index = generate_apps(tmp_path, ["idor-easy", "sqli-easy"], seeds_per_class=3)
    assert len(index) == 6
    seeds = [e["seed"] for e in index]
    assert seeds == [1101, 1102, 1103, 3301, 3302, 3303]


def test_gen_rejects_unknown_class(tmp_path):
    with pytest.raises(ValueError, match="unknown"):
        generate_apps(tmp_path, ["bogus-class"], seeds_per_class=1)


@pytest.mark.integration
def test_audit_requires_vibecutter_checkout():
    """The full `audit` phase needs VibeCutter's own venv + clone (VC_ROOT) and a
    per-target venv (VCVENV_PY), neither of which exists in this repo's CI/dev env.
    So there is no meaningful in-repo assertion for the audit pipeline: this test is
    marked `integration` (excluded from the default `pytest -m "not integration"`
    run) and skips here because VibeCutter's modules are not importable. To exercise
    audit for real, run under VibeCutter's own venv with VC_ROOT/VCVENV_PY set:
        VC_ROOT=... VCVENV_PY=... $VC_ROOT/.venv/bin/python \
            $ULSANER_ROOT/engine/vibecutter_bench.py audit <workdir> <out.json>
    """
    pytest.importorskip("contracts.schemas")  # VibeCutter-only; not present -> skip
