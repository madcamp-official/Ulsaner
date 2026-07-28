import inspect
import pathlib
import random
import pytest
from engine.injector import inject
from engine.params import build_seed_data, write_seed_data
from engine.exploit_gen import build_idor_exploit
from engine.slots.easy_idor import build_easy_idor_slot
from engine import verifier
from engine.verifier import verify_bundle

TEMPLATE_DIR = pathlib.Path(__file__).parent.parent.parent / "templates" / "notes_app"


@pytest.mark.integration
def test_verify_bundle_passes_for_easy_idor(tmp_path):
    app_dir = tmp_path / "app"
    inject(TEMPLATE_DIR, app_dir, build_easy_idor_slot())
    seed_data, flag = build_seed_data(random.Random(7))
    write_seed_data(app_dir, seed_data)
    exploit = build_idor_exploit(seed_data, flag)
    assert verify_bundle(app_dir, exploit, tag="ulsaner-verifier-test") is True


def test_verify_bundle_accepts_optional_health_check_path_defaulting_to_notes_2():
    sig = inspect.signature(verifier.verify_bundle)
    assert "health_check_path" in sig.parameters
    assert sig.parameters["health_check_path"].default == "/notes/2"


def test_wait_for_health_accepts_a_path_argument():
    sig = inspect.signature(verifier._wait_for_health)
    assert "path" in sig.parameters
