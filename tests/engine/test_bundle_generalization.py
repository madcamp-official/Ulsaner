import inspect
from engine import bundle, params


def test_generate_bundle_defaults_preserve_current_behavior():
    sig = inspect.signature(bundle.generate_bundle)
    p = sig.parameters
    assert p["template_dir"].default == bundle.TEMPLATE_DIR
    assert p["seed_data_builder"].default is params.build_seed_data
    assert p["exploit_builders"].default is None
    assert p["reorder_var_name"].default == "note"
    assert p["health_check_path"].default == "/notes/2"


def test_generate_bundle_keeps_original_required_params_first():
    # backward-compat: platform/sources.py calls with these keyword names, no max_attempts
    sig = inspect.signature(bundle.generate_bundle)
    names = list(sig.parameters)
    assert names[:5] == ["seed", "output_dir", "slot_builder", "task_prompt", "solution_summary"]


def test_tickets_template_dir_exists_as_a_bundle_constant():
    assert bundle.TICKETS_TEMPLATE_DIR.name == "tickets_app"
