import json
import pathlib
import subprocess
import pytest
from engine.injector import inject
from engine.slots.easy_idor import build_easy_idor_slot
from engine.slots.hard_idor import build_hard_idor_slot

TEMPLATE_DIR = pathlib.Path(__file__).parent.parent.parent / "templates" / "notes_app"
RULE_PATH = pathlib.Path(__file__).parent.parent.parent / "engine" / "semgrep_rules" / "missing_ownership_check.yml"


def _run_semgrep(target_file: pathlib.Path) -> list:
    result = subprocess.run(
        ["semgrep", "--config", str(RULE_PATH), "--json", str(target_file)],
        capture_output=True, text=True, check=True,
    )
    return json.loads(result.stdout)["results"]


@pytest.mark.integration
def test_semgrep_flags_easy_idor(tmp_path):
    app_dir = tmp_path / "easy_app"
    inject(TEMPLATE_DIR, app_dir, build_easy_idor_slot())
    findings = _run_semgrep(app_dir / "routes" / "notes.py")
    assert len(findings) > 0


@pytest.mark.integration
def test_semgrep_does_not_flag_hard_idor(tmp_path):
    app_dir = tmp_path / "hard_app"
    inject(TEMPLATE_DIR, app_dir, build_hard_idor_slot())
    findings = _run_semgrep(app_dir / "routes" / "notes.py")
    assert len(findings) == 0
