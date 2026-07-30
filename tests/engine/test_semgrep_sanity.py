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


@pytest.mark.integration
def test_semgrep_does_not_flag_the_new_notes_list_route_on_either_tier(tmp_path):
    # GET /notes (list_notes) has no ownership check by design (it's a
    # metadata-only workspace feed, not a per-object fetch) — it must never
    # trip missing-ownership-check on either the easy or hard idor slot, since
    # the AST transformers only ever target the get_note function by name.
    easy_app_dir = tmp_path / "easy_app_list_notes"
    inject(TEMPLATE_DIR, easy_app_dir, build_easy_idor_slot())
    easy_findings = _run_semgrep(easy_app_dir / "routes" / "notes.py")
    assert not any("list_notes" in f["extra"]["lines"] for f in easy_findings)

    hard_app_dir = tmp_path / "hard_app_list_notes"
    inject(TEMPLATE_DIR, hard_app_dir, build_hard_idor_slot())
    hard_findings = _run_semgrep(hard_app_dir / "routes" / "notes.py")
    assert len(hard_findings) == 0  # unchanged: whole-file zero-findings guarantee still holds


from engine.slots.easy_sqli import build_easy_sqli_slot
from engine.slots.hard_sqli import build_hard_sqli_slot

SQLI_RULE_PATH = (
    pathlib.Path(__file__).parent.parent.parent
    / "engine" / "semgrep_rules" / "unparameterized_sql_execute.yml"
)


def _run_sqli_semgrep(target_file: pathlib.Path) -> list:
    result = subprocess.run(
        ["semgrep", "--config", str(SQLI_RULE_PATH), "--json", str(target_file)],
        capture_output=True, text=True, check=True,
    )
    return json.loads(result.stdout)["results"]


@pytest.mark.integration
def test_semgrep_flags_easy_sqli(tmp_path):
    app_dir = tmp_path / "easy_sqli_app"
    inject(TEMPLATE_DIR, app_dir, build_easy_sqli_slot())
    findings = _run_sqli_semgrep(app_dir / "db.py")
    assert len(findings) > 0


@pytest.mark.integration
def test_semgrep_does_not_flag_hard_sqli(tmp_path):
    # hard_sqli is genuinely still injectable (proven by the Docker E2E in Task
    # A7), but its transformed call is a 2-arg .execute(query, (f"%{q}%",)) with
    # a params tuple, so the naive "1-arg f-string execute" rule structurally
    # cannot match it — existence of a params tuple != correctness (ALL values
    # actually parameterized), extending this project's existence-vs-correctness
    # thesis from authorization checks to injection.
    app_dir = tmp_path / "hard_sqli_app"
    inject(TEMPLATE_DIR, app_dir, build_hard_sqli_slot())
    findings = _run_sqli_semgrep(app_dir / "db.py")
    assert len(findings) == 0
