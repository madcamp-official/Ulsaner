import pathlib
from engine.benchmark import run_external_auditor


def test_run_external_auditor_reports_success_on_exit_code_zero(tmp_path):
    stub = tmp_path / "fake_auditor.sh"
    stub.write_text("#!/bin/sh\necho solved\nexit 0\n")
    stub.chmod(0o755)
    result = run_external_auditor(tmp_path, [str(stub)])
    assert result.solved is True
    assert "solved" in result.raw_output


def test_run_external_auditor_reports_failure_on_nonzero_exit(tmp_path):
    stub = tmp_path / "fake_auditor.sh"
    stub.write_text("#!/bin/sh\necho no bugs found\nexit 1\n")
    stub.chmod(0o755)
    result = run_external_auditor(tmp_path, [str(stub)])
    assert result.solved is False
