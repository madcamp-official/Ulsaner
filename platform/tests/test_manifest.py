"""플랫폼 manifest 로더 테스트.

플랫폼은 번들의 manifest.json 을 읽어 (1) 계약 스키마 부합을 검증하고,
(2) 검증 서비스가 쓸 flag 판정과 (3) 학생에게 노출할 블랙박스 뷰를 제공한다.
"""

import copy
import json
from pathlib import Path

import pytest
from ulsaner_platform.manifest import (
    Manifest,
    ManifestValidationError,
    load_bundle_manifest,
    load_manifest,
)

VALID_MANIFEST = {
    "id": "3f8b0c2e-1a2b-4c3d-9e4f-5a6b7c8d9e0f",
    "vuln_type": "idor",
    "tier": "easy",
    "entry": {
        "port": 8000,
        "task_prompt": "다른 사용자의 비공개 데이터를 읽어 flag를 찾아라",
    },
    "flag": "FLAG{unit_secret}",
    "verify": {"method": "flag_submit"},
    "_internal": {"flag_planted_in": "user 2의 비공개 노트"},
}


def write_manifest(dir_path: Path, data: dict) -> Path:
    path = dir_path / "manifest.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_load_manifest_exposes_typed_fields(tmp_path):
    path = write_manifest(tmp_path, VALID_MANIFEST)

    m = load_manifest(path)

    assert isinstance(m, Manifest)
    assert m.id == "3f8b0c2e-1a2b-4c3d-9e4f-5a6b7c8d9e0f"
    assert m.vuln_type == "idor"
    assert m.tier == "easy"
    assert m.port == 8000
    assert m.task_prompt == "다른 사용자의 비공개 데이터를 읽어 flag를 찾아라"
    assert m.flag == "FLAG{unit_secret}"
    assert m.verify_method == "flag_submit"


def test_load_manifest_rejects_contract_violation(tmp_path):
    bad = copy.deepcopy(VALID_MANIFEST)
    bad.pop("flag")  # 계약 필수 필드 누락
    path = write_manifest(tmp_path, bad)

    with pytest.raises(ManifestValidationError):
        load_manifest(path)


def test_check_flag_accepts_exact_match(tmp_path):
    m = load_manifest(write_manifest(tmp_path, VALID_MANIFEST))
    assert m.check_flag("FLAG{unit_secret}") is True


def test_check_flag_rejects_wrong_value(tmp_path):
    m = load_manifest(write_manifest(tmp_path, VALID_MANIFEST))
    assert m.check_flag("FLAG{wrong}") is False


def test_check_flag_tolerates_surrounding_whitespace(tmp_path):
    # 학생이 복붙하면 앞뒤 공백/개행이 섞이기 쉽다.
    m = load_manifest(write_manifest(tmp_path, VALID_MANIFEST))
    assert m.check_flag("  FLAG{unit_secret}\n") is True


def test_public_view_hides_flag_and_internal(tmp_path):
    m = load_manifest(write_manifest(tmp_path, VALID_MANIFEST))

    view = m.public_view()

    assert view["id"] == VALID_MANIFEST["id"]
    assert view["vuln_type"] == "idor"
    assert view["entry"]["task_prompt"] == VALID_MANIFEST["entry"]["task_prompt"]
    assert "flag" not in view
    assert "_internal" not in view


def test_load_bundle_manifest_reads_manifest_json_from_dir(tmp_path):
    write_manifest(tmp_path, VALID_MANIFEST)

    m = load_bundle_manifest(tmp_path)

    assert m.id == VALID_MANIFEST["id"]
