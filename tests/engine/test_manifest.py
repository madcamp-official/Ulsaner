import json
import pathlib
import pytest
import jsonschema
from engine.manifest import build_manifest, write_manifest

SCHEMA_PATH = pathlib.Path(__file__).parent.parent.parent / "contract" / "manifest_schema.json"

def test_schema_file_is_valid_json():
    schema = json.loads(SCHEMA_PATH.read_text())
    assert schema["title"] == "Ulsaner Challenge Bundle Manifest"


def test_build_manifest_has_required_fields():
    m = build_manifest(
        vuln_type="idor",
        tier="easy",
        flag="FLAG{abc}",
        task_prompt="다른 사용자의 비공개 노트를 읽어 flag를 찾아라",
        reference_exploit_path="exploits/reference.json",
        solution_summary="get_note의 소유권 체크 누락",
    )
    assert m["vuln_type"] == "idor"
    assert m["tier"] == "easy"
    assert m["flag"] == "FLAG{abc}"
    assert m["_internal"]["solution_summary"] == "get_note의 소유권 체크 누락"


def test_write_manifest_validates_against_schema(tmp_path):
    m = build_manifest(
        vuln_type="idor", tier="easy", flag="FLAG{abc}",
        task_prompt="prompt", reference_exploit_path="exploits/reference.json",
        solution_summary="summary",
    )
    write_manifest(tmp_path, m, SCHEMA_PATH)
    assert (tmp_path / "manifest.json").exists()


def test_write_manifest_rejects_invalid_manifest(tmp_path):
    with pytest.raises(jsonschema.ValidationError):
        write_manifest(tmp_path, {"id": "only-id"}, SCHEMA_PATH)
