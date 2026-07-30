import json
import pathlib
import pytest
import jsonschema
from engine.manifest import build_manifest, write_manifest

SCHEMA_PATH = pathlib.Path(__file__).parent.parent.parent / "contract" / "manifest_schema.json"

def test_schema_file_is_valid_json():
    schema = json.loads(SCHEMA_PATH.read_text())
    # title wording is B(플랫폼)와 자유롭게 바뀔 수 있는 문구라 정확한 문자열은 검증하지 않는다 —
    # 존재 여부와 스키마로서 최소 형태만 확인한다.
    assert isinstance(schema.get("title"), str) and schema["title"]
    assert schema.get("type") == "object"


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


def _validate_vuln_type(vuln_type: str) -> None:
    schema = json.loads(SCHEMA_PATH.read_text())
    m = build_manifest(
        vuln_type=vuln_type,
        tier="hard" if vuln_type == "hard_sqli" else "easy",
        flag="FLAG{deadbeef}",
        task_prompt="x",
        reference_exploit_path="exploits/reference.json",
        solution_summary="y",
    )
    jsonschema.validate(m, schema)


def test_build_manifest_embeds_hints_and_validates(tmp_path):
    # 힌트를 넘기면 entry.hints 로 실리고 스키마를 통과한다(온디맨드 힌트 계약).
    schema = json.loads(SCHEMA_PATH.read_text())
    m = build_manifest(
        vuln_type="idor", tier="easy", flag="FLAG{abc}",
        task_prompt="prompt", reference_exploit_path="exploits/reference.json",
        solution_summary="summary", hints=["관찰부터", "다음 단계", "구체적 방법"],
    )
    jsonschema.validate(m, schema)
    assert m["entry"]["hints"] == ["관찰부터", "다음 단계", "구체적 방법"]


def test_build_manifest_without_hints_omits_key(tmp_path):
    # 힌트를 안 넘기면 entry 에 hints 키가 없다 — 기존 번들·fixture 형태 그대로(하위호환).
    schema = json.loads(SCHEMA_PATH.read_text())
    m = build_manifest(
        vuln_type="idor", tier="easy", flag="FLAG{abc}",
        task_prompt="prompt", reference_exploit_path="exploits/reference.json",
        solution_summary="summary",
    )
    jsonschema.validate(m, schema)
    assert "hints" not in m["entry"]


def test_schema_accepts_hard_sqli_vuln_type():
    _validate_vuln_type("hard_sqli")


def test_schema_accepts_xss_vuln_type():
    _validate_vuln_type("xss")
