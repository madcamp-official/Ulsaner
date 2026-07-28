"""계약 테스트 — 생성된 manifest.json이 contract/manifest_schema.json 에 부합하는지.

이 스키마는 엔진(Part A)↔플랫폼(Part B)의 유일한 공용 인터페이스다(설계 문서 §5).
여기서 검증하는 것은 "정상 manifest는 통과하고, 계약을 어긴 manifest는 거부된다"는 계약 자체다.
"""

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "contract" / "manifest_schema.json"

# 설계 문서 §5 의 예시를 구체화한 정상 manifest.
VALID_MANIFEST = {
    "id": "3f8b0c2e-1a2b-4c3d-9e4f-5a6b7c8d9e0f",
    "vuln_type": "idor",
    "tier": "easy",
    "entry": {
        "port": 8000,
        "task_prompt": "다른 사용자의 비공개 데이터를 읽어 flag를 찾아라",
    },
    "flag": "FLAG{sample_secret}",
    "verify": {"method": "flag_submit"},
    "_internal": {
        "flag_planted_in": "user 2의 비공개 노트",
        "reference_exploit": "exploits/idor_a1b2.py",
        "solution_summary": "소유권 체크가 없어 아무 note_id나 조회 가능",
    },
}


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def validator() -> Draft202012Validator:
    schema = load_schema()
    Draft202012Validator.check_schema(schema)  # 스키마 자체가 유효한 JSON Schema인지
    return Draft202012Validator(schema)


def without(key: str) -> dict:
    m = copy.deepcopy(VALID_MANIFEST)
    m.pop(key)
    return m


def with_change(**changes) -> dict:
    m = copy.deepcopy(VALID_MANIFEST)
    m.update(changes)
    return m


def test_schema_file_exists_and_is_valid_json_schema():
    assert SCHEMA_PATH.exists(), f"계약 스키마가 없다: {SCHEMA_PATH}"
    validator()  # check_schema 통과해야 함


def test_valid_manifest_passes():
    validator().validate(VALID_MANIFEST)  # 예외 없이 통과


def test_internal_block_is_optional():
    # _internal 은 플랫폼 검증용 부가정보라 없어도 계약상 유효해야 한다.
    validator().validate(without("_internal"))


@pytest.mark.parametrize("missing", ["id", "vuln_type", "tier", "entry", "flag", "verify"])
def test_required_field_missing_is_rejected(missing):
    with pytest.raises(ValidationError):
        validator().validate(without(missing))


def test_unknown_vuln_type_is_rejected():
    # enum 밖의 값이어야 한다. xss/hard_sqli 는 계약에 추가돼(엔진 PR #27) 이제 유효하므로
    # 아직 계약에 없는 클래스(ssrf)로 '알 수 없는 vuln_type' 을 검증한다.
    with pytest.raises(ValidationError):
        validator().validate(with_change(vuln_type="ssrf"))


def test_unknown_tier_is_rejected():
    with pytest.raises(ValidationError):
        validator().validate(with_change(tier="medium"))


def test_flag_without_flag_wrapper_is_rejected():
    # flag 는 반드시 FLAG{...} 형식이어야 검증 서비스가 일관되게 판정한다.
    with pytest.raises(ValidationError):
        validator().validate(with_change(flag="just_a_string"))


def test_unknown_top_level_field_is_rejected():
    # 계약 오타(예: verrify)를 잡기 위해 최상위는 additionalProperties=false 여야 한다.
    with pytest.raises(ValidationError):
        validator().validate(with_change(typo_field="oops"))
