"""챌린지 번들 manifest 로딩·검증.

계약(contract/manifest_schema.json)이 진실의 원천이다. 여기서 스키마를 재구현하지 않고
jsonschema 로 계약 부합을 먼저 강제한 뒤, 편의를 위한 타입드 뷰(Manifest)로 감싼다.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

# platform/ulsaner_platform/manifest.py -> parents[2] == 레포 루트
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _REPO_ROOT / "contract" / "manifest_schema.json"


class ManifestValidationError(ValueError):
    """manifest 가 계약 스키마를 어겼을 때."""


@functools.lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


class Manifest:
    """검증을 통과한 manifest 의 타입드 뷰.

    직접 생성하지 말고 load_manifest / load_bundle_manifest 를 쓴다.
    """

    def __init__(self, data: dict):
        self._data = data

    # --- 계약 필드 접근자 ---
    @property
    def id(self) -> str:
        return self._data["id"]

    @property
    def vuln_type(self) -> str:
        return self._data["vuln_type"]

    @property
    def tier(self) -> str:
        return self._data["tier"]

    @property
    def port(self) -> int:
        return self._data["entry"]["port"]

    @property
    def task_prompt(self) -> str:
        return self._data["entry"]["task_prompt"]

    @property
    def flag(self) -> str:
        return self._data["flag"]

    @property
    def verify_method(self) -> str:
        return self._data["verify"]["method"]

    # --- 검증 서비스용 ---
    def check_flag(self, submitted: str) -> bool:
        """제출된 flag 가 정답과 일치하는지. 복붙 시 섞이는 앞뒤 공백은 허용."""
        return submitted.strip() == self.flag

    # --- 학생 노출용 (블랙박스) ---
    def public_view(self) -> dict:
        """학생에게 노출 가능한 필드만. flag·_internal 은 절대 포함하지 않는다(설계 §5)."""
        return {
            "id": self.id,
            "vuln_type": self.vuln_type,
            "tier": self.tier,
            "entry": {"port": self.port, "task_prompt": self.task_prompt},
        }


def _validate(data: dict) -> None:
    try:
        _validator().validate(data)
    except ValidationError as exc:
        raise ManifestValidationError(str(exc)) from exc


def load_manifest(path: str | Path) -> Manifest:
    """manifest.json 파일 경로에서 로드 + 계약 검증."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    _validate(data)
    return Manifest(data)


def load_bundle_manifest(bundle_dir: str | Path) -> Manifest:
    """번들 디렉토리(내부의 manifest.json)에서 로드."""
    return load_manifest(Path(bundle_dir) / "manifest.json")
