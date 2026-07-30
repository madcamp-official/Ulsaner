import json
import uuid
import pathlib
import jsonschema


def build_manifest(
    vuln_type: str,
    tier: str,
    flag: str,
    task_prompt: str,
    reference_exploit_path: str,
    solution_summary: str,
    hints: list[str] | None = None,
) -> dict:
    entry: dict = {"port": 8000, "task_prompt": task_prompt}
    # 힌트는 선택 — 있을 때만 entry 에 싣는다(없으면 기존 manifest 형태 그대로, 하위호환).
    if hints:
        entry["hints"] = list(hints)
    return {
        "id": str(uuid.uuid4()),
        "vuln_type": vuln_type,
        "tier": tier,
        "entry": entry,
        "flag": flag,
        "verify": {"method": "flag_submit"},
        "_internal": {
            "flag_planted_in": "target user's private note",
            "reference_exploit": reference_exploit_path,
            "solution_summary": solution_summary,
        },
    }


def write_manifest(output_dir: pathlib.Path, manifest: dict, schema_path: pathlib.Path) -> None:
    schema = json.loads(schema_path.read_text())
    jsonschema.validate(manifest, schema)
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
