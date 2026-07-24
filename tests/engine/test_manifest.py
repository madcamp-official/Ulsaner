import json
import pathlib

SCHEMA_PATH = pathlib.Path(__file__).parent.parent.parent / "contract" / "manifest_schema.json"

def test_schema_file_is_valid_json():
    schema = json.loads(SCHEMA_PATH.read_text())
    assert schema["title"] == "Ulsaner Challenge Manifest"
