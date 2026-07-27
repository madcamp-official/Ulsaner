import pathlib
from engine.injector import inject
from engine.slots.easy_idor import build_easy_idor_slot

TEMPLATE_DIR = pathlib.Path(__file__).parent.parent.parent / "templates" / "notes_app"


def test_inject_writes_vulnerable_code(tmp_path):
    output_dir = tmp_path / "bundle_app"
    slot = build_easy_idor_slot()
    inject(TEMPLATE_DIR, output_dir, slot)
    result = (output_dir / "routes" / "notes.py").read_text()
    # the ownership check itself must be gone from get_note; checking the bare
    # substring "owner_id" would also match list_notes's legitimate metadata field
    assert "note.owner_id != user.id" not in result


def test_inject_preserves_untouched_files(tmp_path):
    output_dir = tmp_path / "bundle_app"
    slot = build_easy_idor_slot()
    inject(TEMPLATE_DIR, output_dir, slot)
    assert (output_dir / "Dockerfile").exists()
    assert (output_dir / "db.py").read_text() == (TEMPLATE_DIR / "db.py").read_text()
