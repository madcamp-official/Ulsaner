import pathlib
from engine.injector import inject
from engine.slots.easy_idor import build_easy_idor_slot

TEMPLATE_DIR = pathlib.Path(__file__).parent.parent.parent / "templates" / "notes_app"


def test_inject_writes_vulnerable_code(tmp_path):
    output_dir = tmp_path / "bundle_app"
    slot = build_easy_idor_slot()
    inject(TEMPLATE_DIR, output_dir, slot)
    result = (output_dir / "routes" / "notes.py").read_text()
    # easy/idor 슬롯은 get_note 의 소유권 체크(note.owner_id != user.id)를 제거한다.
    # (list_notes 의 정상 메타데이터 필드 n.owner_id 는 취약점과 무관하므로, 전체 파일에서
    #  "owner_id" 유무가 아니라 소유권 체크 구문 자체가 사라졌는지로 검증한다.)
    assert "note.owner_id != user.id" not in result


def test_inject_preserves_untouched_files(tmp_path):
    output_dir = tmp_path / "bundle_app"
    slot = build_easy_idor_slot()
    inject(TEMPLATE_DIR, output_dir, slot)
    assert (output_dir / "Dockerfile").exists()
    assert (output_dir / "db.py").read_text() == (TEMPLATE_DIR / "db.py").read_text()
