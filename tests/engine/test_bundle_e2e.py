import pytest
from engine.bundle import generate_bundle, BundleGenerationError
from engine.slots.easy_idor import build_easy_idor_slot
from engine.slots.hard_idor import build_hard_idor_slot


@pytest.mark.integration
def test_generate_easy_idor_bundle_e2e(tmp_path):
    import json
    output_dir = tmp_path / "bundle-1"
    result = generate_bundle(
        seed=1,
        output_dir=output_dir,
        slot_builder=build_easy_idor_slot,
        task_prompt="다른 사용자의 비공개 노트를 읽어 flag를 찾아라",
        solution_summary="get_note의 소유권 체크 누락을 이용해 다른 유저의 노트를 조회",
    )
    assert (result / "manifest.json").exists()
    assert (result / "app" / "seed_data.json").exists()
    assert (result / "app" / "Dockerfile").exists()

    # Assert reference exploit file exists and has expected structure
    exploit_path = result / "exploits" / "reference.json"
    assert exploit_path.exists()
    with open(exploit_path) as f:
        exploit_data = json.load(f)
    assert "method" in exploit_data
    assert "path" in exploit_data
    assert "headers" in exploit_data
    assert "expected_flag" in exploit_data
    assert isinstance(exploit_data["expected_flag"], str)
    assert len(exploit_data["expected_flag"]) > 0

    # Easy tier must be unaffected by the hard-tier-only reorder pass (Task 12)
    routes_code = (result / "app" / "routes" / "notes.py").read_text()
    assert "note = get_note_by_id(note_id)" in routes_code

    # An idor bundle must leave the sqli surface (db.py's search) untouched and safe
    db_code = (result / "app" / "db.py").read_text()
    assert "LIKE ?" in db_code
    assert "LIKE '%{q}%'" not in db_code


@pytest.mark.integration
def test_generate_bundle_raises_after_max_attempts_when_verification_always_fails(tmp_path):
    from engine.slots.base import Slot

    def broken_slot_builder():
        return Slot(
            vuln_type="idor",
            tier="easy",
            target_file="routes/notes.py",
            target_function="get_note",
            transform=lambda module: module,  # no-op: check stays in place, exploit will fail
        )

    with pytest.raises(BundleGenerationError):
        generate_bundle(
            seed=2,
            output_dir=tmp_path / "bundle-2",
            slot_builder=broken_slot_builder,
            task_prompt="prompt",
            solution_summary="summary",
            max_attempts=2,
        )


@pytest.mark.integration
def test_generate_hard_idor_bundle_e2e(tmp_path):
    output_dir = tmp_path / "bundle-3"
    result = generate_bundle(
        seed=3,
        output_dir=output_dir,
        slot_builder=build_hard_idor_slot,
        task_prompt="다른 사용자의 비공개 노트를 읽어 flag를 찾아라",
        solution_summary="workspace_id 스코프 체크가 owner_id를 대신하는 결함을 이용 (같은 workspace의 다른 유저 노트 열람 가능)",
    )
    assert (result / "manifest.json").exists()


from engine.slots.easy_sqli import build_easy_sqli_slot


@pytest.mark.integration
def test_generate_easy_sqli_bundle_e2e(tmp_path):
    import json
    output_dir = tmp_path / "bundle-4"
    result = generate_bundle(
        seed=4,
        output_dir=output_dir,
        slot_builder=build_easy_sqli_slot,
        task_prompt="검색 기능(GET /notes/search?q=)에서 다른 사용자의 비공개 노트 내용을 찾아 flag를 알아내라",
        solution_summary="db.search_notes_by_title의 문자열 이어붙이기 SQL을 UNION 기반 인젝션으로 악용해 is_private 필터를 우회, 비공개 노트 본문을 title 컬럼으로 유출",
    )
    assert (result / "manifest.json").exists()
    assert (result / "app" / "seed_data.json").exists()
    assert (result / "app" / "Dockerfile").exists()

    exploit_path = result / "exploits" / "reference.json"
    assert exploit_path.exists()
    with open(exploit_path) as f:
        exploit_data = json.load(f)
    assert exploit_data["method"] == "GET"
    assert exploit_data["path"].startswith("/notes/search?q=")
    assert exploit_data["headers"] == {}
    assert isinstance(exploit_data["expected_flag"], str)
    assert len(exploit_data["expected_flag"]) > 0

    manifest = json.loads((result / "manifest.json").read_text())
    assert manifest["vuln_type"] == "sqli"
    assert manifest["tier"] == "easy"

    # sqli slot targets db.py only — the notes.py route (idor slot's target) must be untouched
    notes_routes_code = (result / "app" / "routes" / "notes.py").read_text()
    assert "note.owner_id != user.id" in notes_routes_code

    # the vulnerable db.py must actually contain the concatenated query, proving the AST
    # transform ran (not just that verification happened to pass by coincidence)
    db_code = (result / "app" / "db.py").read_text()
    assert "LIKE ?" not in db_code
    assert "LIKE '%{q}%'" in db_code
