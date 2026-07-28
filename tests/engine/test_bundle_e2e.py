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


from engine.slots.hard_sqli import build_hard_sqli_slot


@pytest.mark.integration
def test_generate_hard_sqli_bundle_e2e(tmp_path):
    import json
    output_dir = tmp_path / "bundle-hard-sqli"
    result = generate_bundle(
        seed=7,
        output_dir=output_dir,
        slot_builder=build_hard_sqli_slot,
        task_prompt="검색 고급 필터(GET /notes/search/advanced)의 exclude 파라미터로 비공개 노트 본문을 유출해 flag를 찾아라",
        solution_summary="search_notes_advanced의 exclude 값이 파라미터 바인딩 대신 문자열 보간되는 결함(prepared statement 위장)을 UNION 인젝션으로 악용",
    )
    assert (result / "manifest.json").exists()
    assert (result / "app" / "seed_data.json").exists()
    assert (result / "app" / "Dockerfile").exists()

    exploit_path = result / "exploits" / "reference.json"
    assert exploit_path.exists()
    with open(exploit_path) as f:
        exploit_data = json.load(f)
    assert exploit_data["method"] == "GET"
    assert exploit_data["path"].startswith("/notes/search/advanced?q=&exclude=")
    assert exploit_data["headers"] == {}
    assert isinstance(exploit_data["expected_flag"], str)
    assert len(exploit_data["expected_flag"]) > 0

    manifest = json.loads((result / "manifest.json").read_text())
    assert manifest["vuln_type"] == "hard_sqli"
    assert manifest["tier"] == "hard"

    # the vulnerable interpolation is really present (transform ran)
    db_code = (result / "app" / "db.py").read_text()
    assert "title != '{exclude}'" in db_code
    assert ", exclude)" not in db_code
    # CROSS-CONTAMINATION: easy_sqli's target (search_notes_by_title) untouched...
    assert "LIKE ?" in db_code
    assert "LIKE '%{q}%'" not in db_code
    # ...and the idor slot's target (routes/notes.py ownership check) intact
    notes_routes_code = (result / "app" / "routes" / "notes.py").read_text()
    assert "note.owner_id != user.id" in notes_routes_code


from engine.slots.xss import build_xss_slot


@pytest.mark.integration
def test_generate_xss_bundle_e2e(tmp_path):
    import json
    output_dir = tmp_path / "bundle-xss"
    result = generate_bundle(
        seed=8,
        output_dir=output_dir,
        slot_builder=build_xss_slot,
        task_prompt="검색 결과 페이지(GET /notes/search/view)에 검색어가 이스케이프 없이 반사된다. 페이로드가 원문 그대로 반영됨을 증명하라 (반사형 XSS).",
        solution_summary="search_notes_view가 검색어 q를 html.escape 없이 HTML에 삽입 -> <script> 페이로드가 이스케이프되지 않고 그대로 반사",
    )
    assert (result / "manifest.json").exists()

    exploit_path = result / "exploits" / "reference.json"
    with open(exploit_path) as f:
        exploit_data = json.load(f)
    assert exploit_data["method"] == "GET"
    assert exploit_data["path"].startswith("/notes/search/view?q=")
    # deliberate divergence: expected_flag is the full <script> payload
    assert exploit_data["expected_flag"].startswith("<script>")
    assert exploit_data["expected_flag"].endswith("</script>")

    manifest = json.loads((result / "manifest.json").read_text())
    assert manifest["vuln_type"] == "xss"
    assert manifest["tier"] == "easy"
    # manifest flag stays the bare FLAG{...} (NOT the payload) and matches the schema
    assert manifest["flag"].startswith("FLAG{")
    assert manifest["flag"] in exploit_data["expected_flag"]

    # the escaping was really stripped from the echoed term (transform ran)...
    search_code = (result / "app" / "routes" / "search.py").read_text()
    assert "safe_q = q" in search_code
    assert "safe_q = html_lib.escape(q)" not in search_code
    # ...but the results-list escaping survives (single sink)
    assert "html_lib.escape(row[1])" in search_code


from engine.bundle import TICKETS_TEMPLATE_DIR, TICKETS_EXPLOIT_BUILDERS
from engine import tickets_params
from engine.slots.tickets import (
    build_tickets_easy_idor_slot,
    build_tickets_hard_idor_slot,
    build_tickets_easy_sqli_slot,
)


def _generate_tickets_bundle(tmp_path, name, seed, slot_builder, reorder_var_name="ticket"):
    return generate_bundle(
        seed=seed,
        output_dir=tmp_path / name,
        slot_builder=slot_builder,
        task_prompt="다른 사용자의 기밀 티켓(description)을 읽어 flag를 찾아라",
        solution_summary="tickets_app에서의 접근제어/인젝션 결함",
        template_dir=TICKETS_TEMPLATE_DIR,
        seed_data_builder=tickets_params.build_seed_data,
        exploit_builders=TICKETS_EXPLOIT_BUILDERS,
        reorder_var_name=reorder_var_name,
        health_check_path="/tickets/2",
    )


@pytest.mark.integration
def test_generate_tickets_easy_idor_bundle_e2e(tmp_path):
    import json
    result = _generate_tickets_bundle(tmp_path, "t-easy-idor", 21, build_tickets_easy_idor_slot)
    assert (result / "manifest.json").exists()
    manifest = json.loads((result / "manifest.json").read_text())
    assert manifest["vuln_type"] == "idor"
    assert manifest["tier"] == "easy"
    tickets_code = (result / "app" / "routes" / "tickets.py").read_text()
    assert "ticket.owner_id != user.id" not in tickets_code
    db_code = (result / "app" / "db.py").read_text()
    assert "LIKE ?" in db_code


@pytest.mark.integration
def test_generate_tickets_hard_idor_bundle_e2e(tmp_path):
    import json
    result = _generate_tickets_bundle(tmp_path, "t-hard-idor", 22, build_tickets_hard_idor_slot)
    manifest = json.loads((result / "manifest.json").read_text())
    assert manifest["vuln_type"] == "idor"
    assert manifest["tier"] == "hard"
    tickets_code = (result / "app" / "routes" / "tickets.py").read_text()
    assert "workspace_id" in tickets_code


@pytest.mark.integration
def test_generate_tickets_easy_sqli_bundle_e2e(tmp_path):
    import json
    result = _generate_tickets_bundle(
        tmp_path, "t-easy-sqli", 23, build_tickets_easy_sqli_slot, reorder_var_name="ticket"
    )
    manifest = json.loads((result / "manifest.json").read_text())
    assert manifest["vuln_type"] == "sqli"
    assert manifest["tier"] == "easy"
    db_code = (result / "app" / "db.py").read_text()
    assert "LIKE '%{q}%'" in db_code
    assert "LIKE ?" not in db_code
    tickets_code = (result / "app" / "routes" / "tickets.py").read_text()
    assert "ticket.owner_id != user.id" in tickets_code
