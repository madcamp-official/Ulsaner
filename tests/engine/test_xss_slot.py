import libcst as cst
from engine.slots.xss import build_xss_slot

CLEAN_SOURCE = '''
import html as html_lib
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from db import search_notes_by_title

router = APIRouter()


@router.get("/notes/search/view", response_class=HTMLResponse)
def search_notes_view(q: str = ""):
    rows = search_notes_by_title(q)
    safe_q = html_lib.escape(q)
    results_html = "".join(f"<li>{html_lib.escape(row[1])}</li>" for row in rows)
    return f"<html><body><p>검색어: {safe_q}</p><ul>{results_html}</ul></body></html>"
'''


def test_xss_slot_metadata():
    slot = build_xss_slot()
    assert slot.vuln_type == "xss"
    assert slot.tier == "easy"
    assert slot.target_file == "routes/search.py"
    assert slot.target_function == "search_notes_view"


def test_xss_slot_strips_escape_from_the_reflected_search_term_only():
    slot = build_xss_slot()
    module = cst.parse_module(CLEAN_SOURCE)
    code = slot.transform(module).code
    # the echoed search term loses its escaping...
    assert "safe_q = q" in code
    assert "safe_q = html_lib.escape(q)" not in code
    # ...but the results list stays escaped (single-sink, minimal, realistic)
    assert "html_lib.escape(row[1])" in code


def test_xss_transformed_code_is_valid_python():
    slot = build_xss_slot()
    module = cst.parse_module(CLEAN_SOURCE)
    compile(slot.transform(module).code, "<generated>", "exec")
