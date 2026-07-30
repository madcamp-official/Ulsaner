import libcst as cst
from engine.slots.easy_sqli import build_easy_sqli_slot

CLEAN_SOURCE = '''
import sqlite3

_NOTES_DB = sqlite3.connect(":memory:")


def search_notes_by_title(q: str) -> list[tuple]:
    cursor = _NOTES_DB.execute(
        "SELECT id, title FROM notes WHERE is_private = 0 AND title LIKE ?",
        (f"%{q}%",),
    )
    return cursor.fetchall()
'''


def test_easy_sqli_slot_concatenates_query_string():
    slot = build_easy_sqli_slot()
    module = cst.parse_module(CLEAN_SOURCE)
    transformed = slot.transform(module)
    code = transformed.code
    assert "LIKE ?" not in code
    assert "LIKE '%{q}%'" in code
    assert "_NOTES_DB.execute(" in code


def test_easy_sqli_transformed_code_is_valid_python():
    slot = build_easy_sqli_slot()
    module = cst.parse_module(CLEAN_SOURCE)
    transformed = slot.transform(module)
    compile(transformed.code, "<generated>", "exec")
