import libcst as cst
from engine.slots.hard_sqli import build_hard_sqli_slot

CLEAN_SOURCE = '''
import sqlite3

_NOTES_DB = sqlite3.connect(":memory:")


def search_notes_advanced(q: str, exclude: str = "") -> list[tuple]:
    query = "SELECT id, title FROM notes WHERE is_private = 0 AND title LIKE ? AND title != ?"
    cursor = _NOTES_DB.execute(query, (f"%{q}%", exclude))
    return cursor.fetchall()
'''


def test_hard_sqli_slot_metadata():
    slot = build_hard_sqli_slot()
    assert slot.vuln_type == "hard_sqli"
    assert slot.tier == "hard"
    assert slot.target_file == "db.py"
    assert slot.target_function == "search_notes_advanced"


def test_hard_sqli_interpolates_exclude_but_keeps_q_bound():
    slot = build_hard_sqli_slot()
    module = cst.parse_module(CLEAN_SOURCE)
    code = slot.transform(module).code
    # exclude becomes raw string-interpolated in the query text...
    assert "title != '{exclude}'" in code
    assert "title != ?" not in code
    # ...but the q placeholder survives (still one real bound parameter)
    assert "LIKE ?" in code
    # the .execute call is STILL a 2-argument call with a params tuple (disguise),
    # but `exclude` was dropped from that tuple
    assert "_NOTES_DB.execute(" in code
    assert ", exclude)" not in code
    assert 'f"%{q}%"' in code


def test_hard_sqli_transformed_code_is_valid_python():
    slot = build_hard_sqli_slot()
    module = cst.parse_module(CLEAN_SOURCE)
    compile(slot.transform(module).code, "<generated>", "exec")


def test_hard_sqli_only_touches_target_function():
    # a sibling function with the same execute shape must be left alone
    source = CLEAN_SOURCE + '''

def unrelated(x):
    q2 = "SELECT 1"
    return _NOTES_DB.execute(q2, (x,))
'''
    slot = build_hard_sqli_slot()
    module = cst.parse_module(source)
    code = slot.transform(module).code
    assert "return _NOTES_DB.execute(q2, (x,))" in code
