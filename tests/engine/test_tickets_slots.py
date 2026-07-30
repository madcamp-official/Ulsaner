import libcst as cst
from engine.slots.tickets import (
    build_tickets_easy_idor_slot,
    build_tickets_hard_idor_slot,
    build_tickets_easy_sqli_slot,
)

IDOR_SOURCE = '''
from fastapi import APIRouter, HTTPException, Depends
from db import get_current_user, get_ticket_by_id

router = APIRouter()

@router.get("/tickets/{ticket_id}")
def get_ticket(ticket_id: int, user=Depends(get_current_user)):
    ticket = get_ticket_by_id(ticket_id)
    if ticket is None:
        raise HTTPException(404)
    if ticket.owner_id != user.id:
        raise HTTPException(403)
    return {"id": ticket.id, "subject": ticket.subject, "description": ticket.description}
'''

SQLI_SOURCE = '''
import sqlite3
_TICKETS_DB = sqlite3.connect(":memory:")

def search_tickets_by_subject(q: str) -> list[tuple]:
    cursor = _TICKETS_DB.execute(
        "SELECT id, subject FROM tickets WHERE is_confidential = 0 AND subject LIKE ?",
        (f"%{q}%",),
    )
    return cursor.fetchall()
'''


def test_tickets_easy_idor_metadata_and_removes_ownership_check():
    slot = build_tickets_easy_idor_slot()
    assert (slot.vuln_type, slot.tier, slot.target_file, slot.target_function) == (
        "idor", "easy", "routes/tickets.py", "get_ticket",
    )
    code = slot.transform(cst.parse_module(IDOR_SOURCE)).code
    assert "ticket.owner_id != user.id" not in code
    assert "ticket is None" in code
    compile(code, "<g>", "exec")


def test_tickets_hard_idor_swaps_to_workspace_scope():
    slot = build_tickets_hard_idor_slot()
    assert (slot.vuln_type, slot.tier) == ("idor", "hard")
    code = slot.transform(cst.parse_module(IDOR_SOURCE)).code
    assert "ticket.workspace_id != user.workspace_id" in code
    assert "ticket.owner_id" not in code
    compile(code, "<g>", "exec")


def test_tickets_easy_sqli_concatenates_query():
    slot = build_tickets_easy_sqli_slot()
    assert (slot.vuln_type, slot.tier, slot.target_file, slot.target_function) == (
        "sqli", "easy", "db.py", "search_tickets_by_subject",
    )
    code = slot.transform(cst.parse_module(SQLI_SOURCE)).code
    assert "LIKE ?" not in code
    assert "LIKE '%{q}%'" in code
    assert "_TICKETS_DB.execute(" in code
    compile(code, "<g>", "exec")
