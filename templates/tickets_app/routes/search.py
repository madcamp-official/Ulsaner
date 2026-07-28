from fastapi import APIRouter
from db import search_tickets_by_subject

router = APIRouter()


@router.get("/tickets/search")
def search_tickets(q: str = ""):
    rows = search_tickets_by_subject(q)
    return {"results": [{"id": row[0], "subject": row[1]} for row in rows]}
