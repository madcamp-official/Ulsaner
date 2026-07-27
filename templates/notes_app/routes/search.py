from fastapi import APIRouter
from db import search_notes_by_title

router = APIRouter()


@router.get("/notes/search")
def search_notes(q: str = ""):
    rows = search_notes_by_title(q)
    return {"results": [{"id": row[0], "title": row[1]} for row in rows]}
