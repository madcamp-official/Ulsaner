import html as html_lib
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from db import search_notes_by_title, search_notes_advanced

router = APIRouter()


@router.get("/notes/search")
def search_notes(q: str = ""):
    rows = search_notes_by_title(q)
    return {"results": [{"id": row[0], "title": row[1]} for row in rows]}


@router.get("/notes/search/advanced")
def search_advanced(q: str = "", exclude: str = ""):
    rows = search_notes_advanced(q, exclude)
    return {"results": [{"id": row[0], "title": row[1]} for row in rows]}


@router.get("/notes/search/view", response_class=HTMLResponse)
def search_notes_view(q: str = ""):
    rows = search_notes_by_title(q)
    safe_q = html_lib.escape(q)
    results_html = "".join(f"<li>{html_lib.escape(row[1])}</li>" for row in rows)
    return f"<html><body><p>검색어: {safe_q}</p><ul>{results_html}</ul></body></html>"
