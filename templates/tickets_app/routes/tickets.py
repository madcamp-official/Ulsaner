from fastapi import APIRouter, HTTPException, Depends
from db import get_current_user, get_ticket_by_id, list_tickets_in_workspace

router = APIRouter()


@router.get("/tickets")
def list_tickets(user=Depends(get_current_user)):
    return [
        {"id": t.id, "owner_id": t.owner_id, "subject": t.subject, "is_confidential": t.is_confidential}
        for t in list_tickets_in_workspace(user.workspace_id)
    ]


@router.get("/tickets/{ticket_id}")
def get_ticket(ticket_id: int, user=Depends(get_current_user)):
    ticket = get_ticket_by_id(ticket_id)
    if ticket is None:
        raise HTTPException(404)
    if ticket.owner_id != user.id:
        raise HTTPException(403)
    return {"id": ticket.id, "subject": ticket.subject, "description": ticket.description}
