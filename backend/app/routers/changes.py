"""Änderungsanträge (Vier-Augen-Prinzip)."""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session as DbSession

from .. import changes, permissions, worker
from ..audit import audit
from ..db import get_db
from ..models import ChangeRequest, Firewall, User
from ..permissions import firewall_or_404
from ..security import client_ip, get_current_user
from ..serializers import change_out, change_summary

router = APIRouter(prefix="/api", tags=["changes"])


class OperationIn(BaseModel):
    entity: str
    action: str
    name: str
    data: dict | None = None
    position: dict | None = None


class SubmitIn(BaseModel):
    title: str = Field(max_length=300)
    justification: str
    ticket_ref: str = ""
    deploy_after: datetime | None = None


class DecisionIn(BaseModel):
    decision: str
    comment: str = ""


class CommentIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)


def _change_or_404(db: DbSession, user: User, change_id: str) -> ChangeRequest:
    cr = db.get(ChangeRequest, change_id)
    if not cr or not permissions.can(db, user, "firewall.view", cr.firewall):
        raise HTTPException(404, "Antrag nicht gefunden")
    if cr.status == "draft" and cr.created_by != user.id:
        raise HTTPException(404, "Antrag nicht gefunden")
    return cr


# --- Entwurf -------------------------------------------------------------------------------------------------

@router.get("/firewalls/{firewall_id}/draft")
def get_draft(firewall_id: str, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id)
    cr = changes.get_draft(db, user, fw)
    return change_out(db, cr, user) if cr else None


@router.post("/firewalls/{firewall_id}/draft/operations")
def add_operation(firewall_id: str, body: OperationIn, user: User = Depends(get_current_user),
                  db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id, "change.create")
    if not fw.last_sync_at:
        raise HTTPException(409, "Firewall wurde noch nie synchronisiert – bitte zuerst synchronisieren")
    cr, warnings = changes.draft_add(db, user, fw, body.model_dump())
    return {"draft": change_out(db, cr, user), "warnings": warnings}


@router.delete("/changes/{change_id}/operations/{index}")
def remove_operation(change_id: str, index: int, user: User = Depends(get_current_user),
                     db: DbSession = Depends(get_db)):
    cr = _change_or_404(db, user, change_id)
    if cr.status != "draft" or cr.created_by != user.id:
        raise HTTPException(409, "Nur eigene Entwürfe können bearbeitet werden")
    changes.draft_remove(db, user, cr, index)
    return change_out(db, cr, user)


@router.post("/changes/{change_id}/submit")
def submit(change_id: str, body: SubmitIn, request: Request, user: User = Depends(get_current_user),
           db: DbSession = Depends(get_db)):
    cr = _change_or_404(db, user, change_id)
    changes.submit(db, user, cr, title=body.title, justification=body.justification, ticket_ref=body.ticket_ref,
                   deploy_after=body.deploy_after, ip=client_ip(request))
    return change_out(db, cr, user)


# --- Liste & Details -----------------------------------------------------------------------------------------

@router.get("/changes")
def list_changes(status: str | None = None, firewall_id: str | None = None, mine: bool = False,
                 to_approve: bool = False, q: str = "", limit: int = 200,
                 user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    stmt = select(ChangeRequest).where(ChangeRequest.status != "draft")
    if status:
        stmt = stmt.where(ChangeRequest.status.in_(status.split(",")))
    if firewall_id:
        stmt = stmt.where(ChangeRequest.firewall_id == firewall_id)
    if mine:
        stmt = stmt.where(ChangeRequest.created_by == user.id)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(ChangeRequest.title.ilike(like), ChangeRequest.ticket_ref.ilike(like),
                              ChangeRequest.justification.ilike(like)))
    rows = db.execute(stmt.order_by(ChangeRequest.number.desc()).limit(min(limit, 1000))).scalars().all()
    out = []
    fw_cache: dict[str, bool] = {}
    for cr in rows:
        if cr.firewall_id not in fw_cache:
            fw_cache[cr.firewall_id] = permissions.can(db, user, "firewall.view", cr.firewall)
        if not fw_cache[cr.firewall_id]:
            continue
        if to_approve:
            if cr.status != "pending" or cr.created_by == user.id:
                continue
            if any(e.kind == "approved" and e.user_id == user.id for e in cr.events):
                continue
            if not permissions.can(db, user, "change.approve", cr.firewall):
                continue
        out.append(change_summary(cr))
    return out


@router.get("/changes/drafts")
def my_drafts(user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    rows = db.execute(select(ChangeRequest).where(ChangeRequest.status == "draft",
                                                  ChangeRequest.created_by == user.id)).scalars().all()
    return [change_summary(cr) for cr in rows if cr.operations]


@router.get("/changes/{change_id}")
def get_change(change_id: str, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    cr = _change_or_404(db, user, change_id)
    out = change_out(db, cr, user)
    # Andere offene Anträge, die dieselben Objekte betreffen
    keys = {(o["entity"], o["name"]) for o in cr.operations or []}
    others = db.execute(select(ChangeRequest).where(
        ChangeRequest.firewall_id == cr.firewall_id, ChangeRequest.id != cr.id,
        ChangeRequest.status.in_(("pending", "approved", "deploying")))).scalars().all()
    out["overlaps"] = [change_summary(o) for o in others
                       if keys & {(x["entity"], x["name"]) for x in o.operations or []}]
    return out


# --- Workflow ------------------------------------------------------------------------------------------------

@router.post("/changes/{change_id}/decision")
def decide(change_id: str, body: DecisionIn, request: Request, user: User = Depends(get_current_user),
           db: DbSession = Depends(get_db)):
    cr = _change_or_404(db, user, change_id)
    changes.decide(db, user, cr, body.decision, body.comment, client_ip(request))
    return change_out(db, cr, user)


@router.post("/changes/{change_id}/withdraw")
def withdraw(change_id: str, request: Request, user: User = Depends(get_current_user),
             db: DbSession = Depends(get_db)):
    cr = _change_or_404(db, user, change_id)
    changes.withdraw(db, user, cr, client_ip(request))
    return change_out(db, cr, user)


@router.post("/changes/{change_id}/comments")
def add_comment(change_id: str, body: CommentIn, user: User = Depends(get_current_user),
                db: DbSession = Depends(get_db)):
    cr = _change_or_404(db, user, change_id)
    changes.comment(db, user, cr, body.text)
    return change_out(db, cr, user)


@router.post("/changes/{change_id}/deploy")
def deploy_now(change_id: str, request: Request, user: User = Depends(get_current_user),
               db: DbSession = Depends(get_db)):
    """Genehmigten (oder fehlgeschlagenen) Antrag sofort ausrollen – im Hintergrund."""
    cr = _change_or_404(db, user, change_id)
    if not permissions.can(db, user, "change.deploy", cr.firewall):
        raise HTTPException(403, "Keine Berechtigung zum Ausrollen")
    if not changes.claim_for_deploy(db, cr.id, ("approved", "failed")):
        raise HTTPException(409, "Antrag ist nicht genehmigt oder wird bereits ausgerollt")
    audit(db, "change.deploy_requested", actor=user, target_type="change", target_id=cr.id, ip=client_ip(request),
          details={"number": cr.number, "firewall": cr.firewall.name})
    worker.deploy_in_background(cr.id, user.id)
    db.refresh(cr)
    return change_out(db, cr, user)


@router.post("/changes/{change_id}/revert")
def revert(change_id: str, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    cr = _change_or_404(db, user, change_id)
    fw: Firewall = firewall_or_404(db, user, cr.firewall_id, "change.create")
    draft = changes.revert_draft(db, user, cr)
    return {"firewall_id": fw.id, "draft_id": draft.id}
