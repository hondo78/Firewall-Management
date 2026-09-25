"""Vorlagen (wiederverwendbare Änderungen) und Abgleich einer Firewall-Gruppe gegen eine Referenz."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .. import changes, diff, permissions, sync
from ..audit import audit
from ..db import get_db
from ..models import ChangeRequest, ChangeTemplate, Firewall, FirewallGroup, User
from ..permissions import firewall_or_404
from ..security import client_ip, get_current_user
from ..serializers import change_out
from ..sophos import entities

router = APIRouter(prefix="/api", tags=["templates"])


def _out(t: ChangeTemplate) -> dict:
    return {"id": t.id, "name": t.name, "description": t.description, "format": t.format,
            "operations": [{"entity": o["entity"], "action": o["action"], "name": o["name"],
                            "label": entities.LABELS.get(o["entity"], o["entity"])} for o in t.operations],
            "created_at": t.created_at, "created_by": t.created_by}


@router.get("/templates")
def list_templates(user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    if not permissions.can_anywhere(db, user, "change.create"):
        return []
    return [_out(t) for t in db.execute(select(ChangeTemplate).order_by(ChangeTemplate.name)).scalars()]


class TemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    change_id: str


@router.post("/templates")
def create_template(body: TemplateIn, request: Request, user: User = Depends(get_current_user),
                    db: DbSession = Depends(get_db)):
    """Vorlage aus einem Entwurf oder Antrag (dessen Operationen, ohne firewall-spezifischen Vorher-Stand)."""
    cr = db.get(ChangeRequest, body.change_id)
    if not cr or not permissions.can(db, user, "change.create", cr.firewall):
        raise HTTPException(404, "Antrag nicht gefunden")
    if db.execute(select(ChangeTemplate).where(ChangeTemplate.name == body.name.strip())).scalar():
        raise HTTPException(409, "Eine Vorlage mit diesem Namen existiert bereits")
    ops = [{k: v for k, v in o.items() if k not in ("before", "before_position")} for o in cr.operations or []]
    if not ops:
        raise HTTPException(400, "Der Antrag enthält keine Änderungen")
    t = ChangeTemplate(name=body.name.strip(), description=body.description, operations=ops,
                       format=entities.fmt_for(cr.firewall.connector), created_by=user.id)
    db.add(t)
    db.flush()
    audit(db, "template.created", actor=user, target_type="template", target_id=t.id, ip=client_ip(request),
          details={"name": t.name, "from_change": cr.number, "operations": len(ops)})
    return _out(t)


@router.delete("/templates/{template_id}")
def delete_template(template_id: str, request: Request, user: User = Depends(get_current_user),
                    db: DbSession = Depends(get_db)):
    t = db.get(ChangeTemplate, template_id)
    if not t:
        raise HTTPException(404, "Vorlage nicht gefunden")
    if t.created_by != user.id and not permissions.has_global(db, user, "admin"):
        raise HTTPException(403, "Nur der Ersteller oder ein Administrator kann die Vorlage löschen")
    db.delete(t)
    audit(db, "template.deleted", actor=user, target_type="template", target_id=template_id, ip=client_ip(request),
          details={"name": t.name})
    return {"ok": True}


@router.post("/firewalls/{firewall_id}/templates/{template_id}/apply")
def apply_template(firewall_id: str, template_id: str, user: User = Depends(get_current_user),
                   db: DbSession = Depends(get_db)):
    """Operationen der Vorlage in den eigenen Entwurf dieser Firewall übernehmen (einzeln geprüft)."""
    fw = firewall_or_404(db, user, firewall_id, "change.create")
    t = db.get(ChangeTemplate, template_id)
    if not t:
        raise HTTPException(404, "Vorlage nicht gefunden")
    if t.format != entities.fmt_for(fw.connector):
        raise HTTPException(400, "Die Vorlage passt nicht zum Format (REST/XML) dieser Firewall")
    cr, warnings, skipped = None, [], []
    for o in t.operations:
        try:
            cr, w = changes.draft_add(db, user, fw, dict(o))
            warnings = w
        except HTTPException as e:
            db.rollback()
            skipped.append(f"{entities.LABELS.get(o['entity'], o['entity'])} „{o['name']}“: {e.detail}")
    if cr is None:
        raise HTTPException(409, "Keine Operation der Vorlage passt: " + "; ".join(skipped))
    if not cr.title:
        cr.title = t.name[:300]
        db.commit()
    return {"draft": change_out(db, cr, user), "warnings": warnings, "skipped": skipped}


@router.get("/groups/{group_id}/drift")
def group_drift(group_id: str, reference: str, user: User = Depends(get_current_user),
                db: DbSession = Depends(get_db)):
    """Abgleich aller Firewalls einer Gruppe gegen eine Referenz-Firewall (je Entität: +/−/~)."""
    group = db.get(FirewallGroup, group_id)
    if not group:
        raise HTTPException(404, "Gruppe nicht gefunden")
    ref = firewall_or_404(db, user, reference)
    ref_cfg = sync.cached_config(db, ref)
    fmt = entities.fmt_for(ref.connector)
    rows = []
    for fw in db.execute(select(Firewall).where(Firewall.group_id == group.id, Firewall.archived.is_(False),
                                                Firewall.id != ref.id).order_by(Firewall.name)).scalars():
        if not permissions.can(db, user, "firewall.view", fw):
            continue
        if entities.fmt_for(fw.connector) != fmt:
            rows.append({"id": fw.id, "name": fw.name, "error": "anderes Format (REST/XML)"})
            continue
        result = diff.compare_configs(ref_cfg, sync.cached_config(db, fw))
        rows.append({"id": fw.id, "name": fw.name, "last_sync_at": fw.last_sync_at, "entities": {
            e: {"missing": len(c["removed"]), "extra": len(c["added"]), "different": len(c["modified"]),
                "missing_names": c["removed"][:50], "different_names": [m["name"] for m in c["modified"]][:50]}
            for e, c in result.items()},
            "total": sum(len(c["removed"]) + len(c["added"]) + len(c["modified"]) for c in result.values())})
    return {"reference": {"id": ref.id, "name": ref.name}, "firewalls": rows,
            "labels": {e: entities.LABELS.get(e, e) for e in entities.names(fmt)}}
