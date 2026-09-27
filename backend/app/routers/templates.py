"""Vorlagen (wiederverwendbare Änderungen) und Abgleich einer Firewall-Gruppe gegen eine Referenz."""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .. import changes, diff, permissions, sync, template_plan
from ..audit import audit
from ..db import get_db
from ..models import ChangeRequest, ChangeTemplate, Firewall, FirewallGroup, User, utcnow
from ..permissions import firewall_or_404
from ..security import client_ip, get_current_user
from ..serializers import change_out
from ..sophos import entities
from ..i18n import tr

router = APIRouter(prefix="/api", tags=["templates"])


def _out(db: DbSession, t: ChangeTemplate, full: bool = False) -> dict:
    items = template_plan.normalize_items(t.operations)
    names = {u.id: u.username for u in db.execute(select(User).where(User.id.in_([x for x in (t.created_by, t.updated_by) if x]))).scalars()}
    out = {"id": t.id, "name": t.name, "description": t.description, "format": t.format, "version": t.version,
           "created_at": t.created_at, "created_by": names.get(t.created_by), "created_by_id": t.created_by,
           "updated_at": t.updated_at, "updated_by": names.get(t.updated_by),
           "items": [{"entity": i["entity"], "name": i["name"], "action": i["action"],
                      "label": entities.LABELS.get(i["entity"], i["entity"]),
                      **({"data": i.get("data"), "position": i.get("position")} if full else {})} for i in items],
           # für die Vorlagen-Auswahl im Editor (ältere Oberflächen)
           "operations": [{"entity": i["entity"], "action": i["action"], "name": i["name"]} for i in items]}
    return out


def _may_edit(db: DbSession, user: User, t: ChangeTemplate) -> bool:
    return t.created_by == user.id or permissions.has_global(db, user, "admin")


def _template_or_404(db: DbSession, template_id: str) -> ChangeTemplate:
    t = db.get(ChangeTemplate, template_id)
    if not t:
        raise HTTPException(404, tr('Vorlage nicht gefunden'))
    return t


@router.get("/templates")
def list_templates(user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    if not permissions.can_anywhere(db, user, "change.create"):
        return []
    return [{**_out(db, t), "may_edit": _may_edit(db, user, t)}
            for t in db.execute(select(ChangeTemplate).order_by(ChangeTemplate.name)).scalars()]


@router.get("/templates/{template_id}")
def get_template(template_id: str, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    if not permissions.can_anywhere(db, user, "change.create"):
        raise HTTPException(403, tr('Keine Berechtigung'))
    t = _template_or_404(db, template_id)
    used = db.execute(select(ChangeRequest).where(ChangeRequest.template_id == t.id)
                      .order_by(ChangeRequest.created_at.desc()).limit(50)).scalars().all()
    return {**_out(db, t, full=True), "may_edit": _may_edit(db, user, t),
            "history": [{"id": c.id, "number": c.number, "firewall": c.firewall.name if c.firewall else "",
                         "status": c.status, "version": c.template_version, "created_at": c.created_at} for c in used]}


class ItemIn(BaseModel):
    entity: str
    name: str = Field(min_length=1, max_length=300)
    action: str = "ensure"
    data: dict | None = None
    position: dict | None = None


class TemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    # entweder aus einem Entwurf/Antrag …
    change_id: str | None = None
    # … oder direkt mit Format und Einträgen
    format: str | None = None
    items: list[ItemIn] | None = None


def _items_in(body_items: list[ItemIn]) -> list[dict]:
    out = []
    for i in body_items:
        item = {"entity": i.entity, "name": i.name.strip(), "action": i.action}
        if i.action == "ensure":
            item["data"] = template_plan.clean_data(i.data or {})
        if i.position and i.entity in entities.RULE_ENTITIES:
            item["position"] = {"type": i.position.get("type"), **({"ref": i.position["ref"]} if i.position.get("ref") else {})}
        out.append(item)
    return out


@router.post("/templates")
def create_template(body: TemplateIn, request: Request, user: User = Depends(get_current_user),
                    db: DbSession = Depends(get_db)):
    """Neue Vorlage – aus einem Entwurf/Antrag (dessen Änderungen) oder leer bzw. mit Einträgen."""
    if not permissions.can_anywhere(db, user, "change.create"):
        raise HTTPException(403, tr('Keine Berechtigung'))
    name = body.name.strip()
    if db.execute(select(ChangeTemplate).where(ChangeTemplate.name == name)).scalar():
        raise HTTPException(409, tr('Eine Vorlage mit diesem Namen existiert bereits'))
    source = None
    if body.change_id:
        cr = db.get(ChangeRequest, body.change_id)
        if not cr or not permissions.can(db, user, "change.create", cr.firewall):
            raise HTTPException(404, tr('Antrag nicht gefunden'))
        items = template_plan.normalize_items(cr.operations)
        if not items:
            raise HTTPException(400, tr('Der Antrag enthält keine Änderungen'))
        fmt, source = entities.fmt_for(cr.firewall.connector), cr.number
    else:
        fmt = body.format if body.format in ("rest", "xml") else None
        if not fmt:
            raise HTTPException(400, tr('Format muss rest oder xml sein'))
        items = _items_in(body.items or [])
    template_plan.validate_items(fmt, items)
    t = ChangeTemplate(name=name, description=body.description.strip(), operations=items, format=fmt, created_by=user.id)
    db.add(t)
    db.flush()
    audit(db, "template.created", actor=user, target_type="template", target_id=t.id, ip=client_ip(request),
          details={"name": t.name, "format": fmt, "items": len(items), **({"from_change": source} if source else {})})
    return _out(db, t, full=True)


class TemplateUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    items: list[ItemIn]
    version: int                                   # Schutz vor gleichzeitigem Bearbeiten


@router.put("/templates/{template_id}")
def update_template(template_id: str, body: TemplateUpdate, request: Request, user: User = Depends(get_current_user),
                    db: DbSession = Depends(get_db)):
    t = _template_or_404(db, template_id)
    if not _may_edit(db, user, t):
        raise HTTPException(403, tr('Nur der Ersteller oder ein Administrator kann die Vorlage ändern'))
    if body.version != t.version:
        raise HTTPException(409, tr('Die Vorlage wurde inzwischen geändert (Version {0}) – bitte neu laden', t.version))
    name = body.name.strip()
    if name != t.name and db.execute(select(ChangeTemplate).where(ChangeTemplate.name == name)).scalar():
        raise HTTPException(409, tr('Eine Vorlage mit diesem Namen existiert bereits'))
    items = _items_in(body.items)
    template_plan.validate_items(t.format, items)
    old = {(i["entity"], i["name"]): i for i in template_plan.normalize_items(t.operations)}
    new = {(i["entity"], i["name"]): i for i in items}
    summary = {"added": [f"{e}:{n}" for e, n in new if (e, n) not in old],
               "removed": [f"{e}:{n}" for e, n in old if (e, n) not in new],
               "changed": [f"{e}:{n}" for (e, n), i in new.items() if (e, n) in old and diff.canonical(i) != diff.canonical(old[(e, n)])]}
    t.name, t.description, t.operations = name, body.description.strip(), items
    t.version += 1
    t.updated_at, t.updated_by = utcnow(), user.id
    audit(db, "template.updated", actor=user, target_type="template", target_id=t.id, ip=client_ip(request),
          details={"name": t.name, "version": t.version, **summary})
    return _out(db, t, full=True)


@router.delete("/templates/{template_id}")
def delete_template(template_id: str, request: Request, user: User = Depends(get_current_user),
                    db: DbSession = Depends(get_db)):
    t = _template_or_404(db, template_id)
    if not _may_edit(db, user, t):
        raise HTTPException(403, tr('Nur der Ersteller oder ein Administrator kann die Vorlage löschen'))
    db.delete(t)
    audit(db, "template.deleted", actor=user, target_type="template", target_id=template_id, ip=client_ip(request),
          details={"name": t.name, "version": t.version})
    return {"ok": True}


class TargetsIn(BaseModel):
    firewall_ids: list[str] = Field(min_length=1, max_length=500)


def _targets(db: DbSession, user: User, ids: list[str]) -> list[Firewall]:
    return [firewall_or_404(db, user, fid, "change.create") for fid in dict.fromkeys(ids)]


@router.post("/templates/{template_id}/preview")
def preview_template(template_id: str, body: TargetsIn, user: User = Depends(get_current_user),
                     db: DbSession = Depends(get_db)):
    """Was die Vorlage auf den gewählten Firewalls ändern würde – nichts wird gespeichert."""
    t = _template_or_404(db, template_id)
    return {"version": t.version, "firewalls": template_plan.preview(db, user, t, _targets(db, user, body.firewall_ids))}


class PushIn(TargetsIn):
    title: str = Field(min_length=1, max_length=300)
    justification: str = Field(min_length=1)
    ticket_ref: str = ""
    deploy_after: datetime | None = None
    expires_at: datetime | None = None
    version: int


@router.post("/templates/{template_id}/push")
def push_template(template_id: str, body: PushIn, request: Request, user: User = Depends(get_current_user),
                  db: DbSession = Depends(get_db)):
    """Vorlage auf Firewalls ausrollen: je Firewall ein Antrag (Sammelantrag) – Vier-Augen-Freigabe wie immer."""
    t = _template_or_404(db, template_id)
    if body.version != t.version:
        raise HTTPException(409, tr('Die Vorlage wurde inzwischen geändert (Version {0}) – bitte die Vorschau neu laden', t.version))
    result = template_plan.push(db, user, t, _targets(db, user, body.firewall_ids), title=body.title,
                                justification=body.justification, ticket_ref=body.ticket_ref,
                                deploy_after=body.deploy_after, expires_at=body.expires_at, ip=client_ip(request))
    audit(db, "template.pushed", actor=user, target_type="template", target_id=t.id, ip=client_ip(request),
          details={"name": t.name, "version": t.version, "changes": [c["number"] for c in result["changes"]],
                   "unchanged": result["unchanged"]})
    return result


class DependenciesIn(BaseModel):
    firewall_id: str
    items: list[dict] = Field(max_length=2000)


@router.post("/templates/dependencies")
def dependencies(body: DependenciesIn, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    """Objekte, auf die die gewählten Einträge (rekursiv) verweisen – zum Mitnehmen in eine Vorlage."""
    fw = firewall_or_404(db, user, body.firewall_id)
    config = sync.cached_config(db, fw)
    idx = {e: {entities.oname(o): o for o in objs} for e, objs in config.items()}
    by_kind: dict[str, list[tuple[str, dict]]] = {}
    for e, objs in idx.items():
        kind = entities.kind_of(e)
        if kind:
            for n, o in objs.items():
                by_kind.setdefault(kind, []).append((e, n))
    todo = [(i["entity"], i["name"]) for i in body.items]
    seen = set(todo)
    found = []
    while todo:
        e, n = todo.pop()
        obj = idx.get(e, {}).get(n)
        if obj is None:
            continue
        for kind, ref in entities.references(e, obj):
            if ref in entities.BUILTIN_REFS:
                continue
            for te, tn in by_kind.get(kind, []):
                if tn == ref and (te, tn) not in seen and not idx[te][tn].get("isInternal") \
                        and te not in entities.REST_READ_ONLY_ENTITIES:
                    seen.add((te, tn))
                    todo.append((te, tn))
                    found.append({"entity": te, "name": tn, "label": entities.LABELS.get(te, te), "data": idx[te][tn]})
    return {"items": found}


@router.post("/firewalls/{firewall_id}/templates/{template_id}/apply")
def apply_template(firewall_id: str, template_id: str, user: User = Depends(get_current_user),
                   db: DbSession = Depends(get_db)):
    """Vorlage in den eigenen Entwurf dieser Firewall übernehmen (nur was fehlt oder abweicht)."""
    fw = firewall_or_404(db, user, firewall_id, "change.create")
    t = _template_or_404(db, template_id)
    if t.format != entities.fmt_for(fw.connector):
        raise HTTPException(400, tr('Die Vorlage passt nicht zum Format (REST/XML) dieser Firewall'))
    p = template_plan.plan(fw, sync.cached_config(db, fw), template_plan.normalize_items(t.operations))
    cr, warnings, skipped = None, [], list(p["errors"])
    for o in p["ops"]:
        try:
            cr, w = changes.draft_add(db, user, fw, dict(o))
            warnings = w
        except HTTPException as e:
            db.rollback()
            skipped.append(f"{tr(entities.LABELS.get(o['entity'], o['entity']))} „{o['name']}“: {e.detail}")
    if cr is None:
        if not p["ops"] and not p["errors"]:
            raise HTTPException(409, tr('Diese Firewall entspricht bereits der Vorlage'))
        raise HTTPException(409, tr('Keine Operation der Vorlage passt: ') + "; ".join(skipped))
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
        raise HTTPException(404, tr('Gruppe nicht gefunden'))
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
