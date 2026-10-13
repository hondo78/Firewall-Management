"""Migrationsassistent: Konfigurationen anderer Hersteller übernehmen – als Entwurf, Vorlage oder Entities.xml."""
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .. import importer, permissions, sync, template_plan
from ..audit import audit
from ..db import get_db
from ..i18n import tr
from ..migration import service
from ..models import ChangeTemplate, User
from ..permissions import firewall_or_404
from ..security import client_ip, get_current_user
from ..sophos import entities, xmlconv

router = APIRouter(prefix="/api/migration", tags=["migration"])


def _may_migrate(db: DbSession, user: User) -> None:
    if not permissions.can_anywhere(db, user, "change.create"):
        raise HTTPException(403, tr('Keine Berechtigung'))


@router.get("/vendors")
def list_vendors(user: User = Depends(get_current_user)):
    out = service.vendors()
    for v in out:
        v["hint"] = tr(v["hint"])
        for row in v["matrix"]:
            row["feature"] = tr(row["feature"])
    return out


@router.post("/parse")
async def parse(request: Request, vendor: str = Form(...), file: UploadFile = File(...),
                user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    """Datei einlesen und Bericht erstellen – nichts wird gespeichert oder an eine Firewall gesendet."""
    _may_migrate(db, user)
    result = service.start(user.id, vendor, file.filename or "", await file.read(importer.MAX_BYTES + 1))
    audit(db, "migration.parsed", actor=user, target_type="migration", ip=client_ip(request),
          details={"vendor": vendor, "file": file.filename, "counts": result["counts"]})
    return result


class BuildIn(BaseModel):
    token: str
    zone_map: dict[str, str] = Field(default_factory=dict)
    prefix: str = Field(default="", max_length=20)


def _build(body: BuildIn, user: User):
    import re
    if body.prefix and not re.fullmatch(r"[A-Za-z0-9_.-]{1,20}", body.prefix):
        raise HTTPException(400, tr('Präfix: nur Buchstaben, Ziffern, _ . - (höchstens 20 Zeichen)'))
    s = service.load(body.token, user.id)
    parsed, notes = service.build(s, body.zone_map, body.prefix)
    return s, parsed, notes


def _counts(parsed: dict) -> dict:
    return {e: len(objs) for e, objs in parsed.items()}


@router.post("/preview")
def preview(body: BuildIn, user: User = Depends(get_current_user)):
    """Ergebnis der Umwandlung: Sophos-Objekte je Typ und Hinweise je Objekt (Aktion nötig / prüfen)."""
    _, parsed, notes = _build(body, user)
    return {"counts": _counts(parsed), "notes": notes,
            "rules": [{"name": r["Name"], "enabled": r.get("Status") != "Disable",
                       "action": (r.get("NetworkPolicy") or {}).get("Action"),
                       "src_zones": ((r.get("NetworkPolicy") or {}).get("SourceZones") or {}).get("Zone", []),
                       "dst_zones": ((r.get("NetworkPolicy") or {}).get("DestinationZones") or {}).get("Zone", [])}
                      for r in parsed.get("FirewallRule", [])]}


class DraftIn(BuildIn):
    firewall_id: str


@router.post("/to-draft")
def to_draft(body: DraftIn, request: Request, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    """Wie „Import prüfen“: Vergleich mit der Ziel-Firewall; Auswahl und Übernahme über /firewalls/{id}/import/apply."""
    fw = firewall_or_404(db, user, body.firewall_id, "change.create")
    if not fw.last_sync_at:
        raise HTTPException(409, tr('„{0}“ wurde noch nie synchronisiert', fw.name))
    s, parsed, notes = _build(body, user)
    items = importer.review(sync.cached_config(db, fw), entities.fmt_for(fw.connector), parsed)
    token = importer.store(user.id, fw.id, items)
    counts = {st: sum(1 for i in items if i["status"] == st) for st in ("new", "changed", "same", "unsupported")}
    audit(db, "migration.to_draft_review", actor=user, target_type="firewall", target_id=fw.id, ip=client_ip(request),
          details={"vendor": s["vendor"], "file": s["filename"], "firewall": fw.name, "counts": counts})
    return {"token": token, "counts": counts, "notes": notes, "api_version": "",
            "items": [{k: v for k, v in i.items() if k != "data"} | {"key": str(n)} for n, i in enumerate(items)]}


class TemplateIn(BuildIn):
    name: str = Field(min_length=1, max_length=200)
    format: str = "rest"
    reference_firewall_id: str | None = None


@router.post("/to-template")
def to_template(body: TemplateIn, request: Request, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    """Als Vorlage (Soll-Zustand) speichern – ausrollbar auf beliebige Firewalls, immer über einen Antrag."""
    _may_migrate(db, user)
    if body.format not in ("rest", "xml"):
        raise HTTPException(400, tr('Format muss rest oder xml sein'))
    name = body.name.strip()
    if db.execute(select(ChangeTemplate).where(ChangeTemplate.name == name)).scalar():
        raise HTTPException(409, tr('Eine Vorlage mit diesem Namen existiert bereits'))
    s, parsed, notes = _build(body, user)
    config = {}
    if body.reference_firewall_id:
        config = sync.cached_config(db, firewall_or_404(db, user, body.reference_firewall_id))
    items, skipped = service.template_items(parsed, body.format, config)
    if not items:
        raise HTTPException(400, tr('Keine übertragbaren Objekte'))
    template_plan.validate_items(body.format, items)
    t = ChangeTemplate(name=name, format=body.format, operations=items, created_by=user.id,
                       description=tr('Migration aus {0} ({1})', service.BY_ID[s["vendor"]]["title"], s["filename"]))
    db.add(t)
    db.flush()
    audit(db, "template.created", actor=user, target_type="template", target_id=t.id, ip=client_ip(request),
          details={"name": t.name, "format": t.format, "items": len(items), "from_migration": s["vendor"],
                   "file": s["filename"], "skipped": len(skipped)})
    return {"id": t.id, "name": t.name, "items": len(items), "skipped": skipped, "notes": notes}


@router.post("/download")
def download(body: BuildIn, request: Request, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    """Entities.xml wie im Config Studio – zum Import auf einer (neuen) Sophos Firewall."""
    _may_migrate(db, user)
    s, parsed, _ = _build(body, user)
    rank = {e: n for n, e in enumerate(entities.WRITE_ORDER)}
    objs = [(e, o) for e in sorted(parsed, key=lambda x: rank.get(x, 100)) for o in parsed[e]]
    audit(db, "migration.downloaded", actor=user, target_type="migration", ip=client_ip(request),
          details={"vendor": s["vendor"], "file": s["filename"], "objects": len(objs)})
    return Response(xmlconv.build_entities_xml(objs, ""), media_type="application/xml",
                    headers={"Content-Disposition": 'attachment; filename="Entities.xml"'})
