"""Sicherungen der Firewall-Konfigurationen: Liste, jetzt sichern, Download, Anheften, Löschen, Wiederherstellen."""
import json
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .. import backups, changes, importer, permissions, settings, sync
from ..audit import audit
from ..db import get_db
from ..models import ConfigBackup, Firewall, User, utcnow
from ..permissions import firewall_or_404
from ..security import client_ip, get_current_user
from ..sophos import connector, entities, xmlconv
from ..i18n import tr

router = APIRouter(prefix="/api/firewalls/{firewall_id}/backups", tags=["backups"])


def _backup_or_404(db: DbSession, fw: Firewall, backup_id: str) -> ConfigBackup:
    b = db.get(ConfigBackup, backup_id)
    if not b or b.firewall_id != fw.id:
        raise HTTPException(404, tr('Sicherung nicht gefunden'))
    return b


def _out(db: DbSession, b: ConfigBackup, prev_hash: str | None) -> dict:
    creator = db.get(User, b.created_by) if b.created_by else None
    return {"id": b.id, "created_at": b.created_at, "trigger": b.trigger, "created_by": creator.username if creator else None,
            "format": b.format, "hash": b.hash[:12], "object_count": b.object_count, "size": b.size,
            "pinned": b.pinned, "note": b.note, "has_file": bool(b.file_path),
            # None = älteste Sicherung (kein Vorgänger zum Vergleich)
            "unchanged": None if prev_hash is None else prev_hash == b.hash}


def schedule_info(db: DbSession) -> dict:
    s = settings.get_all(db)
    info = {k.removeprefix("backup_"): v for k, v in s.items() if k.startswith("backup_")}
    info["next_run"] = backups.next_slot(s, utcnow()) if s["backup_enabled"] else None
    return info


@router.get("")
def list_backups(firewall_id: str, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id)
    rows = db.execute(select(ConfigBackup).where(ConfigBackup.firewall_id == fw.id)
                      .order_by(ConfigBackup.created_at.desc())).scalars().all()
    items = [_out(db, b, rows[i + 1].hash if i + 1 < len(rows) else None) for i, b in enumerate(rows)]
    sfos = None
    if fw.connector == "rest":
        cached = sync.cached_config(db, fw).get("backupSettings") or []
        sfos = cached[0] if cached else None
    return {"schedule": schedule_info(db), "items": items, "sfos": sfos,
            "may_backup": permissions.can(db, user, "firewall.manage", fw),
            "may_restore": permissions.can(db, user, "change.create", fw),
            "may_delete": user.is_superadmin}


class BackupIn(BaseModel):
    note: str = Field(default="", max_length=300)


@router.post("")
def backup_now(firewall_id: str, body: BackupIn, request: Request, user: User = Depends(get_current_user),
               db: DbSession = Depends(get_db)):
    """Sofort sichern (liest die Konfiguration live – auf der Firewall wird nichts geändert)."""
    fw = firewall_or_404(db, user, firewall_id, "firewall.manage")
    try:
        b = backups.create(db, fw, trigger="manual", actor=user, note=body.note)
    except connector.ConnectorError as e:
        audit(db, "backup.failed", actor=user, target_type="firewall", target_id=fw.id, ip=client_ip(request),
              details={"firewall": fw.name, "error": str(e)})
        raise HTTPException(502, tr('Sicherung fehlgeschlagen: {0}', e))
    return _out(db, b, None)


class BackupPatch(BaseModel):
    pinned: bool | None = None
    note: str | None = Field(default=None, max_length=300)


@router.patch("/{backup_id}")
def update_backup(firewall_id: str, backup_id: str, body: BackupPatch, request: Request,
                  user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id, "firewall.manage")
    b = _backup_or_404(db, fw, backup_id)
    if body.pinned is not None:
        b.pinned = body.pinned
    if body.note is not None:
        b.note = body.note.strip()
    audit(db, "backup.updated", actor=user, target_type="firewall", target_id=fw.id, ip=client_ip(request),
          details={"firewall": fw.name, "backup_id": b.id, "pinned": b.pinned, "note": b.note})
    if body.pinned is False:
        backups.apply_retention(db, fw)
        db.commit()
    return {"ok": True}


@router.delete("/{backup_id}")
def delete_backup(firewall_id: str, backup_id: str, request: Request,
                  user: User = Depends(permissions.require_superadmin), db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id)
    b = _backup_or_404(db, fw, backup_id)
    backups.remove_file(b)
    details = {"firewall": fw.name, "backup_id": b.id, "created_at": b.created_at.isoformat(), "trigger": b.trigger}
    db.delete(b)
    audit(db, "backup.deleted", actor=user, target_type="firewall", target_id=fw.id, ip=client_ip(request),
          details=details)
    return {"ok": True}


@router.get("/{backup_id}/download")
def download_backup(firewall_id: str, backup_id: str, request: Request, format: str = "json",
                    user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id)
    b = _backup_or_404(db, fw, backup_id)
    doc = backups.unpack(b)
    stamp = b.created_at.astimezone(backups._tz()).strftime("%Y-%m-%d_%H%M")
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", fw.name)
    audit(db, "backup.downloaded", actor=user, target_type="firewall", target_id=fw.id, ip=client_ip(request),
          details={"firewall": fw.name, "backup_id": b.id, "format": format})
    if format == "xml":
        if b.format == "rest":
            raise HTTPException(400, tr('Entities.xml gibt es nur für Sicherungen im XML-Format'))
        objs = [(e, o) for e in entities.NAMES for o in doc["config"].get(e, [])]
        return Response(xmlconv.build_entities_xml(objs, fw.api_version), media_type="application/xml",
                        headers={"Content-Disposition": f'attachment; filename="Entities_{base}_{stamp}.xml"'})
    return Response(json.dumps(doc, indent=2, ensure_ascii=False), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="Sicherung_{base}_{stamp}.json"'})


@router.post("/{backup_id}/restore/review")
def restore_review(firewall_id: str, backup_id: str, user: User = Depends(get_current_user),
                   db: DbSession = Depends(get_db)):
    """Sicherung mit dem aktuellen Stand vergleichen – Auswahl wie bei der Import-Prüfung, nichts wird geändert."""
    fw = firewall_or_404(db, user, firewall_id, "change.create")
    b = _backup_or_404(db, fw, backup_id)
    if b.format != entities.fmt_for(fw.connector):
        raise HTTPException(409, tr('Die Sicherung stammt aus einer anderen Anbindung (REST/XML) und passt nicht zum aktuellen Format'))
    items = backups.restore_review(sync.cached_config(db, fw), backups.config_of(b), b.format)
    token = importer.store(user.id, fw.id, items)
    counts = {s: sum(1 for i in items if i["status"] == s) for s in ("new", "changed", "removed")}
    return {"token": token, "counts": counts, "created_at": b.created_at,
            "items": [{k: v for k, v in i.items() if k != "data"} | {"key": str(n)} for n, i in enumerate(items)]}


class RestoreIn(BaseModel):
    token: str
    keys: list[str] = Field(max_length=10000)


@router.post("/{backup_id}/restore/apply")
def restore_apply(firewall_id: str, backup_id: str, body: RestoreIn, request: Request,
                  user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    """Ausgewählte Unterschiede in den eigenen Entwurf übernehmen – ausgerollt wird erst nach Freigabe."""
    from ..serializers import change_out
    fw = firewall_or_404(db, user, firewall_id, "change.create")
    b = _backup_or_404(db, fw, backup_id)
    items = importer.load(body.token, user.id, fw.id)
    ops = backups.restore_operations(items, set(body.keys), backups.config_of(b), sync.cached_config(db, fw))
    added, skipped, draft = 0, [], None
    for op in ops:
        try:
            draft, _ = changes.draft_add(db, user, fw, op)
            added += 1
        except HTTPException as e:
            db.rollback()
            skipped.append(f"{tr(entities.LABELS.get(op['entity'], op['entity']))} „{op['name']}“: {e.detail}")
    if draft is None:
        draft = changes.get_draft(db, user, fw)
    audit(db, "backup.restore_to_draft", actor=user, target_type="firewall", target_id=fw.id, ip=client_ip(request),
          details={"firewall": fw.name, "backup_id": b.id, "added": added, "skipped": len(skipped)})
    return {"added": added, "skipped": skipped, "draft": change_out(db, draft, user) if draft else None}
