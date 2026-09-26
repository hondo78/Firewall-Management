"""Firewalls, Firewall-Gruppen, Konfigurationsansicht, Versionsstände/Vergleich und Firmware."""
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from datetime import date, datetime, time, timezone

from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from .. import changes, crypto, diagnose, diff, permissions, sync
from ..audit import audit
from ..db import get_db
from ..models import (CentralAccount, ChangeRequest, ConfigObject, ConfigSnapshot, Firewall, FirewallGroup, User,
                      new_id)
from ..permissions import firewall_or_404
from ..security import client_ip, get_current_user
from ..serializers import change_summary, firewall_out, group_out
from ..sophos import connector, entities, restapi, xmlapi, xmlconv
from ..sophos.central import CentralError
from ..i18n import tr

router = APIRouter(prefix="/api", tags=["firewalls"])


# --- Gruppen -------------------------------------------------------------------------------------------------

class GroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""


@router.get("/groups")
def list_groups(user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    groups = db.execute(select(FirewallGroup).order_by(FirewallGroup.name)).scalars().all()
    visible = permissions.visible_group_ids(db, user)
    # Admins sehen alle Gruppen (für Rollenzuweisungen)
    if visible is not None and not permissions.has_global(db, user, "admin"):
        groups = [g for g in groups if g.id in visible]
    return [group_out(g) for g in groups]


@router.post("/groups")
def create_group(body: GroupIn, request: Request, user: User = Depends(permissions.require_global("firewall.manage")),
                 db: DbSession = Depends(get_db)):
    g = FirewallGroup(name=body.name.strip(), description=body.description)
    db.add(g)
    db.flush()
    audit(db, "group.created", actor=user, target_type="group", target_id=g.id, ip=client_ip(request),
          details={"name": g.name})
    return group_out(g)


@router.put("/groups/{group_id}")
def update_group(group_id: str, body: GroupIn, request: Request,
                 user: User = Depends(permissions.require_global("firewall.manage")), db: DbSession = Depends(get_db)):
    g = db.get(FirewallGroup, group_id)
    if not g:
        raise HTTPException(404, tr('Gruppe nicht gefunden'))
    if g.central_id and body.name.strip() != g.name:
        raise HTTPException(409, tr('Gruppen aus Sophos Central werden dort umbenannt'))
    g.name, g.description = body.name.strip(), body.description
    audit(db, "group.updated", actor=user, target_type="group", target_id=g.id, ip=client_ip(request),
          details={"name": g.name})
    return group_out(g)


@router.delete("/groups/{group_id}")
def delete_group(group_id: str, request: Request, user: User = Depends(permissions.require_global("firewall.manage")),
                 db: DbSession = Depends(get_db)):
    g = db.get(FirewallGroup, group_id)
    if not g:
        raise HTTPException(404, tr('Gruppe nicht gefunden'))
    db.delete(g)
    audit(db, "group.deleted", actor=user, target_type="group", target_id=group_id, ip=client_ip(request),
          details={"name": g.name})
    return {"ok": True}


# --- Firewalls -----------------------------------------------------------------------------------------------

class FirewallIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    group_id: str | None = None
    connector: str = "rest"
    api_url: str = ""
    api_username: str = ""
    # XML-API: Passwort · REST-API: API-Key (beides verschlüsselt im selben Feld)
    api_password: str | None = None
    api_key_expires_at: date | None = None
    verify_tls: bool = True
    central_account_id: str | None = None
    central_id: str = ""
    # REST: optionaler XML-API-Zugang für WAF-Regeln (None = unverändert, "" = entfernen)
    xml_username: str | None = None
    xml_password: str | None = None


CONNECTION_FIELDS = frozenset(("connector", "api_url", "api_username", "api_password", "api_key_expires_at", "verify_tls",
                     "central_account_id", "central_id", "xml_username", "xml_password"))


def _require_superadmin(user: User) -> None:
    if not user.is_superadmin:
        raise HTTPException(403, tr('Verbindungseinstellungen einer Firewall darf nur ein Superadmin sehen und ändern'))


def _keep_connection(fw: Firewall, body: FirewallIn) -> FirewallIn:
    """Für Nicht-Superadmins: Verbindungsfelder unverändert übernehmen; ein Änderungsversuch wird abgelehnt."""
    current = {"connector": fw.connector, "api_url": fw.api_url, "api_username": fw.api_username, "api_password": None,
               "api_key_expires_at": fw.api_key_expires_at.date() if fw.api_key_expires_at else None,
               "verify_tls": fw.verify_tls, "central_account_id": None, "central_id": fw.central_id,
               "xml_username": None, "xml_password": None}
    for k in CONNECTION_FIELDS & body.model_fields_set:
        v = getattr(body, k)
        if k in ("api_password", "central_account_id", "xml_password", "xml_username") and v is None:
            continue
        if k in ("api_password", "central_account_id", "xml_password") and not v:
            continue
        if k == "xml_username" and v.strip() == (fw.xml_username or ""):
            continue
        if isinstance(v, str):
            v = v.strip()
        if v != current[k]:
            raise HTTPException(403, tr('Verbindungseinstellungen einer Firewall darf nur ein Superadmin ändern'))
    return body.model_copy(update=current)


def _visible_firewalls(db: DbSession, user: User) -> list[Firewall]:
    fws = db.execute(select(Firewall).where(Firewall.archived.is_(False)).order_by(Firewall.name)).scalars().all()
    return [f for f in fws if permissions.can(db, user, "firewall.view", f)]


@router.get("/firewalls")
def list_firewalls(user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    fws = _visible_firewalls(db, user)
    open_counts: dict[str, int] = {}
    for fid, in db.execute(select(ChangeRequest.firewall_id).where(ChangeRequest.status.in_(("pending", "approved")))):
        open_counts[fid] = open_counts.get(fid, 0) + 1
    out = []
    for f in fws:
        item = firewall_out(db, f, user)
        item["open_changes"] = open_counts.get(f.id, 0)
        out.append(item)
    return out


def _check_manage_target(db: DbSession, user: User, group_id: str | None) -> None:
    """Anlegen/Verschieben nur in Gruppen, für die der Benutzer firewall.manage hat."""
    probe = Firewall(group_id=group_id)
    if not permissions.can(db, user, "firewall.manage", probe):
        raise HTTPException(403, tr('Keine Berechtigung, Firewalls in dieser Gruppe zu verwalten'))


def _apply_fw(db: DbSession, fw: Firewall, body: FirewallIn) -> None:
    if body.connector not in ("rest", "xmlapi", "central"):
        raise HTTPException(400, tr('Connector muss rest, xmlapi oder central sein'))
    if body.group_id and not db.get(FirewallGroup, body.group_id):
        raise HTTPException(400, tr('Unbekannte Gruppe'))
    old_fmt = entities.fmt_for(fw.connector) if fw.connector else None
    new_fmt = entities.fmt_for(body.connector)
    if fw.last_sync_at and old_fmt and old_fmt != new_fmt:
        # REST- und XML-Format sind nicht kompatibel: Cache neu aufbauen, offene Anträge blockieren den Wechsel
        if db.execute(select(ChangeRequest.id).where(
                ChangeRequest.firewall_id == fw.id,
                ChangeRequest.status.in_(("pending", "approved", "deploying")))).first():
            raise HTTPException(409, tr('Wechsel zwischen REST- und XML-Anbindung erst, wenn keine Anträge mehr offen sind'))
        for cr in db.execute(select(ChangeRequest).where(ChangeRequest.firewall_id == fw.id,
                                                         ChangeRequest.status == "draft")).scalars():
            cr.status = "withdrawn"
        db.execute(delete(ConfigObject).where(ConfigObject.firewall_id == fw.id))
        fw.config_hash, fw.last_sync_at = "", None
    fw.name, fw.group_id, fw.connector = body.name.strip(), body.group_id, body.connector
    fw.api_url, fw.api_username, fw.verify_tls = body.api_url.strip(), body.api_username.strip(), body.verify_tls
    if body.api_password is not None and body.api_password != "":
        sync.encrypt_firewall_password(fw, body.api_password.strip())
    if body.connector == "rest" and body.xml_username is not None:
        fw.xml_username = body.xml_username.strip()
        if not fw.xml_username:
            fw.xml_password_enc, fw.xml_status = "", ""
    if body.connector == "rest" and body.xml_password:
        fw.xml_password_enc = crypto.encrypt(body.xml_password, f"firewall-xml:{fw.id}")
    if body.connector != "rest":
        fw.xml_username, fw.xml_password_enc, fw.xml_status = "", "", ""
    if body.connector == "rest" and fw.xml_username and not fw.xml_password_enc:
        raise HTTPException(400, tr('Für den XML-API-Zugang (WAF-Regeln) fehlt das Passwort'))
    if body.connector == "rest":
        fw.api_key_expires_at = (datetime.combine(body.api_key_expires_at, time(23, 59), tzinfo=timezone.utc)
                                 if body.api_key_expires_at else None)
    if body.central_account_id is not None:
        if body.central_account_id and not db.get(CentralAccount, body.central_account_id):
            raise HTTPException(400, tr('Unbekanntes Central-Konto'))
        fw.central_account_id = body.central_account_id or None
        fw.central_id = body.central_id or fw.central_id
    if fw.connector == "rest":
        if not fw.api_url or not fw.api_password_enc:
            raise HTTPException(400, tr('Für die REST-API sind Adresse und API-Key nötig'))
        try:
            restapi.normalize_base_url(fw.api_url)
        except restapi.RestApiError as e:
            raise HTTPException(400, str(e))
    if fw.connector == "xmlapi":
        if not fw.api_url or not fw.api_username or not fw.api_password_enc:
            raise HTTPException(400, tr('Für die XML-API sind Adresse, Benutzer und Passwort nötig'))
        try:
            xmlapi.normalize_base_url(fw.api_url)
        except xmlapi.XmlApiError as e:
            raise HTTPException(400, str(e))
    if fw.connector == "central" and not (fw.central_account_id and fw.central_id):
        raise HTTPException(400, tr('Central-Connector nur für aus Sophos Central übernommene Firewalls'))


@router.post("/firewalls")
def create_firewall(body: FirewallIn, request: Request, user: User = Depends(get_current_user),
                    db: DbSession = Depends(get_db)):
    _require_superadmin(user)  # Anlegen heißt Verbindung einrichten
    _check_manage_target(db, user, body.group_id)
    fw = Firewall(id=new_id())
    _apply_fw(db, fw, body)
    db.add(fw)
    audit(db, "firewall.created", actor=user, target_type="firewall", target_id=fw.id, ip=client_ip(request),
          details={"name": fw.name, "connector": fw.connector, "api_url": fw.api_url})
    return firewall_out(db, fw, user)


@router.get("/firewalls/{firewall_id}")
def get_firewall(firewall_id: str, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id)
    return firewall_out(db, fw, user)


@router.put("/firewalls/{firewall_id}")
def update_firewall(firewall_id: str, body: FirewallIn, request: Request, user: User = Depends(get_current_user),
                    db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id, "firewall.manage")
    if body.group_id != fw.group_id:
        _check_manage_target(db, user, body.group_id)
    before = {"name": fw.name, "group_id": fw.group_id, "connector": fw.connector, "api_url": fw.api_url,
              "api_username": fw.api_username, "verify_tls": fw.verify_tls}
    if not user.is_superadmin:
        body = _keep_connection(fw, body)
    _apply_fw(db, fw, body)
    audit(db, "firewall.updated", actor=user, target_type="firewall", target_id=fw.id, ip=client_ip(request),
          details={"before": before, "after": {"name": fw.name, "group_id": fw.group_id, "connector": fw.connector,
                                               "api_url": fw.api_url, "api_username": fw.api_username,
                                               "verify_tls": fw.verify_tls},
                   "secret_changed": bool(body.api_password), "xml_access": bool(fw.xml_username),
                   "xml_secret_changed": bool(body.xml_password)})
    return firewall_out(db, fw, user)


@router.delete("/firewalls/{firewall_id}")
def delete_firewall(firewall_id: str, request: Request, user: User = Depends(get_current_user),
                    db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id, "firewall.manage")
    if db.execute(select(ChangeRequest.id).where(ChangeRequest.firewall_id == fw.id,
                                                 ChangeRequest.status.in_(("pending", "approved", "deploying")))).first():
        raise HTTPException(409, tr('Es gibt noch offene Anträge für diese Firewall'))
    # Nur aus der Verwaltung entfernen – auf der Firewall bzw. in Central ändert sich nichts.
    # Archivieren statt löschen: Anträge, Verlauf und Versionsstände bleiben nachvollziehbar.
    fw.archived = True
    fw.api_password_enc = ""
    fw.xml_password_enc = ""
    db.execute(delete(ConfigObject).where(ConfigObject.firewall_id == fw.id))
    draft = db.execute(select(ChangeRequest).where(ChangeRequest.firewall_id == fw.id,
                                                   ChangeRequest.status == "draft")).scalars().all()
    for cr in draft:
        cr.status = "withdrawn"
    audit(db, "firewall.removed", actor=user, target_type="firewall", target_id=firewall_id, ip=client_ip(request),
          details={"name": fw.name, "serial": fw.serial})
    return {"ok": True}


@router.post("/firewalls/{firewall_id}/test")
def test_firewall(firewall_id: str, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id, "firewall.manage")
    _require_superadmin(user)
    try:
        return {"ok": True, "message": connector.test_connection(db, fw)}
    except connector.ConnectorError as e:
        return {"ok": False, "message": str(e)}


@router.post("/firewalls/{firewall_id}/sync")
def sync_now(firewall_id: str, request: Request, user: User = Depends(get_current_user),
             db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id, "firewall.view")
    try:
        result = sync.sync_firewall(db, fw, actor=user)
    except connector.ConnectorError as e:
        raise HTTPException(502, tr('Synchronisation fehlgeschlagen: {0}', e))
    audit(db, "firewall.synced", actor=user, target_type="firewall", target_id=fw.id, ip=client_ip(request),
          details={"firewall": fw.name, "changed": result["changed"]})
    return result


# --- Konfiguration -------------------------------------------------------------------------------------------

def _pending_ops(db: DbSession, fw: Firewall, user: User) -> dict[tuple[str, str], list[dict]]:
    """Geplante Änderungen je Objekt (offene/genehmigte Anträge + eigener Entwurf)."""
    rows = db.execute(select(ChangeRequest).where(
        ChangeRequest.firewall_id == fw.id, ChangeRequest.status.in_(("pending", "approved", "deploying", "draft")))
    ).scalars().all()
    out: dict[tuple[str, str], list[dict]] = {}
    for cr in rows:
        if cr.status == "draft" and cr.created_by != user.id:
            continue
        for o in cr.operations or []:
            out.setdefault((o["entity"], o["name"]), []).append(
                {"change_id": cr.id, "number": cr.number, "status": cr.status, "action": o["action"]})
    return out


@router.get("/firewalls/{firewall_id}/config")
def get_config(firewall_id: str, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id)
    config = sync.cached_config(db, fw)
    pending = _pending_ops(db, fw, user)
    draft = changes.get_draft(db, user, fw)
    draft_ops = draft.operations if draft else []
    preview = changes.effective_config(config, draft_ops) if draft_ops else config
    fmt = entities.fmt_for(fw.connector)
    return {
        "format": fmt,
        "entities": [{"entity": e, "label": label, "section": section, "count": len(config.get(e, []))}
                     for e, label, section in entities.managed(fmt)],
        "objects": config,
        # Konfiguration inkl. eigenem Entwurf (Vorschau wie im Config-Studio-Editor)
        "preview": preview,
        "pending": [{"entity": e, "name": n, "changes": v} for (e, n), v in pending.items()],
        "last_sync_at": fw.last_sync_at, "last_sync_error": fw.last_sync_error,
    }


@router.get("/firewalls/{firewall_id}/objects/{entity}/{name}/xml")
def object_xml(firewall_id: str, entity: str, name: str, user: User = Depends(get_current_user),
               db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id)
    obj = next((o for o in sync.cached_config(db, fw).get(entity, []) if entities.oname(o) == name), None)
    if obj is None:
        raise HTTPException(404, tr('Objekt nicht gefunden'))
    used = changes.used_by(sync.cached_config(db, fw), entity, name)
    if entity in entities.REST_RESOURCES:
        import json
        return {"format": "json", "xml": json.dumps(obj, indent=2, ensure_ascii=False), "used_by": used}
    return {"format": "xml", "xml": xmlconv.to_xml(entity, obj), "used_by": used}


class XmlParseIn(BaseModel):
    entity: str
    xml: str


@router.post("/xml/parse")
def parse_xml(body: XmlParseIn, _: User = Depends(get_current_user)):
    """Roh-XML (Experten-Editor) in Objektdaten umwandeln."""
    import xml.etree.ElementTree as ET
    try:
        el = ET.fromstring(body.xml.strip())
    except ET.ParseError as e:
        raise HTTPException(400, tr('XML ungültig: {0}', e))
    if el.tag != body.entity:
        raise HTTPException(400, tr('Wurzelelement muss <{0}> sein', body.entity))
    data = xmlconv.element_to_value(el)
    if not isinstance(data, dict) or not data.get("Name"):
        raise HTTPException(400, tr('Objekt benötigt ein <Name>-Element'))
    return {"data": xmlconv.strip_position(data)}


@router.get("/firewalls/{firewall_id}/export.xml")
def export_xml(firewall_id: str, request: Request, user: User = Depends(get_current_user),
               db: DbSession = Depends(get_db)):
    """Zwischengespeicherte Konfiguration als Entities.xml (z. B. zum Öffnen im Sophos Config Studio)."""
    from fastapi.responses import Response
    fw = firewall_or_404(db, user, firewall_id)
    if entities.fmt_for(fw.connector) == "rest":
        raise HTTPException(400, tr('Entities.xml gibt es nur für XML-/Central-Anbindung – REST: JSON-Export nutzen'))
    config = sync.cached_config(db, fw)
    objs = [(e, o) for e in entities.NAMES for o in config.get(e, [])]
    audit(db, "config.exported", actor=user, target_type="firewall", target_id=fw.id, ip=client_ip(request),
          details={"firewall": fw.name, "objects": len(objs)})
    return Response(xmlconv.build_entities_xml(objs, fw.api_version), media_type="application/xml",
                    headers={"Content-Disposition": f'attachment; filename="Entities.xml"'})


# --- Versionsstände & Vergleich ------------------------------------------------------------------------------

@router.get("/firewalls/{firewall_id}/snapshots")
def list_snapshots(firewall_id: str, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id)
    rows = db.execute(select(ConfigSnapshot.id, ConfigSnapshot.created_at, ConfigSnapshot.reason,
                             ConfigSnapshot.change_id, ConfigSnapshot.summary, ConfigSnapshot.hash)
                      .where(ConfigSnapshot.firewall_id == fw.id)
                      .order_by(ConfigSnapshot.created_at.desc())).all()
    numbers = dict(db.execute(select(ChangeRequest.id, ChangeRequest.number)
                              .where(ChangeRequest.firewall_id == fw.id)).all())
    return [{"id": r.id, "created_at": r.created_at, "reason": r.reason, "change_id": r.change_id,
             "change_number": numbers.get(r.change_id), "summary": r.summary, "hash": r.hash[:12]} for r in rows]


def _snapshot_data(db: DbSession, fw: Firewall, ref: str) -> dict:
    if ref == "current":
        return sync.cached_config(db, fw)
    if ref.startswith("backup:"):
        from .. import backups
        from ..models import ConfigBackup
        b = db.get(ConfigBackup, ref.removeprefix("backup:"))
        if not b or b.firewall_id != fw.id:
            raise HTTPException(404, tr('Sicherung nicht gefunden'))
        return backups.config_of(b)
    snap = db.get(ConfigSnapshot, ref)
    if not snap or snap.firewall_id != fw.id:
        raise HTTPException(404, tr('Versionsstand nicht gefunden'))
    return snap.data


@router.get("/firewalls/{firewall_id}/compare")
def compare(firewall_id: str, a: str, b: str = "current", other_firewall: str | None = None,
            user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    """Vergleich zweier Stände einer Firewall – oder (other_firewall) mit dem aktuellen Stand einer anderen."""
    fw = firewall_or_404(db, user, firewall_id)
    old = _snapshot_data(db, fw, a)
    if other_firewall:
        other = firewall_or_404(db, user, other_firewall)
        new = sync.cached_config(db, other)
    else:
        new = _snapshot_data(db, fw, b)
    result = diff.compare_configs(old, new)
    return {"entities": [{"entity": e, "label": entities.LABELS.get(e, e), **c} for e, c in result.items()],
            "totals": {k: sum(len(c[k]) for c in result.values()) for k in ("added", "removed", "modified")}}


# --- Firmware (nur Sophos Central) ---------------------------------------------------------------------------

class FirmwareIn(BaseModel):
    version: str
    upgrade_at: str | None = None


def _central_fw(db: DbSession, fw: Firewall):
    acc = db.get(CentralAccount, fw.central_account_id) if fw.central_account_id else None
    if not acc or not fw.central_id:
        raise HTTPException(400, tr('Firmware-Verwaltung nur für Firewalls aus Sophos Central'))
    return connector.central_client(acc)


@router.get("/firewalls/{firewall_id}/firmware")
def firmware_check(firewall_id: str, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id)
    try:
        res = _central_fw(db, fw).firmware_check([fw.central_id])
    except CentralError as e:
        raise HTTPException(502, str(e))
    mine = next((f for f in res.get("firewalls", []) if f.get("id") == fw.central_id), {})
    versions = {v["version"]: v for v in res.get("firmwareVersions", [])}
    return {"current": mine.get("firmwareVersion") or fw.firmware,
            "available": [versions.get(v, {"version": v}) for v in mine.get("upgradeToVersion", [])]}


@router.post("/firewalls/{firewall_id}/firmware")
def firmware_upgrade(firewall_id: str, body: FirmwareIn, request: Request, user: User = Depends(get_current_user),
                     db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id, "firmware.manage")
    item = {"id": fw.central_id, "upgradeToVersion": body.version}
    if body.upgrade_at:
        item["upgradeAt"] = body.upgrade_at
    try:
        res = _central_fw(db, fw).firmware_upgrade([item])
    except CentralError as e:
        audit(db, "firmware.upgrade_failed", actor=user, target_type="firewall", target_id=fw.id,
              ip=client_ip(request), details={"firewall": fw.name, "version": body.version, "error": str(e)})
        raise HTTPException(502, str(e))
    audit(db, "firmware.upgrade_scheduled", actor=user, target_type="firewall", target_id=fw.id,
          ip=client_ip(request), details={"firewall": fw.name, "from": fw.firmware, "version": body.version,
                                          "upgrade_at": body.upgrade_at, "result": res.get("firewalls")})
    return res


@router.delete("/firewalls/{firewall_id}/firmware")
def firmware_cancel(firewall_id: str, request: Request, user: User = Depends(get_current_user),
                    db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id, "firmware.manage")
    try:
        res = _central_fw(db, fw).firmware_cancel([fw.central_id])
    except CentralError as e:
        raise HTTPException(502, str(e))
    audit(db, "firmware.upgrade_cancelled", actor=user, target_type="firewall", target_id=fw.id,
          ip=client_ip(request), details={"firewall": fw.name})
    return res


@router.get("/firewalls/{firewall_id}/changes")
def firewall_changes(firewall_id: str, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    fw = firewall_or_404(db, user, firewall_id)
    rows = db.execute(select(ChangeRequest).where(ChangeRequest.firewall_id == fw.id, ChangeRequest.status != "draft")
                      .order_by(ChangeRequest.number.desc()).limit(100)).scalars().all()
    return [change_summary(cr) for cr in rows]


@router.post("/firewalls/{firewall_id}/diagnose")
def diagnose_firewall(firewall_id: str, request: Request, user: User = Depends(get_current_user),
                      db: DbSession = Depends(get_db)):
    """Probelauf: prüft Anbindung und Rechte mit ausschließlich lesenden Aufrufen."""
    fw = firewall_or_404(db, user, firewall_id, "firewall.manage")
    _require_superadmin(user)
    result = diagnose.firewall(db, fw)
    audit(db, "firewall.diagnosed", actor=user, target_type="firewall", target_id=fw.id, ip=client_ip(request),
          details={"firewall": fw.name, "passed": result["passed"], "failed": result["failed"],
                   "failed_steps": [s["name"] for s in result["steps"] if s["ok"] is False]})
    return result


@router.get("/firewalls/{firewall_id}/central-info")
def central_info(firewall_id: str, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    """Lizenzen (Licensing API) und offene Alerts (Common API) einer Firewall aus Sophos Central."""
    fw = firewall_or_404(db, user, firewall_id)
    client = _central_fw(db, fw)
    out: dict = {"licenses": None, "alerts": None, "errors": []}
    try:
        lic = next((x for x in client.firewall_licenses() if x.get("serialNumber") == fw.serial), None)
        out["licenses"] = lic.get("licenses", []) if lic else []
        out["model_type"] = (lic or {}).get("modelType")
        out["last_seen_at"] = (lic or {}).get("lastSeenAt")
    except CentralError as e:
        out["errors"].append(f"Lizenzen: {e}")
    try:
        names = {fw.name, fw.hostname, fw.serial} - {""}
        out["alerts"] = [a for a in client.firewall_alerts()
                         if (a.get("managedAgent") or {}).get("id") == fw.central_id
                         or (a.get("managedAgent") or {}).get("name") in names]
    except CentralError as e:
        out["errors"].append(f"Alerts: {e}")
    return out


@router.get("/firewalls/{firewall_id}/export.json")
def export_json(firewall_id: str, request: Request, user: User = Depends(get_current_user),
                db: DbSession = Depends(get_db)):
    """Zwischengespeicherte Konfiguration als JSON (REST-Format bzw. XML-Dicts)."""
    import json
    from fastapi.responses import Response
    fw = firewall_or_404(db, user, firewall_id)
    config = sync.cached_config(db, fw)
    audit(db, "config.exported", actor=user, target_type="firewall", target_id=fw.id, ip=client_ip(request),
          details={"firewall": fw.name, "objects": sum(len(v) for v in config.values()), "format": "json"})
    body = {"firewall": fw.name, "format": entities.fmt_for(fw.connector), "exportedAt": datetime.now(timezone.utc)
            .isoformat(), "objects": config}
    return Response(json.dumps(body, indent=2, ensure_ascii=False), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="firewall-config.json"'})


@router.get("/firewalls/{firewall_id}/analysis")
def analysis(firewall_id: str, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    """Regel-Analyse der aktuellen (zwischengespeicherten) Konfiguration."""
    from .. import lint
    fw = firewall_or_404(db, user, firewall_id)
    findings = lint.analyze(sync.cached_config(db, fw))
    return {"findings": findings, "counts": {s: sum(1 for f in findings if f["severity"] == s)
                                             for s in ("high", "medium", "info")}}


# --- Import (wie „Review import“ im Config Studio) ---------------------------------------------------------

@router.post("/firewalls/{firewall_id}/import/review")
async def import_review(firewall_id: str, file: UploadFile = File(...), user: User = Depends(get_current_user),
                        db: DbSession = Depends(get_db)):
    """Entities.xml/.tar hochladen und mit der Firewall vergleichen – nichts wird gespeichert oder geändert."""
    from .. import importer
    fw = firewall_or_404(db, user, firewall_id, "change.create")
    parsed, version = importer.parse_upload(await file.read(importer.MAX_BYTES + 1))
    items = importer.review(sync.cached_config(db, fw), entities.fmt_for(fw.connector), parsed)
    token = importer.store(user.id, fw.id, items)
    counts = {s: sum(1 for i in items if i["status"] == s) for s in ("new", "changed", "same", "unsupported")}
    return {"token": token, "api_version": version, "counts": counts,
            "items": [{k: v for k, v in i.items() if k != "data"} | {"key": str(n)} for n, i in enumerate(items)]}


class ImportApplyIn(BaseModel):
    token: str
    keys: list[str] = Field(max_length=5000)


@router.post("/firewalls/{firewall_id}/import/apply")
def import_apply(firewall_id: str, body: ImportApplyIn, request: Request, user: User = Depends(get_current_user),
                 db: DbSession = Depends(get_db)):
    """Ausgewählte Import-Einträge in den eigenen Entwurf übernehmen (einzeln geprüft)."""
    from .. import importer
    from ..serializers import change_out
    fw = firewall_or_404(db, user, firewall_id, "change.create")
    items = importer.load(body.token, user.id, fw.id)
    ops = importer.operations(items, set(body.keys), sync.cached_config(db, fw))
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
    audit(db, "config.import_to_draft", actor=user, target_type="firewall", target_id=fw.id, ip=client_ip(request),
          details={"firewall": fw.name, "added": added, "skipped": len(skipped)})
    return {"added": added, "skipped": skipped, "draft": change_out(db, draft, user) if draft else None}
