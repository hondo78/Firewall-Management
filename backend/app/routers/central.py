"""Sophos-Central-Konten (Service Principals) verwalten und Inventar übernehmen."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .. import config, crypto, diagnose, sync
from ..audit import audit
from ..db import get_db
from ..models import CentralAccount, Firewall, FirewallGroup, User, new_id
from ..permissions import require_superadmin
from ..security import client_ip
from ..sophos import connector
from ..sophos.central import CentralClient, CentralError, normalize_status
from ..i18n import tr

router = APIRouter(prefix="/api/central-accounts", tags=["central"])
# Central-Konten enthalten Zugangsdaten zu allen Firewalls eines Tenants → nur Superadmin
admin_only = require_superadmin


class AccountIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    client_id: str = Field(min_length=1)
    client_secret: str | None = None
    id_url: str = ""
    api_url: str = ""
    tenant_id: str = ""


def account_out(a: CentralAccount) -> dict:
    return {"id": a.id, "name": a.name, "client_id": a.client_id, "id_url": a.id_url, "api_url": a.api_url,
            "id_type": a.id_type, "principal_id": a.principal_id, "tenant_id": a.tenant_id,
            "data_region": a.data_region, "last_sync_at": a.last_sync_at, "last_error": a.last_error}


@router.get("")
def list_accounts(_: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    return [account_out(a) for a in db.execute(select(CentralAccount).order_by(CentralAccount.name)).scalars()]


def _resolve(db: DbSession, acc: CentralAccount) -> list[dict]:
    try:
        tenants = sync.resolve_account(acc)
        acc.last_error = ""
    except CentralError as e:
        acc.last_error = str(e)
        db.commit()
        raise HTTPException(502, str(e))
    return tenants


@router.post("")
def create_account(body: AccountIn, request: Request, actor: User = Depends(admin_only),
                   db: DbSession = Depends(get_db)):
    if not body.client_secret:
        raise HTTPException(400, tr('Client-Secret fehlt'))
    acc = CentralAccount(id=new_id(), name=body.name, client_id=body.client_id.strip(),
                         id_url=(body.id_url or config.SOPHOS_ID_URL).rstrip("/"),
                         api_url=(body.api_url or config.SOPHOS_API_URL).rstrip("/"), tenant_id=body.tenant_id)
    acc.client_secret_enc = crypto.encrypt(body.client_secret, f"central:{acc.id}")
    tenants = _resolve(db, acc)
    db.add(acc)
    audit(db, "central.account_created", actor=actor, target_type="central_account", target_id=acc.id,
          ip=client_ip(request), details={"name": acc.name, "type": acc.id_type, "client_id": acc.client_id})
    return {**account_out(acc), "tenants": tenants}


@router.put("/{account_id}")
def update_account(account_id: str, body: AccountIn, request: Request, actor: User = Depends(admin_only),
                   db: DbSession = Depends(get_db)):
    acc = db.get(CentralAccount, account_id)
    if not acc:
        raise HTTPException(404, tr('Konto nicht gefunden'))
    acc.name, acc.client_id = body.name, body.client_id.strip()
    acc.id_url = (body.id_url or config.SOPHOS_ID_URL).rstrip("/")
    acc.api_url = (body.api_url or config.SOPHOS_API_URL).rstrip("/")
    acc.tenant_id = body.tenant_id or acc.tenant_id
    if body.client_secret:
        acc.client_secret_enc = crypto.encrypt(body.client_secret, f"central:{acc.id}")
    tenants = _resolve(db, acc)
    audit(db, "central.account_updated", actor=actor, target_type="central_account", target_id=acc.id,
          ip=client_ip(request), details={"name": acc.name, "secret_changed": bool(body.client_secret),
                                          "tenant_id": acc.tenant_id})
    return {**account_out(acc), "tenants": tenants}


@router.get("/{account_id}/tenants")
def tenants(account_id: str, _: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    acc = db.get(CentralAccount, account_id)
    if not acc:
        raise HTTPException(404, tr('Konto nicht gefunden'))
    result = _resolve(db, acc)
    db.commit()
    return result


@router.post("/{account_id}/sync")
def sync_inventory(account_id: str, request: Request, actor: User = Depends(admin_only),
                   db: DbSession = Depends(get_db)):
    acc = db.get(CentralAccount, account_id)
    if not acc:
        raise HTTPException(404, tr('Konto nicht gefunden'))
    if acc.id_type in ("partner", "organization") and not acc.tenant_id:
        raise HTTPException(400, tr('Bitte zuerst einen Tenant auswählen'))
    try:
        return sync.sync_central_inventory(db, acc, actor)
    except CentralError as e:
        raise HTTPException(502, str(e))


@router.delete("/{account_id}")
def delete_account(account_id: str, request: Request, actor: User = Depends(admin_only),
                   db: DbSession = Depends(get_db)):
    acc = db.get(CentralAccount, account_id)
    if not acc:
        raise HTTPException(404, tr('Konto nicht gefunden'))
    db.delete(acc)
    audit(db, "central.account_deleted", actor=actor, target_type="central_account", target_id=account_id,
          ip=client_ip(request), details={"name": acc.name})
    return {"ok": True}


@router.post("/{account_id}/diagnose")
def diagnose_account(account_id: str, request: Request, actor: User = Depends(admin_only),
                     db: DbSession = Depends(get_db)):
    """Probelauf: nur lesende Aufrufe gegen Sophos Central (inkl. Suche nach nicht dokumentierten Endpunkten)."""
    acc = db.get(CentralAccount, account_id)
    if not acc:
        raise HTTPException(404, tr('Konto nicht gefunden'))
    result = diagnose.central(db, acc)
    audit(db, "central.diagnosed", actor=actor, target_type="central_account", target_id=acc.id,
          ip=client_ip(request), details={"account": acc.name, "passed": result["passed"], "failed": result["failed"],
                                          "failed_steps": [s["name"] for s in result["steps"] if s["ok"] is False]})
    return result


# --- Inventar in Sophos Central verwalten (Firewall Management API) ------------------------------------------
# Verwaltungsaktionen am Central-Tenant, keine Firewall-Konfiguration: direkt ausgeführt (Superadmin), jede im Audit-Log.
# Konfigurationsänderungen – auch der MDR-Threat-Feed – laufen dagegen immer über Anträge mit Vier-Augen-Prinzip.

class GeoIn(BaseModel):
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)


class CentralFirewallIn(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=40)
    geo: GeoIn | None = None


class ConfirmIn(BaseModel):
    confirm: str = ""


class GroupCreateIn(BaseModel):
    name: str = Field(min_length=3, max_length=40)
    parent_id: str | None = None
    assign: list[str] = Field(default_factory=list, max_length=1000)
    import_from: str | None = None


class GroupUpdateIn(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=40)
    assign: list[str] = Field(default_factory=list, max_length=1000)
    unassign: list[str] = Field(default_factory=list, max_length=1000)


def _account(db: DbSession, account_id: str) -> tuple[CentralAccount, CentralClient]:
    acc = db.get(CentralAccount, account_id)
    if not acc:
        raise HTTPException(404, tr('Konto nicht gefunden'))
    if acc.id_type in ("partner", "organization") and not acc.tenant_id:
        raise HTTPException(400, tr('Bitte zuerst einen Tenant auswählen'))
    return acc, connector.central_client(acc)


def _central(call):
    try:
        return call()
    except CentralError as e:
        raise HTTPException(502, str(e))


def _resync(db: DbSession, acc: CentralAccount, actor: User) -> str:
    """Gruppenzuordnung lokal nachziehen; ein Fehler hier macht die Aktion in Central nicht ungeschehen."""
    try:
        sync.sync_central_inventory(db, acc, actor)
        return ""
    except CentralError as e:
        return str(e)


@router.get("/{account_id}/inventory")
def inventory(account_id: str, _: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    acc, client = _account(db, account_id)
    fws, groups = _central(lambda: (client.firewalls(), client.groups()))
    local = {f.central_id: f for f in db.execute(select(Firewall).where(Firewall.central_account_id == acc.id)).scalars()}
    out_fws = []
    for f in fws:
        lf = local.get(f["id"])
        out_fws.append({**f, "status": normalize_status(f.get("status")),
                        "local": {"id": lf.id, "name": lf.name, "archived": lf.archived} if lf else None})
    return {"firewalls": out_fws, "groups": groups}


@router.get("/{account_id}/groups/{group_id}/sync-status")
def group_sync_status(account_id: str, group_id: str, _: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    _, client = _account(db, account_id)
    return _central(lambda: client.group_sync_status(group_id))


@router.patch("/{account_id}/firewalls/{central_id}")
def update_central_firewall(account_id: str, central_id: str, body: CentralFirewallIn, request: Request,
                            actor: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    acc, client = _account(db, account_id)
    if body.name is None and body.geo is None:
        raise HTTPException(400, tr('Keine Änderung angegeben'))
    geo = body.geo.model_dump() if body.geo else None
    res = _central(lambda: client.update_firewall(central_id, body.name, geo))
    audit(db, "central.firewall_updated", actor=actor, target_type="central_account", target_id=acc.id,
          ip=client_ip(request), details={"account": acc.name, "central_id": central_id, "name": body.name, "geo": geo})
    return res


@router.post("/{account_id}/firewalls/{central_id}/approve")
def approve_central_firewall(account_id: str, central_id: str, request: Request, actor: User = Depends(admin_only),
                             db: DbSession = Depends(get_db)):
    """Verwaltung durch Sophos Central freigeben (Aktion approveManagement)."""
    acc, client = _account(db, account_id)
    res = _central(lambda: client.approve_management(central_id))
    audit(db, "central.firewall_approved", actor=actor, target_type="central_account", target_id=acc.id,
          ip=client_ip(request), details={"account": acc.name, "central_id": central_id})
    return res


@router.delete("/{account_id}/firewalls/{central_id}")
def delete_central_firewall(account_id: str, central_id: str, body: ConfirmIn, request: Request,
                            actor: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    """Firewall aus Sophos Central entfernen. Bestätigung mit dem Namen der Firewall in Central."""
    acc, client = _account(db, account_id)
    fw = next((f for f in _central(client.firewalls) if f["id"] == central_id), None)
    if not fw:
        raise HTTPException(404, tr('Firewall nicht in Sophos Central gefunden'))
    if body.confirm.strip() != (fw.get("name") or fw.get("hostname") or ""):
        raise HTTPException(400, tr('Zur Bestätigung den Namen der Firewall eingeben'))
    _central(lambda: client.delete_firewall(central_id))
    local = db.execute(select(Firewall).where(Firewall.central_account_id == acc.id,
                                              Firewall.central_id == central_id)).scalar()
    note = ""
    if local:
        if local.connector == "central":
            # ohne Central nicht mehr erreichbar → wie „Firewall entfernen“ archivieren (Historie bleibt)
            local.archived, local.api_password_enc, local.xml_password_enc = True, "", ""
            note = tr('„{0}“ wurde im Tool archiviert (Anbindung über Sophos Central)', local.name)
        else:
            local.central_id, local.central_account_id, local.mdr_status = "", None, ""
            note = tr('„{0}“ bleibt über ihre direkte Anbindung verwaltet, ohne Central-Zuordnung', local.name)
    audit(db, "central.firewall_deleted", actor=actor, target_type="central_account", target_id=acc.id,
          ip=client_ip(request), details={"account": acc.name, "central_id": central_id, "name": fw.get("name"),
                                          "serial": fw.get("serialNumber"), "local": local.name if local else None})
    return {"ok": True, "note": note}


@router.post("/{account_id}/groups")
def create_central_group(account_id: str, body: GroupCreateIn, request: Request, actor: User = Depends(admin_only),
                         db: DbSession = Depends(get_db)):
    acc, client = _account(db, account_id)
    res = _central(lambda: client.create_group(body.name.strip(), body.assign, body.parent_id, body.import_from))
    audit(db, "central.group_created", actor=actor, target_type="central_account", target_id=acc.id,
          ip=client_ip(request), details={"account": acc.name, "name": body.name, "parent_id": body.parent_id,
                                          "firewalls": len(body.assign), "config_import_from": body.import_from})
    return {**res, "sync_error": _resync(db, acc, actor)}


@router.patch("/{account_id}/groups/{group_id}")
def update_central_group(account_id: str, group_id: str, body: GroupUpdateIn, request: Request,
                         actor: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    acc, client = _account(db, account_id)
    if body.name is None and not body.assign and not body.unassign:
        raise HTTPException(400, tr('Keine Änderung angegeben'))
    res = _central(lambda: client.update_group(group_id, body.name, body.assign, body.unassign))
    audit(db, "central.group_updated", actor=actor, target_type="central_account", target_id=acc.id,
          ip=client_ip(request), details={"account": acc.name, "group_id": group_id, "name": body.name,
                                          "assigned": len(body.assign), "unassigned": len(body.unassign)})
    return {**(res or {}), "sync_error": _resync(db, acc, actor)}


@router.delete("/{account_id}/groups/{group_id}")
def delete_central_group(account_id: str, group_id: str, request: Request, actor: User = Depends(admin_only),
                         db: DbSession = Depends(get_db)):
    acc, client = _account(db, account_id)
    _central(lambda: client.delete_group(group_id))
    local = db.execute(select(FirewallGroup).where(FirewallGroup.central_account_id == acc.id,
                                                   FirewallGroup.central_id == group_id)).scalar()
    if local:
        # Die Gruppe bleibt im Tool (Rollen-Zuweisungen hängen daran), nur ohne Central-Bezug
        local.central_id, local.central_account_id = "", None
    audit(db, "central.group_deleted", actor=actor, target_type="central_account", target_id=acc.id,
          ip=client_ip(request), details={"account": acc.name, "group_id": group_id,
                                          "local_group": local.name if local else None})
    return {"ok": True}
