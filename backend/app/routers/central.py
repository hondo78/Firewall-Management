"""Sophos-Central-Konten (Service Principals) verwalten und Inventar übernehmen."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .. import config, crypto, diagnose, sync
from ..audit import audit
from ..db import get_db
from ..models import CentralAccount, User, new_id
from ..permissions import require_superadmin
from ..security import client_ip
from ..sophos.central import CentralError
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
