"""Administration: Benutzer, Rollen, Rollenzuweisungen, Einstellungen."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from .. import permissions, settings
from ..audit import audit
from ..db import get_db
from ..models import (ChangeEvent, ChangeRequest, ChangeTemplate, ConfigBackup, FirewallGroup, Role, RoleAssignment,
                      User)
from ..permissions import require_global
from ..security import client_ip, get_current_user, hash_password
from ..serializers import user_out

router = APIRouter(prefix="/api", tags=["admin"])
admin_only = require_global("admin")


class AssignmentIn(BaseModel):
    role_id: str
    group_id: str | None = None


class UserIn(BaseModel):
    username: str = Field(min_length=2, max_length=100)
    display_name: str = ""
    email: str = ""
    password: str | None = None
    is_superadmin: bool = False
    active: bool = True
    assignments: list[AssignmentIn] = Field(default_factory=list)


class RoleIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str = ""
    permissions: list[str] = Field(default_factory=list)


# --- Benutzer ----------------------------------------------------------------------------------------------

@router.get("/users")
def list_users(user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    # Namensliste für alle (Filter im Antragsverlauf); Details nur für Admins
    users = db.execute(select(User).where(User.deleted.is_(False)).order_by(User.username)).scalars().all()
    if permissions.has_global(db, user, "admin"):
        return [user_out(u) for u in users]
    return [{"id": u.id, "username": u.username, "display_name": u.display_name} for u in users]


def _apply_assignments(db: DbSession, u: User, items: list[AssignmentIn]) -> list[str]:
    seen = set()
    u.assignments.clear()
    db.flush()
    labels = []
    for a in items:
        key = (a.role_id, a.group_id)
        if key in seen:
            continue
        seen.add(key)
        role = db.get(Role, a.role_id)
        if not role:
            raise HTTPException(400, "Unbekannte Rolle")
        group = db.get(FirewallGroup, a.group_id) if a.group_id else None
        if a.group_id and not group:
            raise HTTPException(400, "Unbekannte Firewall-Gruppe")
        u.assignments.append(RoleAssignment(role_id=role.id, group_id=a.group_id))
        labels.append(f"{role.name} @ {group.name if group else 'alle Firewalls'}")
    return labels


def _check_last_superadmin(db: DbSession, u: User, is_superadmin: bool, active: bool) -> None:
    if u.is_superadmin and (not is_superadmin or not active):
        others = db.execute(select(func.count()).select_from(User).where(
            User.is_superadmin.is_(True), User.active.is_(True), User.id != u.id)).scalar()
        if not others:
            raise HTTPException(409, "Der letzte aktive Superadmin kann nicht herabgestuft werden")


@router.post("/users")
def create_user(body: UserIn, request: Request, actor: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    name = body.username.strip().lower()
    if db.execute(select(User).where(User.username == name)).scalar():
        raise HTTPException(409, "Benutzername existiert bereits")
    if not body.password or len(body.password) < 10:
        raise HTTPException(400, "Passwort muss mindestens 10 Zeichen haben")
    u = User(username=name, display_name=body.display_name, email=body.email, active=body.active,
             is_superadmin=body.is_superadmin, password_hash=hash_password(body.password))
    db.add(u)
    db.flush()
    labels = _apply_assignments(db, u, body.assignments)
    audit(db, "user.created", actor=actor, target_type="user", target_id=u.id, ip=client_ip(request),
          details={"username": name, "superadmin": u.is_superadmin, "roles": labels})
    return user_out(u)


@router.put("/users/{user_id}")
def update_user(user_id: str, body: UserIn, request: Request, actor: User = Depends(admin_only),
                db: DbSession = Depends(get_db)):
    u = db.get(User, user_id)
    if not u or u.deleted:
        raise HTTPException(404, "Benutzer nicht gefunden")
    _check_last_superadmin(db, u, body.is_superadmin, body.active)
    before = {"roles": [f"{a.role.name} @ {a.group_id or 'alle'}" for a in u.assignments],
              "superadmin": u.is_superadmin, "active": u.active}
    u.display_name, u.email, u.active, u.is_superadmin = body.display_name, body.email, body.active, body.is_superadmin
    if body.password:
        if len(body.password) < 10:
            raise HTTPException(400, "Passwort muss mindestens 10 Zeichen haben")
        u.password_hash = hash_password(body.password)
    labels = _apply_assignments(db, u, body.assignments)
    audit(db, "user.updated", actor=actor, target_type="user", target_id=u.id, ip=client_ip(request), details={
        "username": u.username, "before": before, "roles": labels, "superadmin": u.is_superadmin,
        "active": u.active, "password_reset": bool(body.password),
    })
    return user_out(u)


@router.delete("/users/{user_id}")
def delete_user(user_id: str, request: Request, actor: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "Benutzer nicht gefunden")
    if u.id == actor.id:
        raise HTTPException(409, "Sie können sich nicht selbst löschen")
    if u.deleted:
        raise HTTPException(404, "Benutzer nicht gefunden")
    _check_last_superadmin(db, u, False, False)
    name = u.username
    if not _has_history(db, u):
        # Nie beteiligt gewesen → endgültig löschen (Rollenzuweisungen werden mit entfernt)
        db.delete(u)
        audit(db, "user.deleted", actor=actor, target_type="user", target_id=user_id, ip=client_ip(request),
              details={"username": name, "mode": "removed"})
        return {"ok": True, "mode": "removed"}
    # Anträge, Genehmigungen oder Vorlagen verweisen auf den Benutzer → anonymisieren statt löschen, damit der
    # Verlauf nachvollziehbar bleibt. Der Benutzername wird frei (umbenannt), Anmeldung ist nicht mehr möglich.
    new_name = f"{name} (gelöscht)"[:100]
    n = 2
    while db.execute(select(User.id).where(User.username == new_name)).first():
        new_name = f"{name} (gelöscht {n})"[:100]
        n += 1
    u.username, u.deleted, u.active, u.is_superadmin = new_name, True, False, False
    u.email, u.password_hash, u.oidc_subject, u.telegram_chat_id = "", "!", "", ""
    u.totp_enabled, u.totp_secret_enc, u.totp_pending_enc = False, "", ""
    u.assignments.clear()
    audit(db, "user.deleted", actor=actor, target_type="user", target_id=u.id, ip=client_ip(request),
          details={"username": name, "mode": "anonymized"})
    return {"ok": True, "mode": "anonymized"}


def _has_history(db: DbSession, u: User) -> bool:
    checks = (select(ChangeRequest.id).where(ChangeRequest.created_by == u.id),
              select(ChangeEvent.id).where(ChangeEvent.user_id == u.id),
              select(ChangeTemplate.id).where(ChangeTemplate.created_by == u.id),
              select(ConfigBackup.id).where(ConfigBackup.created_by == u.id))
    return any(db.execute(q.limit(1)).first() for q in checks)


# --- Rollen ------------------------------------------------------------------------------------------------

@router.get("/permissions")
def list_permissions(_: User = Depends(get_current_user)):
    return [{"key": k, "label": v, "global_only": k in permissions.GLOBAL_ONLY}
            for k, v in permissions.PERMISSIONS.items()]


@router.get("/roles")
def list_roles(_: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    roles = db.execute(select(Role).order_by(Role.builtin.desc(), Role.name)).scalars().all()
    counts = dict(db.execute(select(RoleAssignment.role_id, func.count()).group_by(RoleAssignment.role_id)).all())
    return [{"id": r.id, "name": r.name, "description": r.description, "permissions": r.permissions,
             "builtin": r.builtin, "assignments": counts.get(r.id, 0)} for r in roles]


def _clean_perms(perms: list[str]) -> list[str]:
    bad = [p for p in perms if p not in permissions.PERMISSIONS]
    if bad:
        raise HTTPException(400, f"Unbekannte Rechte: {', '.join(bad)}")
    return sorted(set(perms))


@router.post("/roles")
def create_role(body: RoleIn, request: Request, actor: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    if db.execute(select(Role).where(Role.name == body.name.strip())).scalar():
        raise HTTPException(409, "Rolle existiert bereits")
    r = Role(name=body.name.strip(), description=body.description, permissions=_clean_perms(body.permissions))
    db.add(r)
    db.flush()
    audit(db, "role.created", actor=actor, target_type="role", target_id=r.id, ip=client_ip(request),
          details={"name": r.name, "permissions": r.permissions})
    return {"id": r.id}


@router.put("/roles/{role_id}")
def update_role(role_id: str, body: RoleIn, request: Request, actor: User = Depends(admin_only),
                db: DbSession = Depends(get_db)):
    r = db.get(Role, role_id)
    if not r:
        raise HTTPException(404, "Rolle nicht gefunden")
    before = list(r.permissions)
    r.name, r.description, r.permissions = body.name.strip(), body.description, _clean_perms(body.permissions)
    audit(db, "role.updated", actor=actor, target_type="role", target_id=r.id, ip=client_ip(request),
          details={"name": r.name, "before": before, "after": r.permissions})
    return {"ok": True}


@router.delete("/roles/{role_id}")
def delete_role(role_id: str, request: Request, actor: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    r = db.get(Role, role_id)
    if not r:
        raise HTTPException(404, "Rolle nicht gefunden")
    if r.builtin:
        raise HTTPException(409, "Vordefinierte Rollen können nicht gelöscht werden")
    in_use = db.execute(select(func.count()).select_from(RoleAssignment).where(RoleAssignment.role_id == r.id)).scalar()
    if in_use:
        raise HTTPException(409, f"Rolle ist noch {in_use}× zugewiesen")
    db.delete(r)
    audit(db, "role.deleted", actor=actor, target_type="role", target_id=role_id, ip=client_ip(request),
          details={"name": r.name})
    return {"ok": True}


# --- Einstellungen -----------------------------------------------------------------------------------------

@router.get("/settings")
def get_settings(_: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    return settings.get_all(db)


@router.put("/settings")
def put_settings(body: dict, request: Request, actor: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    try:
        changed = settings.set_many(db, body)
    except (TypeError, ValueError):
        raise HTTPException(400, "Ungültiger Wert")
    if changed:
        audit(db, "settings.updated", actor=actor, target_type="settings", ip=client_ip(request), details=changed)
    else:
        db.commit()
    return settings.get_all(db)
