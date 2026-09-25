"""Rechte-Modell.

Ein Benutzer erhält Rollen (= Mengen von Rechten), jeweils global oder für eine Firewall-Gruppe.
Firewall-bezogene Rechte gelten für eine Firewall, wenn eine globale Zuweisung oder eine Zuweisung für ihre
Gruppe das Recht enthält. Globale Rechte (GLOBAL_ONLY) zählen nur aus globalen Zuweisungen.
Superadmins haben immer alle Rechte.
"""
from fastapi import Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .db import get_db
from .models import Firewall, Role, RoleAssignment, User
from .security import get_current_user

PERMISSIONS: dict[str, str] = {
    "firewall.view": "Firewalls und Konfiguration ansehen",
    "change.create": "Änderungen beantragen",
    "change.approve": "Änderungen genehmigen oder ablehnen (nie eigene)",
    "change.deploy": "Genehmigte Änderungen manuell ausrollen / erneut versuchen",
    "firewall.manage": "Firewalls verbinden, bearbeiten und synchronisieren",
    "firmware.manage": "Firmware-Updates planen",
    "audit.view": "Audit-Log einsehen (nur global)",
    "admin": "Benutzer, Rollen, Central-Konten und Einstellungen verwalten (nur global)",
}
GLOBAL_ONLY = {"audit.view", "admin"}

BUILTIN_ROLES = [
    ("Betrachter", "Nur lesen", ["firewall.view"]),
    ("Operator", "Darf Regeländerungen beantragen", ["firewall.view", "change.create"]),
    ("Approver", "Prüft und genehmigt Änderungen anderer", ["firewall.view", "change.approve"]),
    ("Firewall-Administrator", "Voller Zugriff auf die zugewiesenen Firewalls",
     ["firewall.view", "change.create", "change.approve", "change.deploy", "firewall.manage", "firmware.manage"]),
    ("Auditor", "Liest Konfiguration und Audit-Log", ["firewall.view", "audit.view"]),
]


def grants(db: DbSession, user: User) -> list[tuple[str | None, set[str]]]:
    """[(group_id | None, rechte)] aller Zuweisungen des Benutzers."""
    rows = db.execute(
        select(RoleAssignment.group_id, Role.permissions)
        .join(Role, Role.id == RoleAssignment.role_id)
        .where(RoleAssignment.user_id == user.id)
    ).all()
    return [(g, set(p or [])) for g, p in rows]


def effective(db: DbSession, user: User) -> dict:
    """Für das Frontend: {"global": [...], "groups": {group_id: [...]}}."""
    if user.is_superadmin:
        return {"global": sorted(PERMISSIONS), "groups": {}}
    out_global: set[str] = set()
    groups: dict[str, set[str]] = {}
    for group_id, perms in grants(db, user):
        if group_id is None:
            out_global |= perms
        else:
            groups.setdefault(group_id, set()).update(perms - GLOBAL_ONLY)
    return {"global": sorted(out_global), "groups": {g: sorted(p) for g, p in groups.items()}}


def has_global(db: DbSession, user: User, perm: str) -> bool:
    if user.is_superadmin:
        return True
    return any(g is None and perm in p for g, p in grants(db, user))


def can(db: DbSession, user: User, perm: str, firewall: Firewall | None) -> bool:
    if user.is_superadmin:
        return True
    for group_id, perms in grants(db, user):
        if perm not in perms:
            continue
        if group_id is None:
            return True
        if perm not in GLOBAL_ONLY and firewall is not None and firewall.group_id == group_id:
            return True
    return False


def can_anywhere(db: DbSession, user: User, perm: str) -> bool:
    """Hat der Benutzer das Recht auf mindestens einer Firewall/Gruppe?"""
    return user.is_superadmin or any(perm in p for _, p in grants(db, user))


def visible_group_ids(db: DbSession, user: User, perm: str = "firewall.view") -> set[str | None] | None:
    """None = alle Firewalls; sonst die Menge der Gruppen-IDs mit dem Recht."""
    if user.is_superadmin:
        return None
    ids: set[str | None] = set()
    for group_id, perms in grants(db, user):
        if perm in perms:
            if group_id is None:
                return None
            ids.add(group_id)
    return ids


def require_global(perm: str):
    def dep(user: User = Depends(get_current_user), db: DbSession = Depends(get_db)) -> User:
        if not has_global(db, user, perm):
            raise HTTPException(403, "Keine Berechtigung")
        return user
    return dep


def firewall_or_404(db: DbSession, user: User, firewall_id: str, perm: str = "firewall.view") -> Firewall:
    """Unsichtbare Firewalls antworten mit 404, fehlende Einzelrechte mit 403."""
    fw = db.get(Firewall, firewall_id)
    if not fw or fw.archived or not can(db, user, "firewall.view", fw):
        raise HTTPException(404, "Firewall nicht gefunden")
    if perm != "firewall.view" and not can(db, user, perm, fw):
        raise HTTPException(403, "Keine Berechtigung für diese Firewall")
    return fw
