import csv
import io
import json
from datetime import datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session as DbSession

from .. import permissions
from ..audit import audit, verify_chain
from ..db import get_db
from datetime import timedelta

from ..models import AuditLog, ChangeRequest, Firewall, User, utcnow
from ..permissions import require_global
from ..security import client_ip, get_current_user

router = APIRouter(prefix="/api", tags=["audit"])
auditor = require_global("audit.view")


def _query(action: str, actor: str, target_id: str, q: str, since: datetime | None, until: datetime | None):
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action.like(f"{action}%"))
    if actor:
        stmt = stmt.where(AuditLog.actor_name == actor.lower())
    if target_id:
        stmt = stmt.where(AuditLog.target_id == target_id)
    if since:
        stmt = stmt.where(AuditLog.ts >= since)
    if until:
        stmt = stmt.where(AuditLog.ts <= until)
    if q:
        # details ist JSON – für die Volltextsuche als Text vergleichen
        from sqlalchemy import String, cast
        stmt = stmt.where(or_(cast(AuditLog.details, String).ilike(f"%{q}%"), AuditLog.action.ilike(f"%{q}%")))
    return stmt


def _out(e: AuditLog) -> dict:
    return {"id": e.id, "ts": e.ts, "actor": e.actor_name, "action": e.action, "target_type": e.target_type,
            "target_id": e.target_id, "details": e.details, "ip": e.ip, "hash": e.hash[:12]}


@router.get("/audit")
def list_audit(action: str = "", actor: str = "", target_id: str = "", q: str = "",
               since: datetime | None = None, until: datetime | None = None, offset: int = 0, limit: int = 100,
               _: User = Depends(auditor), db: DbSession = Depends(get_db)):
    stmt = _query(action, actor, target_id, q, since, until)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar()
    rows = db.execute(stmt.order_by(AuditLog.id.desc()).offset(offset).limit(min(limit, 500))).scalars().all()
    return {"total": total, "items": [_out(e) for e in rows]}


@router.get("/audit/actions")
def audit_actions(_: User = Depends(auditor), db: DbSession = Depends(get_db)):
    return sorted(db.execute(select(AuditLog.action).distinct()).scalars())


@router.get("/audit/verify")
def verify(request: Request, user: User = Depends(auditor), db: DbSession = Depends(get_db)):
    result = verify_chain(db)
    audit(db, "audit.verified", actor=user, ip=client_ip(request), details=result)
    return result


@router.get("/audit/export.csv")
def export_csv(request: Request, action: str = "", actor: str = "", target_id: str = "", q: str = "",
               since: datetime | None = None, until: datetime | None = None,
               user: User = Depends(auditor), db: DbSession = Depends(get_db)):
    rows = db.execute(_query(action, actor, target_id, q, since, until).order_by(AuditLog.id)).scalars().all()
    audit(db, "audit.exported", actor=user, ip=client_ip(request), details={"rows": len(rows)})
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["id", "zeit", "benutzer", "aktion", "objekttyp", "objekt", "ip", "details", "hash", "prev_hash"])
    for e in rows:
        w.writerow([e.id, e.ts.isoformat(), e.actor_name, e.action, e.target_type, e.target_id, e.ip,
                    json.dumps(e.details, ensure_ascii=False), e.hash, e.prev_hash])
    return StreamingResponse(iter(["﻿" + buf.getvalue()]), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": 'attachment; filename="audit-log.csv"'})


@router.get("/dashboard")
def dashboard(user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    fws = [f for f in db.execute(select(Firewall).where(Firewall.archived.is_(False))).scalars() if permissions.can(db, user, "firewall.view", f)]
    ids = {f.id for f in fws}
    crs = [c for c in db.execute(select(ChangeRequest).where(
        ChangeRequest.status.in_(("pending", "approved", "deploying", "failed", "conflict")))).scalars()
        if c.firewall_id in ids]
    to_approve = [c for c in crs if c.status == "pending" and c.created_by != user.id
                  and not any(e.kind == "approved" and e.user_id == user.id for e in c.events)
                  and permissions.can(db, user, "change.approve", c.firewall)]
    recent = []
    if permissions.has_global(db, user, "audit.view"):
        recent = [_out(e) for e in db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(12)).scalars()]
    return {
        "firewalls": len(fws),
        "firewalls_error": sum(1 for f in fws if f.last_sync_error),
        "firewalls_never_synced": sum(1 for f in fws if not f.last_sync_at),
        "firewalls_disconnected": sum(1 for f in fws if f.central_status and f.central_status.get("connected") is False),
        # API-Keys, die in den nächsten 30 Tagen ablaufen (oder abgelaufen sind)
        "keys_expiring": [{"id": f.id, "name": f.name, "expires_at": f.api_key_expires_at} for f in fws
                          if f.connector == "rest" and f.api_key_expires_at
                          and f.api_key_expires_at < utcnow() + timedelta(days=30)],
        "pending": sum(1 for c in crs if c.status == "pending"),
        "approved": sum(1 for c in crs if c.status in ("approved", "deploying")),
        "failed": sum(1 for c in crs if c.status in ("failed", "conflict")),
        "to_approve": len(to_approve),
        "mine_open": sum(1 for c in crs if c.created_by == user.id),
        "recent": recent,
    }
