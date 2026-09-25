"""Audit-Log mit Hash-Kette: hash = sha256(prev_hash + kanonisches JSON des Eintrags).

Wird ein Eintrag nachträglich in der DB verändert oder gelöscht, schlägt verify_chain() ab dieser Stelle fehl.
"""
import hashlib
import json
from datetime import timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session as DbSession

from . import syslog
from .models import AuditLog, User, utcnow

_GENESIS = "0" * 64
_LOCK_ID = 7_264_002


def _canonical(entry: AuditLog) -> str:
    return json.dumps({
        "ts": entry.ts.astimezone(timezone.utc).isoformat(),
        "actor_id": entry.actor_id,
        "actor_name": entry.actor_name,
        "action": entry.action,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "details": entry.details,
        "ip": entry.ip,
    }, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _hash(prev_hash: str, entry: AuditLog) -> str:
    return hashlib.sha256((prev_hash + _canonical(entry)).encode()).hexdigest()


def audit(db: DbSession, action: str, *, actor: User | None = None, actor_name: str | None = None,
          target_type: str = "", target_id: str = "", details: dict | None = None, ip: str = "",
          commit: bool = True) -> AuditLog:
    # Serialisiert Schreiber, damit die Kette nicht verzweigt (Lock gilt bis Transaktionsende).
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": _LOCK_ID})
    prev = db.execute(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1)).scalar() or _GENESIS
    # Mikrosekunden weg: SQLite und Postgres runden sonst unterschiedlich → Hash wäre nicht reproduzierbar
    entry = AuditLog(
        ts=utcnow().replace(microsecond=0),
        actor_id=actor.id if actor else None,
        actor_name=actor.username if actor else (actor_name or "system"),
        action=action,
        target_type=target_type,
        target_id=str(target_id or ""),
        # Normalisieren, damit der Hash nach dem Laden aus der DB identisch ist
        details=json.loads(json.dumps(details or {}, default=str)),
        ip=ip or "",
        prev_hash=prev,
    )
    entry.hash = _hash(prev, entry)
    db.add(entry)
    if commit:
        db.commit()
    else:
        db.flush()
    syslog.send(entry.ts, action, {
        "actor": entry.actor_name, "action": action, "target_type": target_type,
        "target_id": entry.target_id, "ip": entry.ip, "details": entry.details,
    })
    return entry


def verify_chain(db: DbSession) -> dict:
    prev = _GENESIS
    count = 0
    for entry in db.execute(select(AuditLog).order_by(AuditLog.id).execution_options(yield_per=1000)).scalars():
        if entry.prev_hash != prev or _hash(prev, entry) != entry.hash:
            return {"ok": False, "checked": count, "broken_at": entry.id}
        prev = entry.hash
        count += 1
    return {"ok": True, "checked": count, "broken_at": None}
