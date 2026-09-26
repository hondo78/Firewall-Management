"""Änderungsanträge: Entwurf → Einreichen → Vier-Augen-Genehmigung → Ausrollen (mit Drift-Prüfung).

Eine Operation: {"entity", "action": add|update|remove, "name", "data" (neues Objekt), "before" (Stand beim
Einreichen), "position"/"before_position" (nur Regeln: {"type": top|bottom|after|before, "ref"})}.
"""
import copy
import logging
import threading
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session as DbSession

from . import diff, notify, permissions, settings, sync
from .audit import audit
from .models import ChangeEvent, ChangeRequest, Firewall, User, new_id, utcnow
from .sophos import connector, entities
from .i18n import tr

log = logging.getLogger("fwm.changes")

OPEN_STATES = ("draft", "pending", "approved", "deploying")
_deploy_lock = threading.Lock()


def event(db: DbSession, cr: ChangeRequest, kind: str, text: str = "", user: User | None = None) -> None:
    db.add(ChangeEvent(change_id=cr.id, kind=kind, text=text, user_id=user.id if user else None,
                       actor_name=user.username if user else "system"))


def next_number(db: DbSession) -> int:
    return (db.execute(select(func.max(ChangeRequest.number))).scalar() or 0) + 1


def get_draft(db: DbSession, user: User, fw: Firewall, create: bool = False) -> ChangeRequest | None:
    cr = db.execute(select(ChangeRequest).where(
        ChangeRequest.firewall_id == fw.id, ChangeRequest.created_by == user.id,
        ChangeRequest.status == "draft")).scalar()
    if cr is None and create:
        cr = ChangeRequest(number=next_number(db), firewall_id=fw.id, created_by=user.id, status="draft")
        db.add(cr)
        db.flush()
        event(db, cr, "created", user=user)
    return cr


# --- Validierung ---------------------------------------------------------------------------------------------

def _index(config: dict[str, list[dict]]) -> dict[str, dict[str, dict]]:
    return {e: {entities.oname(o): o for o in objs} for e, objs in config.items()}


def rule_position(config: dict[str, list[dict]], name: str, entity: str = "FirewallRule") -> dict:
    """Aktuelle Position einer Regel als Positionsangabe (nach Vorgänger bzw. ganz oben)."""
    # WAF-Regeln: Position in der gemeinsamen Regelliste (REST), sofern dort vorhanden
    if entity in entities.POSITION_SCOPE and any(entities.oname(r) == name for r in config.get(entities.POSITION_SCOPE[entity][0], [])):
        entity = entities.POSITION_SCOPE[entity][0]
    names = [entities.oname(r) for r in config.get(entity, [])]
    if name not in names:
        return {"type": "bottom"}
    i = names.index(name)
    return {"type": "top"} if i == 0 else {"type": "after", "ref": names[i - 1]}


def effective_config(config: dict[str, list[dict]], ops: list[dict]) -> dict[str, list[dict]]:
    """Konfiguration, wie sie nach Anwendung der Operationen aussähe (für Vorschau und Prüfungen)."""
    out = copy.deepcopy(config)
    for o in ops:
        lst = out.setdefault(o["entity"], [])
        idx = next((i for i, x in enumerate(lst) if entities.oname(x) == o["name"]), None)
        if o["action"] == "remove":
            if idx is not None:
                lst.pop(idx)
            continue
        if idx is not None:
            lst.pop(idx)
        pos = o.get("position")
        if o["entity"] in entities.RULE_ENTITIES and pos:
            kind = pos.get("type", "bottom")
            names = [entities.oname(x) for x in lst]
            if kind == "top":
                idx = 0
            elif kind in ("after", "before") and pos.get("ref") in names:
                idx = names.index(pos["ref"]) + (1 if kind == "after" else 0)
            else:
                idx = len(lst)
        lst.insert(len(lst) if idx is None else idx, o["data"])
    return out


references = entities.references


def check_references(config: dict[str, list[dict]]) -> list[str]:
    """Hinweise auf Verweise zu Objekten, die (im Cache) nicht existieren."""
    idx = _index(config)
    warnings = []
    for entity in entities.REFERRING_ENTITIES:
        for obj in config.get(entity, []):
            for kind, name in references(entity, obj):
                if name in entities.BUILTIN_REFS:
                    continue
                if not any(name in idx.get(e, {}) for e in entities.REF_ENTITIES[kind]):
                    warnings.append(tr('{0} „{1}“ verweist auf unbekanntes Objekt „{2}“ – vordefiniertes Objekt der Firewall?', tr(entities.LABELS[entity]), entities.oname(obj), name))
    return warnings


def used_by(config: dict[str, list[dict]], entity: str, name: str) -> list[str]:
    kind = entities.kind_of(entity)
    if not kind:
        return []
    out = []
    for ent in entities.REFERRING_ENTITIES:
        for obj in config.get(ent, []):
            if (kind, name) in references(ent, obj):
                out.append(f"{tr(entities.LABELS[ent])} „{entities.oname(obj)}“")
    return out


def _check_backup_settings(d: dict) -> None:
    """SFOS lehnt unvollständige Sicherungsziele erst beim Ausrollen ab – schon im Entwurf prüfen."""
    storage = d.get("backupStorage")
    if storage not in ("local", "ftp", "email"):
        raise HTTPException(400, tr('Sicherungsziel muss lokal, FTP oder E-Mail sein'))
    ftp = d.get("ftp") or {}
    if storage == "ftp" and not (ftp.get("server") and ftp.get("username")):
        raise HTTPException(400, tr('Für FTP-Sicherungen sind Server und Benutzer nötig'))
    if storage == "email" and not d.get("emailRecipients"):
        raise HTTPException(400, tr('Für Sicherungen per E-Mail ist mindestens ein Empfänger nötig'))
    sc = d.get("schedule") or {}
    if sc.get("frequency") not in ("never", "daily", "weekly", "monthly"):
        raise HTTPException(400, tr('Ungültige Häufigkeit der Sicherung'))
    if sc.get("frequency") == "weekly" and not sc.get("dayOfWeek"):
        raise HTTPException(400, tr('Wöchentliche Sicherung braucht einen Wochentag'))
    if sc.get("frequency") == "monthly" and not sc.get("dayOfMonth"):
        raise HTTPException(400, tr('Monatliche Sicherung braucht einen Tag im Monat'))


def validate_operation(fw: Firewall, op: dict, config: dict[str, list[dict]]) -> dict:
    entity, action, name = op.get("entity"), op.get("action"), (op.get("name") or "").strip()
    if entity not in entities.names(entities.fmt_for(fw.connector)):
        raise HTTPException(400, tr('Entität {0} passt nicht zur Anbindung dieser Firewall', entity))
    if entity in entities.REST_READ_ONLY_ENTITIES:
        raise HTTPException(400, tr('{0} werden auf der Firewall gepflegt, nicht über dieses Tool', tr(entities.LABELS[entity])))
    if action not in ("add", "update", "remove"):
        raise HTTPException(400, tr('Aktion muss add, update oder remove sein'))
    if entity in entities.REST_SINGLETONS and action != "update":
        raise HTTPException(400, tr('{0} kann nur geändert, nicht angelegt oder gelöscht werden', tr(entities.LABELS[entity])))
    if not name:
        raise HTTPException(400, tr('Name fehlt'))
    if action == "remove" and not connector.capabilities(fw)["remove"]:
        raise HTTPException(400, tr('Löschen ist über Sophos Central nicht möglich – Objekt stattdessen deaktivieren oder die Firewall über die REST-API anbinden'))
    existing = _index(config).get(entity, {})
    if action == "remove" and (existing.get(name) or {}).get("isInternal"):
        raise HTTPException(400, tr('{0} „{1}“ ist ein eingebautes Objekt der Firewall und kann nicht gelöscht werden', tr(entities.LABELS[entity]), name))
    if action == "add" and name in existing:
        raise HTTPException(409, tr('{0} „{1}“ existiert bereits', tr(entities.LABELS[entity]), name))
    if action in ("update", "remove") and name not in existing:
        raise HTTPException(404, tr('{0} „{1}“ existiert nicht (mehr)', tr(entities.LABELS[entity]), name))
    clean = {"entity": entity, "action": action, "name": name}
    if action != "remove":
        data = op.get("data")
        if not isinstance(data, dict):
            raise HTTPException(400, tr('Objektdaten fehlen'))
        drop = ("Position", "After", "Before") + entities.REST_READ_ONLY
        data = {k: v for k, v in data.items() if k not in drop}
        if data.get(entities.name_key(entity)) != name:
            raise HTTPException(400, tr('Umbenennen ist nicht möglich – neues Objekt anlegen und altes löschen'))
        clean["data"] = data
        if entity == "backupSettings":
            _check_backup_settings(data)
        if action == "update" and diff.canonical(data) == diff.canonical(existing[name]) and not op.get("position"):
            raise HTTPException(400, tr('Keine Änderung gegenüber dem aktuellen Stand'))
    if entity in entities.RULE_ENTITIES and op.get("position") and action != "remove":
        pos = op["position"]
        if pos.get("type") not in ("top", "bottom", "after", "before"):
            raise HTTPException(400, tr('Ungültige Position'))
        if pos.get("type") in ("after", "before") and pos.get("ref") == name:
            raise HTTPException(400, tr('Eine Regel kann nicht relativ zu sich selbst positioniert werden'))
        scope = entities.POSITION_SCOPE.get(entity, (entity,))
        if pos.get("type") in ("after", "before") and not any(pos.get("ref") in _index(config).get(e, {}) for e in scope):
            raise HTTPException(400, tr('Bezugsregel „{0}“ für die Position existiert nicht', pos.get('ref')))
        clean["position"] = {"type": pos["type"], **({"ref": pos["ref"]} if pos.get("ref") else {})}
    elif entity in entities.RULE_ENTITIES and action == "add":
        clean["position"] = {"type": "bottom"}
    return clean


def merge_operation(ops: list[dict], new: dict) -> list[dict]:
    """Operation in den Entwurf übernehmen; mehrfache Änderungen desselben Objekts werden zusammengefasst."""
    key = (new["entity"], new["name"])
    prev = next((o for o in ops if (o["entity"], o["name"]) == key), None)
    rest = [o for o in ops if (o["entity"], o["name"]) != key]
    if prev is None:
        return rest + [new]
    if prev["action"] == "add":
        if new["action"] == "remove":
            return rest                       # angelegt und wieder gelöscht → nichts zu tun
        return rest + [{**new, "action": "add", "position": new.get("position") or prev.get("position")}]
    if prev["action"] == "remove" and new["action"] == "add":
        return rest + [{**new, "action": "update"}]
    return rest + [new]


def with_before(ops: list[dict], config: dict[str, list[dict]]) -> list[dict]:
    """Stand vor der Änderung festhalten – Grundlage für Drift-Prüfung, Anzeige und Rücknahme."""
    idx = _index(config)
    out = []
    for o in ops:
        o = {k: v for k, v in o.items() if k not in ("before", "before_position")}
        if o["action"] in ("update", "remove"):
            o["before"] = idx.get(o["entity"], {}).get(o["name"])
            if o["entity"] in entities.RULE_ENTITIES:
                o["before_position"] = rule_position(config, o["name"], o["entity"])
        out.append(o)
    return out


def draft_add(db: DbSession, user: User, fw: Firewall, op: dict) -> tuple[ChangeRequest, list[str]]:
    config = sync.cached_config(db, fw)
    cr = get_draft(db, user, fw, create=True)
    # gegen den Stand *mit* den bisherigen Entwurfsänderungen prüfen
    working = effective_config(config, cr.operations or [])
    clean = validate_operation(fw, op, working)
    if clean["action"] == "remove":
        users = [u for u in used_by(working, clean["entity"], clean["name"])]
        if users:
            raise HTTPException(409, tr('Wird noch verwendet von: {0}', ', '.join(users)))
    ops = merge_operation(list(cr.operations or []), clean)
    cr.operations = with_before(ops, config)
    warnings = check_references(effective_config(config, cr.operations))
    event(db, cr, "draft_changed", f"{clean['action']} {clean['entity']} „{clean['name']}“", user)
    db.commit()
    return cr, warnings


def draft_remove(db: DbSession, user: User, cr: ChangeRequest, index: int) -> None:
    ops = list(cr.operations or [])
    if not 0 <= index < len(ops):
        raise HTTPException(404, tr('Operation nicht gefunden'))
    removed = ops.pop(index)
    cr.operations = ops
    event(db, cr, "draft_changed", tr('entfernt: {0} {1} „{2}“', removed['action'], removed['entity'], removed['name']), user)
    db.commit()


# --- Workflow ------------------------------------------------------------------------------------------------

def check_expiry(db: DbSession, expires_at, deploy_after) -> None:
    if expires_at is None:
        return
    start = deploy_after or utcnow()
    if expires_at <= start + timedelta(minutes=5):
        raise HTTPException(400, tr('Die Befristung muss mindestens 5 Minuten nach dem Ausrollen enden'))
    max_days = int(settings.get(db, "temp_max_days"))
    if max_days and expires_at > start + timedelta(days=max_days):
        raise HTTPException(400, tr('Befristung höchstens {0} Tage', max_days))


def submit(db: DbSession, user: User, cr: ChangeRequest, *, title: str, justification: str, ticket_ref: str,
           deploy_after, ip: str, expires_at=None, extra_firewall_ids: list[str] | None = None) -> list[ChangeRequest]:
    """Einreichen; mit extra_firewall_ids als Sammelantrag (gleiche Änderungen auf weiteren Firewalls)."""
    extra = _prepare_batch(db, user, cr, extra_firewall_ids or [])
    if extra:
        cr.batch_id = new_id()
    _submit_one(db, user, cr, title=title, justification=justification, ticket_ref=ticket_ref,
                deploy_after=deploy_after, ip=ip, expires_at=expires_at, announce=not extra)
    if not extra:
        return [cr]
    batch_id = cr.batch_id
    out = [cr]
    for fw, ops in extra:
        sib = ChangeRequest(number=next_number(db), firewall_id=fw.id, created_by=user.id, status="draft",
                            operations=ops, batch_id=batch_id)
        db.add(sib)
        db.flush()
        event(db, sib, "created", tr('Sammelantrag mit CR-{0:04d}', cr.number), user)
        _submit_one(db, user, sib, title=title, justification=justification, ticket_ref=ticket_ref,
                    deploy_after=deploy_after, ip=ip, expires_at=expires_at, announce=False)
        out.append(sib)
    db.commit()
    notify.change_event(cr.id, "pending")
    return out


def _prepare_batch(db: DbSession, user: User, cr: ChangeRequest, firewall_ids: list[str]):
    """Alles vorab prüfen (alles oder nichts): Rechte, gleiches Format, Operationen passen zur Ziel-Firewall."""
    out = []
    fmt = entities.fmt_for(cr.firewall.connector)
    for fid in dict.fromkeys(firewall_ids):
        if fid == cr.firewall_id:
            continue
        fw = db.get(Firewall, fid)
        if not fw or fw.archived or not permissions.can(db, user, "change.create", fw):
            raise HTTPException(403, tr('Keine Berechtigung für eine der ausgewählten Firewalls'))
        if entities.fmt_for(fw.connector) != fmt:
            raise HTTPException(400, tr('„{0}“ nutzt ein anderes Format (REST/XML) – nicht im selben Antrag möglich', fw.name))
        if not fw.last_sync_at:
            raise HTTPException(409, tr('„{0}“ wurde noch nie synchronisiert', fw.name))
        config = sync.cached_config(db, fw)
        working, clean = config, []
        for o in cr.operations or []:
            base = {k: v for k, v in o.items() if k not in ("before", "before_position")}
            try:
                c = validate_operation(fw, base, working)
            except HTTPException as e:
                raise HTTPException(e.status_code, f"„{fw.name}“: {e.detail}")
            clean.append(c)
            working = effective_config(working, [c])
        out.append((fw, with_before(clean, config)))
    return out


def _submit_one(db: DbSession, user: User, cr: ChangeRequest, *, title: str, justification: str, ticket_ref: str,
                deploy_after, ip: str, expires_at=None, announce: bool = True) -> None:
    if cr.status != "draft" or cr.created_by != user.id:
        raise HTTPException(409, tr('Nur eigene Entwürfe können eingereicht werden'))
    if not cr.operations:
        raise HTTPException(400, tr('Der Entwurf enthält keine Änderungen'))
    if not title.strip() or not justification.strip():
        raise HTTPException(400, tr('Titel und Begründung sind Pflichtfelder'))
    if settings.get(db, "require_ticket") and not ticket_ref.strip():
        raise HTTPException(400, tr('Ticket-Referenz ist Pflicht'))
    fw = cr.firewall
    if not permissions.can(db, user, "change.create", fw):
        raise HTTPException(403, tr('Keine Berechtigung, Änderungen für diese Firewall zu beantragen'))
    config = sync.cached_config(db, fw)
    # Gegen den aktuellen Cache neu prüfen (die Konfiguration kann sich seit Anlage des Entwurfs geändert haben)
    working = config
    for o in cr.operations:
        validate_operation(fw, o, working)
        working = effective_config(working, [o])
    cr.operations = with_before(cr.operations, config)
    cr.title, cr.justification, cr.ticket_ref = title.strip(), justification.strip(), ticket_ref.strip()
    check_expiry(db, expires_at, deploy_after)
    cr.deploy_after = deploy_after
    cr.expires_at = expires_at
    cr.required_approvals = int(settings.get(db, "required_approvals"))
    cr.status = "pending"
    cr.submitted_at = utcnow()
    event(db, cr, "submitted", justification.strip(), user)
    audit(db, "change.submitted", actor=user, target_type="change", target_id=cr.id, ip=ip, details={
        "number": cr.number, "firewall": fw.name, "title": cr.title, "ticket": cr.ticket_ref,
        "operations": [f"{o['action']} {o['entity']} {o['name']}" for o in cr.operations],
        **({"expires_at": expires_at.isoformat()} if expires_at else {}),
        **({"batch": cr.batch_id} if cr.batch_id else {}),
    })
    if announce:
        notify.change_event(cr.id, "pending")


def approvals(cr: ChangeRequest) -> list[ChangeEvent]:
    return [e for e in cr.events if e.kind == "approved"]


def batch_members(db: DbSession, cr: ChangeRequest, states: tuple | None = None) -> list[ChangeRequest]:
    """Alle Anträge eines Sammelantrags (inkl. cr), sonst nur cr."""
    if not cr.batch_id:
        return [cr]
    stmt = select(ChangeRequest).where(ChangeRequest.batch_id == cr.batch_id)
    if states:
        stmt = stmt.where(ChangeRequest.status.in_(states))
    return list(db.execute(stmt.order_by(ChangeRequest.number)).scalars())


def _check_decide(db: DbSession, user: User, cr: ChangeRequest, decision: str, comment: str) -> None:
    if cr.status != "pending":
        raise HTTPException(409, tr('Antrag ist nicht (mehr) offen'))
    if not permissions.can(db, user, "change.approve", cr.firewall):
        raise HTTPException(403, tr('Keine Berechtigung zum Genehmigen für die Firewall „{0}“', cr.firewall.name))
    if cr.created_by == user.id:
        raise HTTPException(403, tr('Vier-Augen-Prinzip: eigene Anträge können nicht genehmigt werden'))
    if any(e.user_id == user.id for e in approvals(cr)):
        raise HTTPException(409, tr('Sie haben diesen Antrag bereits genehmigt'))
    if decision == "reject" and not comment.strip():
        raise HTTPException(400, tr('Bitte eine Begründung für die Ablehnung angeben'))
    if decision not in ("approve", "reject"):
        raise HTTPException(400, tr('Entscheidung muss approve oder reject sein'))


def decide(db: DbSession, user: User, cr: ChangeRequest, decision: str, comment: str, ip: str) -> None:
    """Entscheidung – bei Sammelanträgen für alle offenen Anträge des Sammelantrags (Rechte auf allen nötig)."""
    members = batch_members(db, cr, ("pending",)) if cr.batch_id else [cr]
    if cr not in members:
        members = [cr] + members
    for m in members:
        _check_decide(db, user, m, decision, comment)
    for m in members:
        _decide_one(db, user, m, decision, comment, ip)


def _decide_one(db: DbSession, user: User, cr: ChangeRequest, decision: str, comment: str, ip: str) -> None:
    if decision == "reject":
        cr.status = "rejected"
        cr.decided_at = utcnow()
        event(db, cr, "rejected", comment.strip(), user)
        audit(db, "change.rejected", actor=user, target_type="change", target_id=cr.id, ip=ip,
              details={"number": cr.number, "firewall": cr.firewall.name, "comment": comment.strip(), "via": ip})
        notify.change_event(cr.id, "rejected")
        return
    event(db, cr, "approved", comment.strip(), user)
    db.flush()
    db.refresh(cr)
    count = len({e.user_id for e in approvals(cr)})
    if count >= cr.required_approvals:
        cr.status = "approved"
        cr.decided_at = utcnow()
    audit(db, "change.approved", actor=user, target_type="change", target_id=cr.id, ip=ip, details={
        "number": cr.number, "firewall": cr.firewall.name, "comment": comment.strip(),
        "approvals": f"{count}/{cr.required_approvals}", "fully_approved": cr.status == "approved",
        **({"via": "telegram"} if ip == "telegram" else {}),
    })
    if cr.status == "approved":
        notify.change_event(cr.id, "approved")


def withdraw(db: DbSession, user: User, cr: ChangeRequest, ip: str) -> None:
    """Zurückziehen – bei Sammelanträgen alle noch nicht ausgerollten Anträge."""
    if cr.batch_id and cr.status != "draft":
        members = [m for m in batch_members(db, cr) if m.status in ("pending", "approved")]
        if cr not in members:
            raise HTTPException(409, tr('Antrag kann in diesem Status nicht zurückgezogen werden'))
        for m in members:
            _withdraw_one(db, user, m, ip)
        return
    _withdraw_one(db, user, cr, ip)


def _withdraw_one(db: DbSession, user: User, cr: ChangeRequest, ip: str) -> None:
    if cr.created_by != user.id and not permissions.has_global(db, user, "admin"):
        raise HTTPException(403, tr('Nur der Antragsteller kann den Antrag zurückziehen'))
    if cr.status not in ("draft", "pending", "approved"):
        raise HTTPException(409, tr('Antrag kann in diesem Status nicht zurückgezogen werden'))
    was_draft = cr.status == "draft"
    cr.status = "withdrawn"
    event(db, cr, "withdrawn", "", user)
    if was_draft:
        db.commit()
        return
    audit(db, "change.withdrawn", actor=user, target_type="change", target_id=cr.id, ip=ip,
          details={"number": cr.number, "firewall": cr.firewall.name})


def comment(db: DbSession, user: User, cr: ChangeRequest, text: str) -> None:
    if not text.strip():
        raise HTTPException(400, tr('Kommentar ist leer'))
    event(db, cr, "comment", text.strip(), user)
    audit(db, "change.commented", actor=user, target_type="change", target_id=cr.id,
          details={"number": cr.number, "text": text.strip()})


def can_revert(db: DbSession, user: User, cr: ChangeRequest) -> bool:
    """Rücknahme anstoßen: wer beantragen ODER genehmigen darf (Superadmins immer)."""
    return cr.status == "deployed" and (permissions.can(db, user, "change.create", cr.firewall)
                                        or permissions.can(db, user, "change.approve", cr.firewall))


def revert_operations(cr: ChangeRequest) -> list[dict]:
    """Umkehrung der Operationen eines ausgerollten Antrags (umgekehrte Reihenfolge)."""
    ops = []
    for o in reversed(cr.operations):
        pos = {"position": o["before_position"]} if o.get("before_position") else {}
        if o["action"] == "add":
            ops.append({"entity": o["entity"], "action": "remove", "name": o["name"]})
        elif o["action"] == "update":
            ops.append({"entity": o["entity"], "action": "update", "name": o["name"], "data": o["before"], **pos})
        else:
            ops.append({"entity": o["entity"], "action": "add", "name": o["name"], "data": o["before"], **pos})
    return ops


def active_revert(db: DbSession, cr: ChangeRequest) -> ChangeRequest | None:
    return db.execute(select(ChangeRequest).where(
        ChangeRequest.reverts_id == cr.id,
        ChangeRequest.status.notin_(("rejected", "withdrawn", "failed", "conflict")))).scalar()


def _create_revert(db: DbSession, cr: ChangeRequest, actor: User | None, *, justification: str, ticket_ref: str,
                   deploy_after, ip: str, preapproved: bool = False) -> ChangeRequest:
    existing = active_revert(db, cr)
    if existing:
        raise HTTPException(409, tr('Für diesen Antrag gibt es bereits die Rücknahme CR-{0:04d}', existing.number))
    fw = cr.firewall
    config = sync.cached_config(db, fw)
    working, clean_ops = config, []
    for o in revert_operations(cr):
        try:
            c = validate_operation(fw, o, working)
        except HTTPException as e:
            raise HTTPException(409, tr('Rücknahme nicht möglich – die Konfiguration hat sich seitdem geändert: {0}', e.detail))
        clean_ops.append(c)
        working = effective_config(working, [c])
    title = tr('Rücknahme von CR-{0:04d}: {1}', cr.number, cr.title)[:300]
    rev = ChangeRequest(number=next_number(db), firewall_id=fw.id, created_by=actor.id if actor else None,
                        status="approved" if preapproved else "pending", title=title,
                        justification=justification.strip(), ticket_ref=ticket_ref.strip(),
                        deploy_after=deploy_after, reverts_id=cr.id, submitted_at=utcnow(),
                        decided_at=utcnow() if preapproved else None,
                        required_approvals=int(settings.get(db, "required_approvals")),
                        operations=with_before(clean_ops, config))
    db.add(rev)
    db.flush()
    event(db, rev, "submitted", justification.strip(), actor)
    if preapproved:
        event(db, rev, "preapproved", tr('Befristung wurde mit CR-{0:04d} genehmigt ({1})', cr.number, ', '.join(e.actor_name for e in approvals(cr))))
    event(db, cr, "comment", tr('Rücknahme {0}beantragt: CR-{1:04d}', 'automatisch ' if actor is None else '', rev.number), actor)
    audit(db, "change.revert_submitted", actor=actor, target_type="change", target_id=rev.id, ip=ip, details={
        "number": rev.number, "reverts": cr.number, "firewall": fw.name, "justification": justification.strip(),
        "automatic": actor is None, "preapproved": preapproved,
        "operations": [f"{o['action']} {o['entity']} {o['name']}" for o in rev.operations],
    })
    if not preapproved:
        notify.change_event(rev.id, "pending")
    return rev


def submit_revert(db: DbSession, user: User, cr: ChangeRequest, *, justification: str, ticket_ref: str,
                  deploy_after, ip: str) -> ChangeRequest:
    """Rücknahme eines ausgerollten Antrags direkt als neuen Antrag einreichen (Vier-Augen-Prinzip gilt weiter:
    wer die Rücknahme stellt, kann sie nicht selbst genehmigen)."""
    if cr.status != "deployed":
        raise HTTPException(409, tr('Nur ausgerollte Anträge können rückgängig gemacht werden'))
    if not can_revert(db, user, cr):
        raise HTTPException(403, tr('Rücknahme erfordert das Recht zum Beantragen oder Genehmigen für diese Firewall'))
    if not justification.strip():
        raise HTTPException(400, tr('Bitte eine Begründung für die Rücknahme angeben'))
    return _create_revert(db, cr, user, justification=justification, ticket_ref=ticket_ref,
                          deploy_after=deploy_after, ip=ip)


def expire(db: DbSession, cr: ChangeRequest) -> ChangeRequest | None:
    """Befristeten, ausgerollten Antrag nach Ablauf zurücknehmen (vom Worker aufgerufen)."""
    if active_revert(db, cr):
        cr.expiry_state = "reverted"          # wurde bereits manuell zurückgenommen
        db.commit()
        return None
    preapproved = bool(settings.get(db, "temp_revert_preapproved"))
    try:
        rev = _create_revert(db, cr, None, justification=tr('Befristung abgelaufen ({0:%d.%m.%Y %H:%M} UTC)', cr.expires_at),
                             ticket_ref=cr.ticket_ref, deploy_after=None, ip="", preapproved=preapproved)
    except HTTPException as e:
        db.rollback()
        cr = db.get(ChangeRequest, cr.id)
        cr.expiry_state = "failed"
        event(db, cr, "expiry_failed", str(e.detail))
        audit(db, "change.expiry_failed", target_type="change", target_id=cr.id,
              details={"number": cr.number, "firewall": cr.firewall.name, "error": str(e.detail)})
        notify.change_event(cr.id, "expiry_failed")
        return None
    cr.expiry_state = "reverted"
    db.commit()
    return rev


# --- Ausrollen -----------------------------------------------------------------------------------------------

def claim_for_deploy(db: DbSession, change_id: str, states=("approved",)) -> bool:
    """Atomarer Statuswechsel → deploying (verhindert doppeltes Ausrollen)."""
    res = db.execute(update(ChangeRequest).where(ChangeRequest.id == change_id, ChangeRequest.status.in_(states))
                     .values(status="deploying"))
    db.commit()
    return res.rowcount == 1


def drift_conflicts(current: dict[str, list[dict]], ops: list[dict]) -> list[str]:
    idx = _index(current)
    problems = []
    for o in ops:
        cur = idx.get(o["entity"], {}).get(o["name"])
        label = f"{tr(entities.LABELS[o['entity']])} „{o['name']}“"
        if o["action"] == "add" and cur is not None:
            problems.append(tr('{0} existiert inzwischen bereits auf der Firewall', label))
        elif o["action"] in ("update", "remove"):
            if cur is None:
                problems.append(tr('{0} existiert nicht mehr auf der Firewall', label))
            elif diff.canonical(cur) != diff.canonical(o.get("before")):
                fields = ", ".join(d["field"] for d in diff.diff_objects(o.get("before"), cur)[:5])
                problems.append(tr('{0} wurde seit dem Einreichen verändert ({1})', label, fields))
    return problems


def deploy(db: DbSession, change_id: str, actor: User | None = None) -> None:
    """Führt einen bereits per claim_for_deploy() übernommenen Antrag aus."""
    with _deploy_lock:
        cr = db.get(ChangeRequest, change_id)
        fw = cr.firewall
        lines: list[dict] = list(cr.deploy_log or [])

        def logline(msg: str) -> None:
            lines.append({"ts": utcnow().isoformat(), "msg": msg})

        logline(tr('Ausrollen gestartet ({0}) über {1}', 'manuell durch ' + actor.username if actor else 'automatisch', connector.capabilities(fw)['label']))
        event(db, cr, "deploy_started", "", actor)
        db.commit()
        try:
            logline(tr('Lese aktuelle Konfiguration zur Drift-Prüfung …'))
            current, _ = connector.fetch_config(db, fw, logline)
            problems = drift_conflicts(current, cr.operations)
            if problems:
                for p in problems:
                    logline(f"KONFLIKT: {p}")
                cr.status, cr.error, cr.deploy_log = "conflict", "; ".join(problems), lines
                event(db, cr, "conflict", "\n".join(problems), actor)
                audit(db, "change.conflict", actor=actor, target_type="change", target_id=cr.id,
                      details={"number": cr.number, "firewall": fw.name, "problems": problems})
                sync.store_config(db, fw, current, reason="sync")
                notify.change_event(cr.id, "conflict")
                return
            logline(tr('Keine Abweichungen – wende Änderungen an …'))
            connector.apply(db, fw, cr.operations, logline)
            logline(tr('Lese Konfiguration nach dem Ausrollen …'))
            try:
                sync.sync_firewall(db, fw, actor=actor, reason="deploy", change_id=cr.id)
                after = _index(sync.cached_config(db, fw))
                for o in cr.operations:
                    present = o["name"] in after.get(o["entity"], {})
                    if present != (o["action"] != "remove"):
                        logline(tr('WARNUNG: {0} „{1}“ – Ergebnis entspricht nicht der Erwartung ({2})', tr(entities.LABELS[o['entity']]), o['name'], o['action']))
            except connector.ConnectorError as e:
                # Änderung ist bereits angewendet – nur die Kontrolle ist gescheitert
                logline(tr('WARNUNG: Kontroll-Synchronisation fehlgeschlagen: {0}', e))
                cr = db.get(ChangeRequest, change_id)
            logline("Fertig.")
            cr.status, cr.error, cr.deployed_at, cr.deploy_log = "deployed", "", utcnow(), lines
            event(db, cr, "deployed", "", actor)
            audit(db, "change.deployed", actor=actor, target_type="change", target_id=cr.id, details={
                "number": cr.number, "firewall": fw.name, "connector": fw.connector,
                "operations": [f"{o['action']} {o['entity']} {o['name']}" for o in cr.operations],
                "approvers": [e.actor_name for e in approvals(cr)],
            })
            notify.change_event(cr.id, "deployed")
        except (connector.DeployError, *connector.ConnectorError) as e:
            db.rollback()
            cr = db.get(ChangeRequest, change_id)
            logline(f"FEHLGESCHLAGEN: {e}")
            cr.status, cr.error, cr.deploy_log = "failed", str(e), lines
            event(db, cr, "failed", str(e), actor)
            audit(db, "change.deploy_failed", actor=actor, target_type="change", target_id=cr.id,
                  details={"number": cr.number, "firewall": cr.firewall.name, "error": str(e)})
            notify.change_event(cr.id, "failed")
        except Exception as e:  # unerwartet: Antrag nicht in „deploying“ hängen lassen
            log.exception("Ausrollen von %s fehlgeschlagen", change_id)
            db.rollback()
            cr = db.get(ChangeRequest, change_id)
            logline(tr('Interner Fehler: {0}', e))
            cr.status, cr.error, cr.deploy_log = "failed", tr('Interner Fehler: {0}', e), lines
            event(db, cr, "failed", str(e), actor)
            audit(db, "change.deploy_failed", actor=actor, target_type="change", target_id=cr.id,
                  details={"number": cr.number, "error": f"intern: {e}"})
            notify.change_event(cr.id, "failed")
