"""Vorlagen: Soll-Zustand je Firewall planen und als (Sammel-)Antrag einreichen.

Ein Eintrag der Vorlage: {entity, name, action: "ensure" | "remove", data, position?}
- ensure: fehlt → anlegen; abweichend → ändern (Felder der Vorlage überschreiben, übrige Felder der Firewall bleiben);
  gleich → nichts zu tun
- remove: vorhanden → löschen; fehlt → nichts zu tun
Ausgerollt wird nie direkt: es entsteht ein Antrag, der das Vier-Augen-Prinzip durchläuft.
"""
from fastapi import HTTPException
from sqlalchemy.orm import Session as DbSession

from . import changes, diff, notify, sync
from .i18n import tr
from .models import ChangeRequest, ChangeTemplate, Firewall, User, new_id
from .sophos import entities

WRITE_ONLY = ("Position", "After", "Before")


def normalize_items(ops: list[dict]) -> list[dict]:
    """Einträge vereinheitlichen (ältere Vorlagen speicherten Operationen add/update/remove)."""
    out = []
    for o in ops or []:
        action = "remove" if o.get("action") == "remove" else "ensure"
        item = {"entity": o["entity"], "name": o["name"], "action": action}
        if action == "ensure":
            item["data"] = clean_data(o.get("data") or {})
        if o.get("position") and o["entity"] in entities.RULE_ENTITIES:
            item["position"] = o["position"]
        out.append(item)
    return out


def clean_data(data: dict) -> dict:
    return {k: v for k, v in data.items() if k not in WRITE_ONLY + entities.REST_READ_ONLY}


def _label(item: dict) -> str:
    return f"{tr(entities.LABELS.get(item['entity'], item['entity']))} „{item['name']}“"


def validate_items(fmt: str, items: list[dict]) -> None:
    names = set(entities.names(fmt))
    seen = set()
    for it in items:
        if it.get("entity") not in names:
            raise HTTPException(400, tr('Objekttyp {0} passt nicht zum Format der Vorlage', it.get("entity")))
        if it["entity"] in entities.REST_READ_ONLY_ENTITIES:
            raise HTTPException(400, tr('{0} werden auf der Firewall gepflegt, nicht über dieses Tool', tr(entities.LABELS[it["entity"]])))
        if not (it.get("name") or "").strip():
            raise HTTPException(400, tr('Name fehlt'))
        if it.get("action") not in ("ensure", "remove"):
            raise HTTPException(400, tr('Aktion muss „anlegen/angleichen“ oder „entfernen“ sein'))
        if it["action"] == "ensure":
            data = it.get("data")
            if not isinstance(data, dict):
                raise HTTPException(400, tr('Objektdaten fehlen'))
            if data.get(entities.name_key(it["entity"])) != it["name"]:
                raise HTTPException(400, tr('{0}: Name in den Daten weicht ab', _label(it)))
        if it["entity"] in entities.REST_SINGLETONS and it["action"] == "remove":
            raise HTTPException(400, tr('{0} kann nur geändert, nicht angelegt oder gelöscht werden', tr(entities.LABELS[it["entity"]])))
        key = (it["entity"], it["name"])
        if key in seen:
            raise HTTPException(400, tr('{0} ist doppelt in der Vorlage', _label(it)))
        seen.add(key)


def plan(fw: Firewall, config: dict[str, list[dict]], items: list[dict]) -> dict:
    """Was die Vorlage auf dieser Firewall ändern würde: Operationen, Zeilen für die Vorschau, Fehler, Warnungen."""
    idx = changes._index(config)
    working = config
    ops, rows, errors = [], [], []
    for it in items:
        e, name = it["entity"], it["name"]
        row = {"entity": e, "name": name, "label": entities.LABELS.get(e, e), "status": "same", "diff": [], "note": ""}
        current = idx.get(e, {}).get(name)
        op = None
        if it["action"] == "remove":
            if current is None:
                row["status"] = "absent"
            else:
                op = {"entity": e, "action": "remove", "name": name}
                row["status"] = "remove"
        elif current is None:
            if e in entities.REST_SINGLETONS:
                row["status"], row["note"] = "error", tr('Einstellung auf dieser Firewall nicht verfügbar')
                errors.append(f"{_label(it)}: {row['note']}")
            else:
                op = {"entity": e, "action": "add", "name": name, "data": it["data"]}
                if e in entities.RULE_ENTITIES:
                    pos = it.get("position") or {"type": "bottom"}
                    scope = entities.POSITION_SCOPE.get(e, (e,))
                    if pos.get("type") in ("after", "before") and not any(
                            pos.get("ref") in changes._index(working).get(s, {}) for s in scope):
                        row["note"] = tr('Bezugsregel „{0}“ fehlt hier – Regel wird unten angefügt', pos.get("ref"))
                        pos = {"type": "bottom"}
                    op["position"] = pos
                row["status"] = "add"
        else:
            merged = {**current, **it["data"]}
            if diff.canonical(merged) != diff.canonical(current):
                op = {"entity": e, "action": "update", "name": name, "data": merged}
                row["status"], row["diff"] = "update", diff.diff_objects(current, merged)
        if op is not None:
            try:
                clean = changes.validate_operation(fw, op, working)
            except HTTPException as ex:
                row["status"], row["note"] = "error", str(ex.detail)
                errors.append(f"{_label(it)}: {ex.detail}")
            else:
                ops.append(clean)
                working = changes.effective_config(working, [clean])
        rows.append(row)
    # Nur Verweis-Warnungen, die durch die Vorlage neu entstehen (bestehende Altlasten nicht melden)
    before = set(changes.check_references(config))
    warnings = [w for w in changes.check_references(working) if w not in before]
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in ("add", "update", "remove", "same", "absent", "error")}
    return {"ops": ops, "rows": rows, "errors": errors, "warnings": warnings, "counts": counts}


def preview(db: DbSession, user: User, t: ChangeTemplate, firewalls: list[Firewall]) -> list[dict]:
    items = normalize_items(t.operations)
    out = []
    for fw in firewalls:
        entry = {"firewall_id": fw.id, "firewall": fw.name}
        if entities.fmt_for(fw.connector) != t.format:
            entry.update(errors=[tr('Die Vorlage passt nicht zum Format (REST/XML) dieser Firewall')], rows=[], warnings=[], counts={})
        elif not fw.last_sync_at:
            entry.update(errors=[tr('„{0}“ wurde noch nie synchronisiert', fw.name)], rows=[], warnings=[], counts={})
        else:
            p = plan(fw, sync.cached_config(db, fw), items)
            entry.update({k: v for k, v in p.items() if k != "ops"}, changes=len(p["ops"]))
        out.append(entry)
    return out


def push(db: DbSession, user: User, t: ChangeTemplate, firewalls: list[Firewall], *, title: str, justification: str,
         ticket_ref: str, deploy_after, expires_at, ip: str) -> dict:
    """Je Firewall mit Änderungen einen Antrag einreichen (mehrere = Sammelantrag). Alles oder nichts."""
    items = normalize_items(t.operations)
    planned, unchanged = [], []
    for fw in firewalls:
        if entities.fmt_for(fw.connector) != t.format:
            raise HTTPException(400, tr('„{0}“: {1}', fw.name, tr('Die Vorlage passt nicht zum Format (REST/XML) dieser Firewall')))
        if not fw.last_sync_at:
            raise HTTPException(409, tr('„{0}“ wurde noch nie synchronisiert', fw.name))
        p = plan(fw, sync.cached_config(db, fw), items)
        if p["errors"]:
            raise HTTPException(409, tr('„{0}“: {1}', fw.name, "; ".join(p["errors"])))
        if p["ops"]:
            planned.append((fw, p["ops"]))
        else:
            unchanged.append(fw.name)
    if not planned:
        raise HTTPException(409, tr('Alle ausgewählten Firewalls entsprechen bereits der Vorlage'))
    batch_id = new_id() if len(planned) > 1 else None
    created = []
    for fw, ops in planned:
        cr = ChangeRequest(number=changes.next_number(db), firewall_id=fw.id, created_by=user.id, status="draft",
                           operations=ops, batch_id=batch_id, template_id=t.id, template_version=t.version)
        db.add(cr)
        db.flush()
        changes.event(db, cr, "created", tr('Aus Vorlage „{0}“ (Version {1})', t.name, t.version), user)
        changes._submit_one(db, user, cr, title=title, justification=justification, ticket_ref=ticket_ref,
                            deploy_after=deploy_after, ip=ip, expires_at=expires_at, announce=False)
        created.append(cr)
    db.commit()
    notify.change_event(created[0].id, "pending")
    return {"changes": [{"id": c.id, "number": c.number, "firewall": c.firewall.name, "operations": len(c.operations)}
                        for c in created], "unchanged": unchanged}
