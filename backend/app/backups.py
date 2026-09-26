"""Sicherungen der Firewall-Konfigurationen: automatisch nach Zeitplan, manuell, Aufbewahrung, Wiederherstellen.

Eine Sicherung ist die vollständige, live von der Firewall gelesene Konfiguration (gzip-JSON in der Datenbank,
optional zusätzlich als Datei in BACKUP_DIR). Wiederherstellen schreibt nichts direkt auf die Firewall: es
erzeugt die nötigen Operationen für den Entwurf – ausgerollt wird wie immer erst nach der Vier-Augen-Freigabe.
"""
import calendar
import gzip
import json
import logging
import os
import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from . import config as appconfig
from . import diff, settings, sync
from .audit import audit
from .models import ChangeRequest, ConfigBackup, Firewall, User, utcnow
from .sophos import connector, entities

log = logging.getLogger("fwm.backups")


# --- Speichern & Lesen ---------------------------------------------------------------------------------------

def pack(fw: Firewall, config: dict[str, list[dict]], created_at: datetime) -> bytes:
    doc = {"firewall": {"id": fw.id, "name": fw.name, "serial": fw.serial, "model": fw.model, "firmware": fw.firmware,
                        "connector": fw.connector},
           "format": entities.fmt_for(fw.connector), "created_at": created_at.isoformat(), "config": config}
    return gzip.compress(json.dumps(doc, ensure_ascii=False, sort_keys=True).encode(), mtime=0)


def unpack(b: ConfigBackup) -> dict:
    return json.loads(gzip.decompress(b.data))


def config_of(b: ConfigBackup) -> dict[str, list[dict]]:
    return unpack(b)["config"]


def _safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_") or "firewall"


def _write_file(fw: Firewall, b: ConfigBackup) -> str:
    local = b.created_at.astimezone(_tz())
    folder = os.path.join(appconfig.BACKUP_DIR, f"{_safe_name(fw.name)}_{fw.id[:8]}")
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{local:%Y-%m-%d_%H%M%S}_{b.trigger}.json.gz")
    with open(path, "wb") as f:
        f.write(b.data)
    return path


def create(db: DbSession, fw: Firewall, *, trigger: str, actor: User | None = None, note: str = "") -> ConfigBackup:
    """Konfiguration live lesen, Cache aktualisieren (erkennt nebenbei Änderungen außerhalb des Tools), sichern."""
    config, version = connector.fetch_config(db, fw)
    if version:
        fw.api_version = version
    sync.store_config(db, fw, config, reason="sync", actor=actor)
    now = utcnow()
    b = ConfigBackup(firewall_id=fw.id, created_at=now, trigger=trigger, created_by=actor.id if actor else None,
                     format=entities.fmt_for(fw.connector), hash=diff.config_hash(config),
                     object_count=sum(len(v) for v in config.values()), note=note.strip()[:300])
    b.data = pack(fw, config, now)
    b.size = len(b.data)
    db.add(b)
    db.flush()
    if settings.get(db, "backup_to_directory"):
        try:
            b.file_path = _write_file(fw, b)
        except OSError as e:
            log.warning("Sicherungsdatei für %s nicht geschrieben: %s", fw.name, e)
    removed = apply_retention(db, fw)
    audit(db, "backup.created", actor=actor, target_type="firewall", target_id=fw.id,
          details={"firewall": fw.name, "backup_id": b.id, "trigger": trigger, "objects": b.object_count,
                   "size": b.size, "file": bool(b.file_path), "retention_removed": removed})
    return b


def apply_retention(db: DbSession, fw: Firewall) -> int:
    """Nur die neuesten N nicht angehefteten Sicherungen behalten (Dateien werden mit entfernt)."""
    keep = int(settings.get(db, "backup_keep"))
    rows = db.execute(select(ConfigBackup).where(ConfigBackup.firewall_id == fw.id, ConfigBackup.pinned.is_(False))
                      .order_by(ConfigBackup.created_at.desc())).scalars().all()
    for b in rows[keep:]:
        remove_file(b)
        db.delete(b)
    return max(0, len(rows) - keep)


def remove_file(b: ConfigBackup) -> None:
    if b.file_path:
        try:
            os.remove(b.file_path)
        except OSError:
            pass


# --- Zeitplan ------------------------------------------------------------------------------------------------

def _tz() -> ZoneInfo:
    try:
        return ZoneInfo(appconfig.TIMEZONE)
    except Exception:  # noqa: BLE001 – unbekannte Zeitzone → UTC
        return ZoneInfo("UTC")


def last_slot(s: dict, now: datetime) -> datetime:
    """Letzter geplanter Zeitpunkt ≤ now (als aware datetime in der Ortszeit)."""
    local = now.astimezone(_tz())
    hh, mm = (int(x) for x in s["backup_time"].split(":"))
    at = local.replace(hour=hh, minute=mm, second=0, microsecond=0)
    freq = s["backup_frequency"]
    if freq == "weekly":
        at -= timedelta(days=(at.weekday() - int(s["backup_weekday"])) % 7)
        return at if at <= local else at - timedelta(days=7)
    if freq == "monthly":
        def in_month(y: int, m: int) -> datetime:
            day = min(int(s["backup_monthday"]), calendar.monthrange(y, m)[1])
            return at.replace(year=y, month=m, day=day)
        cand = in_month(at.year, at.month)
        if cand <= local:
            return cand
        y, m = (at.year, at.month - 1) if at.month > 1 else (at.year - 1, 12)
        return in_month(y, m)
    return at if at <= local else at - timedelta(days=1)


def next_slot(s: dict, now: datetime) -> datetime:
    probe = now
    for _ in range(40):
        probe = probe + timedelta(days=1)
        slot = last_slot(s, probe)
        if slot > now.astimezone(_tz()):
            return slot
    return probe


def due_firewalls(db: DbSession, now: datetime | None = None) -> list[str]:
    """Firewalls, deren letzte automatische Sicherung vor dem letzten geplanten Zeitpunkt liegt."""
    s = settings.get_all(db)
    if not s["backup_enabled"]:
        return []
    now = now or utcnow()
    slot = last_slot(s, now)
    busy = set(db.execute(select(ChangeRequest.firewall_id).where(ChangeRequest.status == "deploying")).scalars())
    out = []
    for fw in db.execute(select(Firewall).where(Firewall.archived.is_(False))).scalars():
        if fw.id in busy or not fw.last_sync_at:
            continue  # noch nie erfolgreich verbunden → erst Anbindung klären
        last = db.execute(select(ConfigBackup.created_at).where(
            ConfigBackup.firewall_id == fw.id, ConfigBackup.trigger == "scheduled")
            .order_by(ConfigBackup.created_at.desc()).limit(1)).scalar()
        if last is None or last < slot:
            out.append(fw.id)
    return out


# --- Wiederherstellen ----------------------------------------------------------------------------------------

def restore_review(current: dict[str, list[dict]], backup: dict[str, list[dict]], fmt: str) -> list[dict]:
    """Unterschiede Sicherung ↔ aktueller Stand als Auswahlliste (gleiches Format wie die Import-Prüfung).

    new = nur in der Sicherung (wird angelegt), changed = abweichend (wird auf den Stand der Sicherung gesetzt),
    removed = nur aktuell vorhanden (wird gelöscht, nur wenn ausdrücklich ausgewählt).
    """
    items = []
    read_only = entities.REST_READ_ONLY_ENTITIES if fmt == "rest" else set()
    for entity in entities.names(fmt):
        if entity in read_only:
            continue
        cur = {entities.oname(o): o for o in current.get(entity, [])}
        old = {entities.oname(o): o for o in backup.get(entity, [])}
        label = entities.LABELS.get(entity, entity)
        for name, o in old.items():
            if name not in cur:
                items.append({"entity": entity, "label": label, "name": name, "status": "new", "diff": [], "data": o})
            elif diff.canonical(cur[name]) != diff.canonical(o):
                items.append({"entity": entity, "label": label, "name": name, "status": "changed",
                              "diff": diff.diff_objects(cur[name], o), "data": o})
        for name, o in cur.items():
            if name not in old and entity not in entities.REST_SINGLETONS and not o.get("isInternal"):
                items.append({"entity": entity, "label": label, "name": name, "status": "removed", "diff": [], "data": o})
    return items


def restore_operations(items: list[dict], keys: set[str], backup: dict[str, list[dict]],
                       current: dict[str, list[dict]]) -> list[dict]:
    """Ausgewählte Einträge → Operationen; neue Regeln an ihre Position aus der Sicherung (nach dem nächsten
    Vorgänger, der aktuell existiert oder ebenfalls wiederhergestellt wird)."""
    chosen_new = {(it["entity"], it["name"]) for i, it in enumerate(items) if str(i) in keys and it["status"] == "new"}
    ops = []
    for i, it in enumerate(items):
        if str(i) not in keys:
            continue
        e, name = it["entity"], it["name"]
        if it["status"] == "removed":
            ops.append({"entity": e, "action": "remove", "name": name})
            continue
        op = {"entity": e, "action": "add" if it["status"] == "new" else "update", "name": name, "data": it["data"]}
        if it["status"] == "new" and e in entities.RULE_ENTITIES:
            order = [entities.oname(o) for o in backup.get(e, [])]
            present = {entities.oname(o) for o in current.get(e, [])}
            before = [n for n in order[:order.index(name)] if n in present or (e, n) in chosen_new]
            op["position"] = {"type": "after", "ref": before[-1]} if before else {"type": "top"}
        ops.append(op)
    rank = {e: n for n, e in enumerate(entities.WRITE_ORDER)}
    # Anlegen/Ändern in Abhängigkeitsreihenfolge, Löschen zuletzt (Regeln vor Objekten)
    keep = sorted([o for o in ops if o["action"] != "remove"], key=lambda o: rank.get(o["entity"], 100))
    drop = sorted([o for o in ops if o["action"] == "remove"], key=lambda o: -rank.get(o["entity"], 100))
    return keep + drop
