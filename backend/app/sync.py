"""Synchronisation: Firewall-Konfiguration einlesen (Cache + Versionsstände) und Inventar aus Sophos Central."""
import logging

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from . import crypto, diff
from .audit import audit
from .models import (CentralAccount, ConfigObject, ConfigSnapshot, Firewall, FirewallGroup, User, utcnow)
from .sophos import connector
from .sophos.central import CentralError, normalize_status
from .sophos import entities

log = logging.getLogger("fwm.sync")


def cached_config(db: DbSession, fw: Firewall) -> dict[str, list[dict]]:
    rows = db.execute(select(ConfigObject).where(ConfigObject.firewall_id == fw.id)
                      .order_by(ConfigObject.entity, ConfigObject.position)).scalars()
    out: dict[str, list[dict]] = {e: [] for e in entities.names(entities.fmt_for(fw.connector))}
    for r in rows:
        out.setdefault(r.entity, []).append(r.data)
    return out


def latest_snapshot(db: DbSession, fw: Firewall) -> ConfigSnapshot | None:
    return db.execute(select(ConfigSnapshot).where(ConfigSnapshot.firewall_id == fw.id)
                      .order_by(ConfigSnapshot.created_at.desc()).limit(1)).scalar()


def store_config(db: DbSession, fw: Firewall, config: dict[str, list[dict]], *, reason: str,
                 change_id: str | None = None, actor: User | None = None) -> dict:
    """Cache ersetzen und bei inhaltlicher Änderung einen neuen Versionsstand anlegen."""
    new_hash = diff.config_hash(config)
    db.execute(delete(ConfigObject).where(ConfigObject.firewall_id == fw.id))
    for entity, objs in config.items():
        for pos, obj in enumerate(objs):
            db.add(ConfigObject(firewall_id=fw.id, entity=entity, name=entities.oname(obj), position=pos, data=obj))
    fw.last_sync_at = utcnow()
    fw.last_sync_error = ""
    result = {"changed": False, "summary": {}}
    if new_hash != fw.config_hash:
        prev = latest_snapshot(db, fw)
        summary = diff.summarize(diff.compare_configs(prev.data, config)) if prev else {}
        kind = reason if prev else "initial"
        db.add(ConfigSnapshot(firewall_id=fw.id, hash=new_hash, reason=kind, change_id=change_id,
                              summary=summary, data=config))
        fw.config_hash = new_hash
        result = {"changed": True, "summary": summary}
        if prev and reason == "sync":
            # Änderung, die nicht über dieses Tool kam (z. B. direkt in der Web-Oberfläche der Firewall)
            audit(db, "config.drift_detected", actor=actor, target_type="firewall", target_id=fw.id,
                  details={"firewall": fw.name, "summary": summary}, commit=False)
    db.commit()
    return result


def sync_firewall(db: DbSession, fw: Firewall, *, actor: User | None = None, reason: str = "sync",
                  change_id: str | None = None) -> dict:
    try:
        config, version = connector.fetch_config(db, fw)
    except connector.ConnectorError as e:
        msg = str(e)
        if msg != fw.last_sync_error:
            audit(db, "firewall.sync_failed", actor=actor, target_type="firewall", target_id=fw.id,
                  details={"firewall": fw.name, "error": msg}, commit=False)
        fw.last_sync_error = msg
        db.commit()
        raise
    if version:
        fw.api_version = version
    result = store_config(db, fw, config, reason=reason, change_id=change_id, actor=actor)
    log.info("Firewall %s synchronisiert (geändert: %s)", fw.name, result["changed"])
    return result


# --- Sophos Central: Konto prüfen und Inventar übernehmen ----------------------------------------------------

def resolve_account(acc: CentralAccount) -> list[dict]:
    """whoami ausführen; bei Tenant-Konten Region übernehmen. Liefert bei Partner/Organisation die Tenants."""
    client = connector.central_client(acc)
    who = client.whoami()
    acc.id_type = who.get("idType", "")
    acc.principal_id = who.get("id", "")
    if acc.id_type == "tenant":
        acc.tenant_id = acc.principal_id
        acc.data_region = (who.get("apiHosts") or {}).get("dataRegion", "")
        return []
    tenants = client.tenants(acc.id_type, acc.principal_id)
    if acc.tenant_id:
        match = next((t for t in tenants if t.get("id") == acc.tenant_id), None)
        if match:
            acc.data_region = match.get("apiHost", acc.data_region)
    return [{"id": t.get("id"), "name": t.get("showAs") or t.get("name"), "apiHost": t.get("apiHost")}
            for t in tenants]


def sync_central_inventory(db: DbSession, acc: CentralAccount, actor: User | None = None) -> dict:
    """Gruppen und Firewalls aus Central übernehmen/aktualisieren. Neue Firewalls nutzen den Central-Connector."""
    try:
        resolve_account(acc)
        client = connector.central_client(acc)
        groups = client.groups()
        fws = client.firewalls()
    except CentralError as e:
        acc.last_error = str(e)
        db.commit()
        raise
    by_central = {g.central_id: g for g in db.execute(
        select(FirewallGroup).where(FirewallGroup.central_account_id == acc.id)).scalars()}
    names = {g["id"]: g["name"] for g in groups}

    def full_name(g: dict) -> str:
        # Verschachtelte Central-Gruppen als Pfad anzeigen („Filialen › Nord“)
        parts, seen, cur = [g["name"]], {g["id"]}, g
        while (cur.get("parentGroup") or {}).get("id") in names and cur["parentGroup"]["id"] not in seen:
            pid = cur["parentGroup"]["id"]
            seen.add(pid)
            parts.insert(0, names[pid])
            cur = next((x for x in groups if x["id"] == pid), {})
        return " › ".join(parts)

    for g in groups:
        grp = by_central.get(g["id"])
        if not grp:
            grp = FirewallGroup(name=full_name(g), central_account_id=acc.id, central_id=g["id"])
            db.add(grp)
            db.flush()
            by_central[g["id"]] = grp
        grp.name = full_name(g)
    existing = {f.central_id: f for f in db.execute(
        select(Firewall).where(Firewall.central_account_id == acc.id)).scalars()}
    created = []
    for f in fws:
        fw = existing.get(f["id"])
        if fw is not None and fw.archived:
            continue  # bewusst aus der Verwaltung entfernt – nicht automatisch wieder aufnehmen
        if not fw:
            fw = Firewall(name=f.get("name") or f.get("hostname") or f.get("serialNumber"), connector="central",
                          central_account_id=acc.id, central_id=f["id"])
            db.add(fw)
            created.append(fw)
        fw.hostname = f.get("hostname", "")
        fw.serial = f.get("serialNumber", "")
        fw.model = f.get("model", "")
        fw.firmware = f.get("firmwareVersion", "")
        fw.external_ips = f.get("externalIpv4Addresses") or []
        fw.central_status = {**normalize_status(f.get("status")), "cluster": f.get("cluster"),
                             "capabilities": f.get("capabilities") or [], "geoLocation": f.get("geoLocation")}
        cg = (f.get("group") or {}).get("id")
        if cg and cg in by_central:
            fw.group_id = by_central[cg].id
    acc.last_sync_at = utcnow()
    acc.last_error = ""
    db.flush()
    audit(db, "central.inventory_synced", actor=actor, target_type="central_account", target_id=acc.id,
          details={"account": acc.name, "firewalls": len(fws), "groups": len(groups),
                   "new_firewalls": [f.name for f in created]})
    return {"firewalls": len(fws), "groups": len(groups), "created": len(created)}


def encrypt_firewall_password(fw: Firewall, password: str) -> None:
    fw.api_password_enc = crypto.encrypt(password, f"firewall:{fw.id}") if password else ""
