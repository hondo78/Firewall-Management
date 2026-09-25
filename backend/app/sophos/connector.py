"""Einheitlicher Zugriff auf eine Firewall – über Sophos Central (Import/Export) oder die lokale XML-API."""
from typing import Callable

from sqlalchemy.orm import Session as DbSession

from .. import crypto
from ..models import CentralAccount, Firewall
from . import entities, xmlconv
from .central import CentralClient, CentralError
from .xmlapi import XmlApiClient, XmlApiError

ConnectorError = (CentralError, XmlApiError)
Log = Callable[[str], None]


class DeployError(Exception):
    pass


def central_client(acc: CentralAccount) -> CentralClient:
    return CentralClient(acc.id_url, acc.api_url, acc.client_id,
                         crypto.decrypt(acc.client_secret_enc, f"central:{acc.id}"),
                         acc.tenant_id, acc.data_region)


def xml_client(fw: Firewall) -> XmlApiClient:
    password = crypto.decrypt(fw.api_password_enc, f"firewall:{fw.id}") if fw.api_password_enc else ""
    return XmlApiClient(fw.api_url, fw.api_username, password, fw.verify_tls)


def _central_for(db: DbSession, fw: Firewall) -> tuple[CentralClient, str]:
    acc = db.get(CentralAccount, fw.central_account_id) if fw.central_account_id else None
    if not acc or not fw.central_id:
        raise CentralError("Firewall ist keinem Sophos-Central-Konto zugeordnet")
    return central_client(acc), fw.central_id


def capabilities(fw: Firewall) -> dict:
    if fw.connector == "central":
        return {"remove": False, "label": "Sophos Central (Import/Export)"}
    return {"remove": True, "label": "XML-API (direkt)"}


def fetch_config(db: DbSession, fw: Firewall, log: Log | None = None) -> tuple[dict[str, list[dict]], str]:
    """Aktuelle Konfiguration aller verwalteten Entitäten: ({entity: [obj, …]}, api_version)."""
    if fw.connector == "central":
        client, cid = _central_for(db, fw)
        archive = client.export_config(cid, entities.NAMES, log)
        data, version = xmlconv.parse_entities_xml(xmlconv.read_tar_entities(archive), set(entities.NAMES))
        return {e: data.get(e, []) for e in entities.NAMES}, version
    client = xml_client(fw)
    data = client.get_many(entities.NAMES)
    return data, client.api_version


def test_connection(db: DbSession, fw: Firewall) -> str:
    if fw.connector == "central":
        client, cid = _central_for(db, fw)
        ids = {f["id"] for f in client.firewalls()}
        if cid not in ids:
            raise CentralError("Firewall ist im Central-Konto nicht (mehr) vorhanden")
        return "Sophos Central erreichbar, Firewall gefunden"
    version = xml_client(fw).test()
    return f"Anmeldung erfolgreich (API-Version {version or 'unbekannt'})"


def apply(db: DbSession, fw: Firewall, ops: list[dict], log: Log) -> None:
    ordered = entities.order_operations(ops)
    if fw.connector == "central":
        if any(o["action"] == "remove" for o in ordered):
            raise DeployError("Löschen ist über den Sophos-Central-Import nicht möglich")
        client, cid = _central_for(db, fw)
        objs = [(o["entity"], xmlconv.with_position(o["data"], o.get("position"))
                 if o["entity"] == "FirewallRule" else o["data"]) for o in ordered]
        archive = xmlconv.build_tar(xmlconv.build_entities_xml(objs, fw.api_version))
        tx = client.import_config([cid], archive, log)
        items = (tx.get("response") or {}).get("items") or []
        mine = next((i for i in items if i.get("firewallId") == cid), None)
        result = (mine or {}).get("result") or tx.get("result")
        if result != "success":
            raise DeployError(f"Import auf der Firewall fehlgeschlagen (Ergebnis: {result})")
        log("Import erfolgreich abgeschlossen")
        return
    client = xml_client(fw)
    done: list[dict] = []
    for o in ordered:
        try:
            msg = _xml_apply_one(client, o)
        except XmlApiError as e:
            log(f"FEHLER bei {_label(o)}: {e}")
            _rollback(client, done, log)
            raise DeployError(f"{_label(o)}: {e}") from e
        done.append(o)
        log(f"{_label(o)} – {o['action']}: {msg}")


def _label(o: dict) -> str:
    return f"{entities.LABELS.get(o['entity'], o['entity'])} „{o['name']}“"


def _xml_apply_one(client: XmlApiClient, o: dict) -> str:
    if o["action"] == "remove":
        return client.remove(o["entity"], o["name"])
    return client.set(o["entity"], o["data"], "add" if o["action"] == "add" else "update", o.get("position"))


def _rollback(client: XmlApiClient, done: list[dict], log: Log) -> None:
    """Bereits angewendete Operationen rückgängig machen (best effort, umgekehrte Reihenfolge)."""
    if not done:
        return
    log(f"Rolle {len(done)} bereits angewendete Operation(en) zurück …")
    for o in reversed(done):
        try:
            if o["action"] == "add":
                client.remove(o["entity"], o["name"])
            elif o["action"] == "update":
                client.set(o["entity"], o["before"], "update", o.get("before_position"))
            else:
                client.set(o["entity"], o["before"], "add", o.get("before_position"))
            log(f"  zurückgerollt: {_label(o)}")
        except XmlApiError as e:
            log(f"  Rücknahme fehlgeschlagen für {_label(o)}: {e} – bitte manuell prüfen!")
