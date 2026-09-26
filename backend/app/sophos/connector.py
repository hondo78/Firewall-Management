"""Einheitlicher Zugriff auf eine Firewall.

Connectoren: "rest" (SFOS REST-API, empfohlen), "central" (Sophos Central Import/Export), "xmlapi" (alte XML-API).
"rest" arbeitet im REST-Format (entities.REST_RESOURCES), die beiden anderen im XML-Format.
"""
from typing import Callable

from sqlalchemy.orm import Session as DbSession

from .. import crypto
from ..models import CentralAccount, Firewall
from . import entities, xmlconv
from .central import CentralClient, CentralError
from .restapi import RestApiClient, RestApiError, patch_body
from .xmlapi import XmlApiClient, XmlApiError

ConnectorError = (CentralError, XmlApiError, RestApiError)
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


def has_waf_xml(fw: Firewall) -> bool:
    return fw.connector == "rest" and bool(fw.xml_username and fw.xml_password_enc)


def waf_xml_client(fw: Firewall) -> XmlApiClient:
    """Zusätzlicher XML-API-Zugang einer REST-Firewall (gleiche Adresse, eigener API-Admin)."""
    password = crypto.decrypt(fw.xml_password_enc, f"firewall-xml:{fw.id}") if fw.xml_password_enc else ""
    return XmlApiClient(fw.api_url, fw.xml_username, password, fw.verify_tls)


def _fetch_waf(db: DbSession, fw: Firewall, log: Log | None) -> list[dict]:
    """WAF-Regeln per XML-API. Bei Fehlern den letzten Stand behalten (sonst sähe es aus, als wären sie gelöscht)."""
    if not has_waf_xml(fw):
        fw.xml_status = ""
        return []
    try:
        rules = waf_xml_client(fw).get("FirewallRule")
    except XmlApiError as e:
        fw.xml_status = f"Fehler: {e}"[:500]
        if log:
            log(f"WAF-Regeln (XML-API): {e} – letzter Stand bleibt erhalten")
        from sqlalchemy import select
        from ..models import ConfigObject
        return list(db.execute(select(ConfigObject.data).where(ConfigObject.firewall_id == fw.id, ConfigObject.entity == "wafRules")
                               .order_by(ConfigObject.position)).scalars())
    fw.xml_status = "ok"
    drop = ("Position", "After", "Before", "transactionid")
    return [{k: v for k, v in r.items() if k not in drop} for r in rules if r.get("PolicyType") == "HTTPBased"]


def rest_client(fw: Firewall) -> RestApiClient:
    key = crypto.decrypt(fw.api_password_enc, f"firewall:{fw.id}") if fw.api_password_enc else ""
    return RestApiClient(fw.api_url, key, fw.verify_tls)


def _central_for(db: DbSession, fw: Firewall) -> tuple[CentralClient, str]:
    acc = db.get(CentralAccount, fw.central_account_id) if fw.central_account_id else None
    if not acc or not fw.central_id:
        raise CentralError("Firewall ist keinem Sophos-Central-Konto zugeordnet")
    return central_client(acc), fw.central_id


def capabilities(fw: Firewall) -> dict:
    if fw.connector == "central":
        return {"remove": False, "label": "Sophos Central (Import/Export)", "format": "xml"}
    if fw.connector == "rest":
        return {"remove": True, "label": "SFOS REST-API", "format": "rest"}
    return {"remove": True, "label": "XML-API (alt)", "format": "xml"}


def fetch_config(db: DbSession, fw: Firewall, log: Log | None = None) -> tuple[dict[str, list[dict]], str]:
    """Aktuelle Konfiguration aller verwalteten Entitäten: ({entity: [obj, …]}, api_version)."""
    if fw.connector == "central":
        client, cid = _central_for(db, fw)
        archive = client.export_config(cid, entities.NAMES, log)
        data, version = xmlconv.parse_entities_xml(xmlconv.read_tar_entities(archive), set(entities.NAMES))
        return {e: data.get(e, []) for e in entities.NAMES}, version
    if fw.connector == "rest":
        client = rest_client(fw)
        out = {}
        for entity, (path, _, _) in entities.REST_RESOURCES.items():
            try:
                if entity in entities.REST_SINGLETONS:
                    # Einstellungsobjekt → als einzelnes Objekt mit festem Namen führen
                    items = [{**client.get_singleton(path), "name": entities.REST_SINGLETONS[entity]}]
                else:
                    items = client.list(path)
            except RestApiError as e:
                # Ressource auf dieser Firmware nicht vorhanden oder vom Admin-Profil nicht lesbar → leer lassen,
                # damit der Rest funktioniert; Auth-/Netzfehler dagegen abbrechen
                if e.status in (403, 404):
                    if log:
                        log(f"{entities.LABELS[entity]}: übersprungen ({e})")
                    out[entity] = []
                    continue
                raise
            out[entity] = [strip_read_only(o) for o in items]
        out["wafRules"] = _fetch_waf(db, fw, log)
        return out, "REST v1"
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
    if fw.connector == "rest":
        client = rest_client(fw)
        client.test()
        msg = f"Anmeldung per API-Key erfolgreich ({client.base_url}{client.prefix})"
        if has_waf_xml(fw):
            version = waf_xml_client(fw).test()
            msg += f" · XML-API für WAF-Regeln: Anmeldung erfolgreich (API-Version {version or 'unbekannt'})"
        return msg
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
    if fw.connector == "rest":
        xml = None
        if any(o["entity"] in entities.REST_XML_ENTITIES for o in ordered):
            if not has_waf_xml(fw):
                raise DeployError("WAF-Regeln brauchen den XML-API-Zugang dieser Firewall (Einstellungen › Anbindung)")
            xml = waf_xml_client(fw)
        _rest_apply(rest_client(fw), ordered, log, xml)
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


# --- REST ----------------------------------------------------------------------------------------------------

def strip_read_only(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in entities.REST_READ_ONLY}


def _singleton_body(before: dict | None, after: dict | None) -> dict:
    return {k: v for k, v in patch_body(before, after).items() if k != "name"}


def _rest_one(client: RestApiClient, o: dict) -> str:
    path = entities.REST_RESOURCES[o["entity"]][0]
    if o["entity"] in entities.REST_SINGLETONS:
        body = _singleton_body(o.get("before"), o["data"])
        if body:
            client.update_singleton(path, body)
        return f"geändert ({', '.join(body)})" if body else "keine Änderung"
    is_rule = o["entity"] in entities.RULE_ENTITIES
    if o["action"] == "remove":
        client.delete(path, o["name"])
        return "gelöscht"
    if o["action"] == "add":
        body = dict(o["data"])
        if is_rule:
            from .restapi import position_body
            body.update(position_body(o.get("position")))
        client.create(path, body)
        return "angelegt"
    body = patch_body(o.get("before"), o["data"])
    done = []
    if body:
        client.update(path, o["name"], body)
        done.append(f"geändert ({', '.join(body)})")
    if is_rule and o.get("position"):
        client.move(path, o["name"], o["position"])
        done.append("verschoben")
    return " und ".join(done) or "keine Änderung"


def _rest_undo(client: RestApiClient, o: dict) -> None:
    path = entities.REST_RESOURCES[o["entity"]][0]
    if o["entity"] in entities.REST_SINGLETONS:
        body = _singleton_body(o["data"], o["before"])
        if body:
            client.update_singleton(path, body)
        return
    is_rule = o["entity"] in entities.RULE_ENTITIES
    if o["action"] == "add":
        client.delete(path, o["name"])
    elif o["action"] == "update":
        body = patch_body(o["data"], o["before"])
        if body:
            client.update(path, o["name"], body)
        if is_rule and o.get("position") and o.get("before_position"):
            client.move(path, o["name"], o["before_position"])
    else:
        from .restapi import position_body
        body = dict(o["before"])
        if is_rule:
            body.update(position_body(o.get("before_position")))
        client.create(path, body)


def _xml_entity_one(xml: XmlApiClient, o: dict) -> str:
    tag = entities.REST_XML_ENTITIES[o["entity"]][0]
    if o["action"] == "remove":
        return xml.remove(tag, o["name"])
    return xml.set(tag, o["data"], "add" if o["action"] == "add" else "update", o.get("position"))


def _xml_entity_undo(xml: XmlApiClient, o: dict) -> None:
    tag = entities.REST_XML_ENTITIES[o["entity"]][0]
    if o["action"] == "add":
        xml.remove(tag, o["name"])
    elif o["action"] == "update":
        xml.set(tag, o["before"], "update", o.get("before_position") if o.get("position") else None)
    else:
        xml.set(tag, o["before"], "add", o.get("before_position"))


def _rest_apply(client: RestApiClient, ordered: list[dict], log: Log, xml: XmlApiClient | None = None) -> None:
    """REST-Operationen (und WAF-Regeln per XML-API) nacheinander; bei Fehler alles bereits Angewendete zurück."""
    def one(o):
        return _xml_entity_one(xml, o) if o["entity"] in entities.REST_XML_ENTITIES else _rest_one(client, o)

    def undo(o):
        return _xml_entity_undo(xml, o) if o["entity"] in entities.REST_XML_ENTITIES else _rest_undo(client, o)
    done: list[dict] = []
    for o in ordered:
        try:
            msg = one(o)
        except (RestApiError, XmlApiError) as e:
            log(f"FEHLER bei {_label(o)}: {e}")
            if done:
                log(f"Rolle {len(done)} bereits angewendete Operation(en) zurück …")
            for d in reversed(done):
                try:
                    undo(d)
                    log(f"  zurückgerollt: {_label(d)}")
                except (RestApiError, XmlApiError) as ue:
                    log(f"  Rücknahme fehlgeschlagen für {_label(d)}: {ue} – bitte manuell prüfen!")
            raise DeployError(f"{_label(o)}: {e}") from e
        done.append(o)
        log(f"{_label(o)}: {msg}")
