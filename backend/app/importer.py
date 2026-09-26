"""Konfiguration importieren (wie „Import“/„Review import“ im Sophos Config Studio).

Eine Entities.xml (oder das Export-Archiv .tar) wird hochgeladen, mit der zwischengespeicherten Konfiguration der
Firewall verglichen (neu / geändert / identisch) und ausgewählte Objekte werden als Operationen in den Entwurf
übernommen – ausgerollt wird wie immer erst nach Vier-Augen-Freigabe.
XML-Firewalls übernehmen die Objekte direkt; für REST-Firewalls werden die gängigen Typen umgewandelt.
Die Datei selbst wird nicht gespeichert; das Ergebnis liegt 30 Minuten im Speicher (je Benutzer und Firewall).
"""
import ipaddress
import secrets
import time
import xml.etree.ElementTree as ET

from fastapi import HTTPException

from . import diff
from .sophos import entities, xmlconv
from .i18n import tr

MAX_BYTES = 20 * 1024 * 1024
_sessions: dict[str, dict] = {}

# XML-Entität → REST-Entität (nur diese werden für REST-Firewalls umgewandelt)
REST_TARGET = {"IPHost": "addressesIpv4", "IPHostGroup": "addressGroupsIpv4", "FQDNHost": "addressesFqdn",
               "FQDNHostGroup": "addressGroupsFqdn", "MACHost": "addressesMac", "Services": "services",
               "ServiceGroup": "serviceGroups", "FirewallRule": "firewallRulesIpv4"}
NET_KEY = {"addressesIpv4": "ipv4Addresses", "addressGroupsIpv4": "ipv4Groups", "addressesFqdn": "fqdnAddresses",
           "addressGroupsFqdn": "fqdnGroups", "addressesMac": "macAddresses", "countryGroups": "countryGroups"}


class Skip(Exception):
    """Objekt kann nicht übernommen werden (Grund als Text)."""


def parse_upload(data: bytes) -> tuple[dict[str, list[dict]], str]:
    if len(data) > MAX_BYTES:
        raise HTTPException(413, tr('Datei zu groß (max. 20 MB)'))
    import io
    import tarfile
    if tarfile.is_tarfile(io.BytesIO(data)):
        try:
            data = xmlconv.read_tar_entities(data)
        except (ValueError, tarfile.TarError):
            raise HTTPException(400, tr('Das Archiv enthält keine Entities.xml'))
    elif b"<Configuration" not in data[:4000]:
        raise HTTPException(400, tr('Keine Entities.xml bzw. kein Export-Archiv (.tar) erkannt'))
    try:
        return xmlconv.parse_entities_xml(data)
    except ET.ParseError as e:
        raise HTTPException(400, tr('XML ungültig: {0}', e))


def _list(v) -> list:
    return v if isinstance(v, list) else ([v] if v else [])


def _refs(names) -> list[dict]:
    return [{"name": n} for n in _list(names) if n]


def _desc(o: dict) -> str:
    return (o.get("Description") or "").strip()


# --- XML → REST ----------------------------------------------------------------------------------------------

def to_rest(entity: str, o: dict, lookup: dict[str, str]) -> tuple[str, dict]:
    """lookup: Objektname → REST-Entität (für die Zuordnung von Netzen/Diensten in Regeln)."""
    target = REST_TARGET.get(entity)
    if not target:
        raise Skip(tr('Objekttyp wird für die REST-API noch nicht umgewandelt'))
    name = o["Name"]
    if name.startswith("#") or "," in name:
        raise Skip(tr('Systemobjekt bzw. Name in der REST-API nicht erlaubt'))
    base = {"name": name, "description": _desc(o)}
    if entity == "IPHost":
        if (o.get("IPFamily") or "IPv4") != "IPv4":
            raise Skip(tr('IPv6-Hosts werden noch nicht umgewandelt'))
        kind = o.get("HostType")
        if kind == "IP":
            return target, {**base, "type": "ipv4Address", "ipv4Address": o["IPAddress"]}
        if kind == "Network":
            cidr = ipaddress.IPv4Network(f"0.0.0.0/{o['Subnet']}").prefixlen
            return target, {**base, "type": "ipv4Network", "ipv4NetworkAddress": o["IPAddress"], "cidr": cidr}
        if kind == "IPRange":
            return target, {**base, "type": "ipv4Range", "ipv4AddressStart": o["StartIPAddress"],
                            "ipv4AddressEnd": o["EndIPAddress"]}
        if kind == "IPList":
            ips = [x.strip() for x in (o.get("ListOfIPAddresses") or "").split(",") if x.strip()]
            return target, {**base, "type": "ipv4List", "ipv4Addresses": ips}
        raise Skip(tr('Host-Typ „{0}“ ist ein Systemobjekt', kind))
    if entity == "IPHostGroup":
        return target, {**base, "ipv4Addresses": _refs((o.get("HostList") or {}).get("Host"))}
    if entity == "FQDNHost":
        return target, {**base, "fqdn": o.get("FQDN", "")}
    if entity == "FQDNHostGroup":
        return target, {**base, "fqdns": _refs((o.get("FQDNHostList") or {}).get("FQDNHost"))}
    if entity == "MACHost":
        if o.get("Type") != "MACAddress":
            raise Skip(tr('MAC-Listen werden noch nicht umgewandelt'))
        return target, {**base, "type": "macAddress", "macAddress": o.get("MACAddress", "")}
    if entity == "Services":
        if o.get("Type") != "TCPorUDP":
            raise Skip(tr('Diensttyp „{0}“ wird noch nicht umgewandelt', o.get('Type')))
        details = _list((o.get("ServiceDetails") or {}).get("ServiceDetail"))
        # Ports als Text – so liefert es die echte Firewall
        return target, {**base, "type": "tcpOrUdp", "services": [
            {"protocol": (d.get("Protocol") or "TCP").lower(), "sourcePort": d.get("SourcePort") or "1:65535",
             "destinationPort": d.get("DestinationPort") or "1:65535"} for d in details]}
    if entity == "ServiceGroup":
        return target, {**base, "services": _refs((o.get("ServiceList") or {}).get("Service"))}
    # FirewallRule
    if o.get("PolicyType") != "Network":
        raise Skip(tr('Regeltyp „{0}“ (Benutzer/WAF) wird noch nicht umgewandelt', o.get('PolicyType')))
    if (o.get("IPFamily") or "IPv4") != "IPv4":
        raise Skip(tr('IPv6-Regeln werden noch nicht umgewandelt'))
    pol = o.get("NetworkPolicy") or {}

    def zones(key):
        z = _list((pol.get(key) or {}).get("Zone"))
        return {"zones": _refs(z)} if z else {"any": True}

    def nets(key):
        names = [n for n in _list((pol.get(key) or {}).get("Network")) if n]
        if not names:
            return {"any": True}
        out: dict[str, list] = {}
        for n in names:
            known = lookup.get(n, "")
            # "@countries" usw.: Einordnung aus vorhandenen Regeln (z. B. eingebaute Länder)
            key = known[1:] if known.startswith("@") else NET_KEY.get(known, "ipv4Addresses")
            out.setdefault(key, []).append({"name": n})
        return out
    svc_names = [s for s in _list((pol.get("Services") or {}).get("Service")) if s]
    services: dict = {"any": True}
    if svc_names:
        services = {}
        for s in svc_names:
            services.setdefault("serviceGroups" if lookup.get(s) == "serviceGroups" else "services", []).append({"name": s})
    rule = {**base, "ruleType": "firewall", "enabled": o.get("Status") != "Disable",
            "action": (pol.get("Action") or "Accept").lower(), "logTraffic": pol.get("LogTraffic") == "Enable",
            "sourceZones": zones("SourceZones"), "destinationZones": zones("DestinationZones"),
            "sourceNetworks": nets("SourceNetworks"), "destinationNetworks": nets("DestinationNetworks"),
            "servicesOrGroups": services}
    if pol.get("Schedule") and pol["Schedule"] != "All The Time":
        rule["schedule"] = {"name": pol["Schedule"]}
    return target, rule


# --- Vergleich -----------------------------------------------------------------------------------------------

def _norm(v):
    """Für den Vergleich: leere Listen/None wie fehlend, Listen ohne Reihenfolge (Gruppenmitglieder, Protokolle)."""
    if isinstance(v, dict):
        return {k: _norm(x) for k, x in v.items() if x not in (None, [], "")}
    if isinstance(v, list):
        return sorted((_norm(x) for x in v), key=diff.canonical)
    return v


def _changed_fields(current: dict, incoming: dict) -> list[dict]:
    """Nur die Felder des importierten Objekts vergleichen (die Firewall liefert oft zusätzliche Standardfelder)."""
    cur, inc = _norm({k: current.get(k) for k in incoming}), _norm(incoming)
    return diff.diff_objects(cur, inc) if diff.canonical(cur) != diff.canonical(inc) else []


def review(config: dict[str, list[dict]], fmt: str, parsed: dict[str, list[dict]]) -> list[dict]:
    items = []
    index = {e: {entities.oname(o): o for o in objs} for e, objs in config.items()}
    if fmt == "rest":
        lookup = {entities.oname(o): e for e, objs in config.items() for o in objs}
        for xml_entity, target in REST_TARGET.items():
            for o in parsed.get(xml_entity, []):
                lookup.setdefault(o["Name"], target)
        # Namen, die in vorhandenen Regeln unter einem bestimmten Schlüssel stehen (Länder sind keine Objekte)
        for rule in config.get("firewallRulesIpv4", []):
            for side in ("sourceNetworks", "destinationNetworks"):
                for key, refs in (rule.get(side) or {}).items():
                    if isinstance(refs, list):
                        for ref in refs:
                            if isinstance(ref, dict) and ref.get("name"):
                                lookup.setdefault(ref["name"], "@" + key)
    for xml_entity, objs in parsed.items():
        for o in objs:
            item = {"source_entity": xml_entity, "name": o.get("Name", "")}
            try:
                if fmt == "rest":
                    entity, data = to_rest(xml_entity, o, lookup)
                else:
                    if xml_entity not in entities.NAMES:
                        raise Skip(tr('Objekttyp wird von diesem Tool nicht verwaltet'))
                    entity, data = xml_entity, o
            except Skip as e:
                items.append({**item, "entity": None, "label": xml_entity, "status": "unsupported", "reason": str(e)})
                continue
            except (KeyError, ValueError) as e:
                items.append({**item, "entity": None, "label": xml_entity, "status": "unsupported",
                              "reason": tr('Unvollständig: {0}', e)})
                continue
            current = index.get(entity, {}).get(data.get("name") or data.get("Name"))
            if current is None:
                status, fields = "new", []
            else:
                fields = _changed_fields(current, data)
                status = "changed" if fields else "same"
            items.append({**item, "entity": entity, "label": entities.LABELS.get(entity, entity), "status": status,
                          "diff": fields, "data": data})
    return items


def store(user_id: str, firewall_id: str, items: list[dict]) -> str:
    now = time.time()
    for k in [k for k, v in _sessions.items() if v["created"] < now - 1800]:
        _sessions.pop(k, None)
    token = secrets.token_urlsafe(16)
    _sessions[token] = {"user": user_id, "firewall": firewall_id, "items": items, "created": now}
    return token


def load(token: str, user_id: str, firewall_id: str) -> list[dict]:
    s = _sessions.get(token)
    if not s or s["user"] != user_id or s["firewall"] != firewall_id or s["created"] < time.time() - 1800:
        raise HTTPException(410, tr('Import abgelaufen – bitte die Datei erneut hochladen'))
    return s["items"]


def operations(items: list[dict], keys: set[str], config: dict[str, list[dict]]) -> list[dict]:
    """Ausgewählte Einträge → Operationen in Schreibreihenfolge (Objekte vor Gruppen vor Regeln)."""
    index = {e: {entities.oname(o): o for o in objs} for e, objs in config.items()}
    ops = []
    for i, it in enumerate(items):
        if str(i) not in keys or it["status"] not in ("new", "changed"):
            continue
        if it["status"] == "new":
            op = {"entity": it["entity"], "action": "add", "name": it["name"], "data": it["data"]}
            if it["entity"] in entities.RULE_ENTITIES:
                op["position"] = {"type": "bottom"}
        else:
            current = index[it["entity"]][it["name"]]
            op = {"entity": it["entity"], "action": "update", "name": it["name"], "data": {**current, **it["data"]}}
        ops.append(op)
    rank = {e: n for n, e in enumerate(entities.WRITE_ORDER)}
    return sorted(ops, key=lambda o: rank.get(o["entity"], 100))
