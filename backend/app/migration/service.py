"""Ablauf des Migrationsassistenten: Hersteller, Upload → Sitzung, Umwandlung, Ziele (Entwurf, Vorlage, Download)."""
import secrets
import time

from fastapi import HTTPException

from .. import importer
from ..i18n import tr
from ..sophos import entities
from . import barracuda, convert, fortigate, model, paloalto, sonicwall, watchguard

SESSION_SECONDS = 3600
_sessions: dict[str, dict] = {}

# (id, Titel, Datei, Hinweis, Parser) – Reihenfolge wie im Config Studio
VENDORS = [
    {"id": "fortigate", "title": "FortiGate", "ext": [".conf", ".txt"], "file": "FortiOS .conf",
     "hint": "Unverschlüsseltes Konfigurations-Backup: System › Configuration › Backup (ohne Passwort).", "parse": fortigate.parse},
    {"id": "paloalto", "title": "Palo Alto Networks", "ext": [".xml"], "file": "running-config.xml",
     "hint": "Device › Setup › Operations › Export named configuration snapshot (oder running-config.xml). Nur die erste vsys wird übernommen.",
     "parse": paloalto.parse},
    {"id": "sonicwall", "title": "SonicWall", "ext": [".exp"], "file": "SonicOS .exp",
     "hint": "Unverschlüsselter Settings-Export (Export Settings bzw. Firmware and Settings).", "parse": sonicwall.parse},
    {"id": "watchguard", "title": "WatchGuard", "ext": [".xml"], "file": "Fireware XML",
     "hint": "Konfigurationsdatei aus dem Policy Manager (File › Save › As File) bzw. Backup-XML.", "parse": watchguard.parse},
    {"id": "barracuda", "title": "Barracuda CloudGen", "ext": [".json"], "file": "CloudGen REST-API JSON",
     "hint": "Netzobjekte, Dienste und Weiterleitungsregeln über die REST-API der Box (Port 8443, API-Token) als eine JSON-Datei – Skript: docs/barracuda-export.sh.",
     "parse": barracuda.parse},
    {"id": "utm", "title": "Sophos UTM (SG)", "ext": [".xml", ".tar"], "file": "Entities.xml",
     "hint": "Mit dem Sophos Migration Utility (migrate.pl) auf der UTM erzeugen; Entities.xml oder Export.tar hochladen.", "parse": None},
    {"id": "sophos", "title": "Sophos Firewall", "ext": [".xml", ".tar"], "file": "Entities.xml",
     "hint": "Backup & firmware › Import export › Export (API-…-Ordner) – Entities.xml oder das .tar.", "parse": None},
]
BY_ID = {v["id"]: v for v in VENDORS}

# Was übernommen wird (Übersicht vor dem Upload) – Stand dieser Umsetzung
MATRIX = {
    "_common": [
        ("objects", "Adressen: Host, Netz, Bereich, FQDN, MAC, IPv6", "supported"),
        ("objects", "Adressgruppen (verschachtelt aufgelöst, IP/FQDN getrennt)", "supported"),
        ("objects", "Dienste TCP/UDP, ICMP, IP-Protokoll; Dienstgruppen", "supported"),
        ("rules", "Firewall-Regeln: Zonen, Adressen, Dienste, Aktion, Protokollierung", "supported"),
        ("concepts", "Interfaces/Zonen → Sophos-Zonen (Zuordnung im Assistenten)", "partial"),
        ("rules", "Sicherheitsprofile, Benutzer, Zeitpläne in Regeln", "manual"),
        ("rules", "NAT-Regeln (im Bericht aufgelistet)", "manual"),
        ("interfaces", "Interfaces, VLANs, Routen, DHCP, DNS", "manual"),
        ("advanced", "VPN, SD-WAN, HA, Wireless, Zertifikate", "unsupported"),
    ],
    "fortigate": [("objects", "Länder- und dynamische Adressen", "manual"), ("rules", "VIPs, IP-Pools, Policy-NAT", "manual")],
    "paloalto": [("rules", "App-ID, Negation, dynamische Gruppen", "manual"), ("concepts", "Mehrere vsys (nur die erste)", "partial")],
    "sonicwall": [("concepts", "Exportformat inoffiziell – Ergebnis sorgfältig prüfen", "partial")],
    "watchguard": [("rules", "Proxy-Policies, Aliase werden aufgelöst", "partial"),
                   ("concepts", "XML-Schema inoffiziell – Ergebnis sorgfältig prüfen", "partial")],
    "barracuda": [("concepts", "Keine Zonen: Internet/Trusted LAN werden Zonen zugeordnet", "partial"),
                  ("objects", "Netzobjekte mit Ausschlüssen, Geo- und dynamische Einträge", "manual"),
                  ("rules", "Bidirektionale Regeln werden zu zwei Regeln, Dst-NAT/Map deaktiviert", "partial"),
                  ("concepts", "Nicht gegen echte Exporte getestet – Ergebnis sorgfältig prüfen", "partial")],
    "utm": [("objects", "Alle Objekte und Regeln aus der Entities.xml von migrate.pl", "supported")],
    "sophos": [("objects", "Alle von diesem Tool verwalteten Objekttypen der Entities.xml", "supported")],
}


def vendors() -> list[dict]:
    out = []
    for v in VENDORS:
        rows = MATRIX.get(v["id"], []) + ([] if v["parse"] is None else MATRIX["_common"])
        out.append({k: v[k] for k in ("id", "title", "ext", "file", "hint")}
                   | {"matrix": [{"section": s, "feature": f, "status": st} for s, f, st in rows]})
    return out


def _cleanup() -> None:
    now = time.time()
    for k in [k for k, s in _sessions.items() if s["created"] < now - SESSION_SECONDS]:
        _sessions.pop(k, None)


def start(user_id: str, vendor: str, filename: str, data: bytes) -> dict:
    v = BY_ID.get(vendor)
    if not v:
        raise HTTPException(400, tr('Unbekannter Hersteller'))
    if len(data) > importer.MAX_BYTES:
        raise HTTPException(413, tr('Datei zu groß (max. 20 MB)'))
    _cleanup()
    if v["parse"] is None:
        parsed, version = importer.parse_upload(data)
        m = model.new(vendor)
        m["source"] = {"api_version": version}
        managed = set(entities.NAMES)
        for e, objs in parsed.items():
            model.report(m, "objects", e, "supported" if e in managed else "unsupported", len(objs),
                         "" if e in managed else tr('Objekttyp wird von diesem Tool nicht verwaltet'))
        session = {"vendor": vendor, "model": m, "sfos": parsed}
    else:
        try:
            m = v["parse"](data)
        except ValueError as e:
            raise HTTPException(400, str(e))
        except Exception as e:                    # fremde Formate: unerwartete Struktur verständlich melden
            raise HTTPException(400, tr('Datei konnte nicht gelesen werden: {0}', e))
        session = {"vendor": vendor, "model": m, "sfos": None}
    token = secrets.token_urlsafe(16)
    _sessions[token] = {**session, "user": user_id, "created": time.time(), "filename": filename[:200]}
    return {"token": token, **summary(_sessions[token])}


def load(token: str, user_id: str) -> dict:
    s = _sessions.get(token)
    if not s or s["user"] != user_id or s["created"] < time.time() - SESSION_SECONDS:
        raise HTTPException(410, tr('Migration abgelaufen – bitte die Datei erneut hochladen'))
    return s


def summary(s: dict) -> dict:
    m = s["model"]
    counts = {k: len(m[k]) for k in ("addresses", "address_groups", "services", "service_groups", "rules", "nat")}
    if s["sfos"] is not None:
        counts = {e: len(objs) for e, objs in s["sfos"].items()}
    return {"vendor": s["vendor"], "filename": s["filename"], "source": m["source"], "interfaces": m["interfaces"],
            "counts": counts, "report": m["report"], "warnings": m["warnings"], "needs_zones": s["sfos"] is None}


def build(s: dict, zone_map: dict[str, str], prefix: str) -> tuple[dict[str, list[dict]], list[dict]]:
    """Sophos-Objekte (XML-Format) und Hinweise. Sophos-Quellen werden unverändert übernommen."""
    if s["sfos"] is not None:
        return {e: objs for e, objs in s["sfos"].items() if e in entities.NAMES}, []
    zm = {i["name"]: i["zone"] for i in s["model"]["interfaces"]}
    zm.update({k: v for k, v in (zone_map or {}).items() if isinstance(v, str)})
    return convert.convert(s["model"], zm, prefix)


def template_items(parsed: dict[str, list[dict]], fmt: str, config: dict) -> tuple[list[dict], list[str]]:
    """Vorlagen-Einträge (ensure) in Schreibreihenfolge; REST über den vorhandenen Import-Umwandler."""
    items, skipped = [], []
    lookup: dict[str, str] = {}
    if fmt == "rest":
        for ent in entities.REST_RESOURCES:
            for o in config.get(ent, []):
                lookup.setdefault(o.get("name", ""), ent)
        for xml_entity, target in importer.REST_TARGET.items():
            for o in parsed.get(xml_entity, []):
                lookup.setdefault(o["Name"], target)
    rank = {e: n for n, e in enumerate(entities.WRITE_ORDER)}
    for xml_entity in sorted(parsed, key=lambda e: rank.get(e, 100)):
        for o in parsed[xml_entity]:
            try:
                entity, data = importer.to_rest(xml_entity, o, lookup) if fmt == "rest" else (xml_entity, o)
            except (importer.Skip, KeyError, ValueError) as e:
                skipped.append(f"{xml_entity} „{o.get('Name', '')}“: {e}")
                continue
            item = {"entity": entity, "name": data.get("name") or data.get("Name"), "action": "ensure", "data": data}
            if entity in entities.RULE_ENTITIES:
                item["position"] = {"type": "bottom"}
            items.append(item)
    return items, skipped
