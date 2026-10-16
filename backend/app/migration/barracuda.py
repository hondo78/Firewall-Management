"""Barracuda CloudGen Firewall (ehem. NextGen) – JSON aus der REST-API der Box → Zwischenmodell.

Das native Regelsatz-Format (.fwrule aus Firewall Admin) ist nicht dokumentiert. Gelesen werden deshalb die Antworten
der CloudGen-REST-API (https://<box>:8443/rest/config/v1/…, Header X-API-Token), zusammengefasst in einer Datei:
  {"networks": GET …/forwarding-firewall/objects/networks?expand=true,
   "services": GET …/forwarding-firewall/objects/services?expand=true,
   "rules":    GET …/forwarding-firewall/rules?expand=true}
Jeder Teil darf die ganze API-Antwort ({"objects": […]} bzw. {"rules": […]}) oder nur die Liste sein. docs/barracuda-
export.sh erzeugt die Datei. Barracuda kennt keine Zonen: eingebaute Objekte wie „Internet“ oder „Trusted LAN“ werden
zu Zonen-Hinweisen, die im Assistenten Sophos-Zonen zugeordnet werden. Netzobjekte mit Ausschlüssen, Geo- oder
dynamischen Einträgen lassen sich nicht übertragen – Regeln damit werden deaktiviert übernommen.
Die Feldnamen sind gegen die öffentliche API-Beschreibung geschrieben, nicht gegen echte Exporte getestet.
"""
import ipaddress
import json

from ..i18n import tr
from . import model

# Eingebaute Netzobjekte: Zone (Hinweis für die Zuordnung) bzw. feste Netze; „Any“/„World“ = beliebig
ZONE_OBJECTS = {"Internet": "Internet", "Trusted LAN": "Trusted LAN", "Trusted LAN Networks": "Trusted LAN",
                "Trusted Networks": "Trusted LAN", "Trusted Next Hop": "Trusted LAN"}
FIXED_OBJECTS = {"Private 10": "10.0.0.0/8", "Private 172": "172.16.0.0/12", "Private 192": "192.168.0.0/16"}
ANY = {"", "any", "world", "any-ipv4", "world-ipv4"}
# Eingebaute Dienste, deren Name nicht direkt in model.COMMON_SERVICES steht
SERVICE_ALIASES = {"HTTP+S": ["HTTP", "HTTPS"], "HTTP+S+FTP": ["HTTP", "HTTPS", "FTP"], "MS-RDP": ["RDP"],
                   "DNS-UDP": ["DNS"], "SMTP+S": ["SMTP", "SMTPS"], "ICMP-ECHO": ["PING"], "ICMP-ALL": ["ICMP"]}
ACTIONS = {"pass": "accept", "allow": "accept", "block": "drop", "drop": "drop", "deny": "reject", "reject": "reject"}
NAT_ACTIONS = {"dnat", "map", "redirect", "app-redirect", "broad-multicast"}
PROTOS = {"6": "TCP", "17": "UDP", "1": "ICMP", "58": "ICMPV6", "tcp": "TCP", "udp": "UDP", "icmp": "ICMP",
          "icmpv6": "ICMPV6", "icmp6": "ICMPV6"}


def _list(part, *keys) -> list:
    """API-Antwort oder blanke Liste → Liste der Objekte."""
    if isinstance(part, list):
        return part
    if isinstance(part, dict):
        for k in keys:
            if isinstance(part.get(k), list):
                return part[k]
    return []


def _refs(v) -> list[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [x for x in v if isinstance(x, str)]
    return []


def _entries(obj: dict) -> list:
    """Einträge eines Objekts bzw. einer expliziten Angabe (included/entries/list)."""
    for k in ("included", "entries", "list"):
        if isinstance(obj.get(k), list):
            return obj[k]
    return []


def parse(data: bytes) -> dict:
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(tr('JSON ungültig: {0}', e))
    if not isinstance(doc, dict) or not _list(doc.get("rules"), "rules"):
        raise ValueError(tr('Keine Barracuda-Konfiguration erkannt (JSON mit „rules“ aus der CloudGen-REST-API erwartet)'))
    m = model.new("barracuda")
    m["source"] = {"name": str(doc.get("name") or doc.get("box") or "")}
    addr_names: set[str] = set()
    excluded, unsupported = [], []

    def address(entry: dict, owner: str) -> str | None:
        """Ein Netz-Eintrag → Name eines Adressobjekts im Modell (None = nicht übertragbar)."""
        val = next((str(entry[k]).strip() for k in ("ip", "address", "value", "network") if entry.get(k)), "")
        dom = next((str(entry[k]).strip() for k in ("domain", "hostname", "fqdn") if entry.get(k)), "")
        mac = str(entry.get("mac") or "").strip()
        if val:
            if "-" in val:
                start, end = (x.strip() for x in val.split("-", 1))
                ipaddress.ip_address(start), ipaddress.ip_address(end)
                item = {"name": val, "type": "range", "start": start, "end": end}
            else:
                net = ipaddress.ip_network(val, strict=False)
                kind = ("host" if net.num_addresses == 1 else "network") + ("6" if net.version == 6 else "")
                item = {"name": val, "type": kind, "value": str(net) if net.num_addresses > 1 else str(net.network_address)}
        elif dom:
            item = {"name": dom, "type": "fqdn", "value": dom}
        elif mac:
            item = {"name": mac, "type": "mac", "value": mac}
        else:
            unsupported.append(f"{owner}: {', '.join(sorted(entry)) or '?'}")
            return None
        if item["name"] not in addr_names:
            addr_names.add(item["name"])
            m["addresses"].append(item)
        return item["name"]

    def network_members(obj: dict, owner: str) -> list[str]:
        members = []
        for e in _entries(obj):
            if not isinstance(e, dict):
                continue
            if e.get("references"):
                members += _refs(e["references"])
                continue
            try:
                a = address(e.get("entry") if isinstance(e.get("entry"), dict) else e, owner)
            except ValueError:
                a = None
            members.append(a or f"__unsupported_{owner}__")
        return members

    # --- Netzobjekte → Gruppen (Mitglieder sind Adressen oder andere Objekte) -------------------------------------
    for o in _list(doc.get("networks"), "objects", "networks"):
        name = str(o.get("name") or "")
        if not name:
            continue
        members = network_members(o, name)
        if o.get("excluded"):
            excluded.append(name)
            members.append(f"__excluded_{name}__")   # Ausschlüsse kann Sophos nicht → Gruppe unvollständig
        m["address_groups"].append({"name": name, "members": members, "comment": str(o.get("comment") or "")})
    known_net = {g["name"] for g in m["address_groups"]}
    for name, net in FIXED_OBJECTS.items():
        if name not in known_net:
            m["addresses"].append({"name": name, "type": "network", "value": net})
            addr_names.add(name)
            known_net.add(name)

    # --- Dienste -------------------------------------------------------------------------------------------------
    def service_items(obj: dict) -> tuple[list[dict], list[str]]:
        items, refs = [], []
        for e in _entries(obj):
            if not isinstance(e, dict):
                continue
            if e.get("references"):
                refs += _refs(e["references"])
                continue
            ent = e.get("entry") if isinstance(e.get("entry"), dict) else e
            proto = PROTOS.get(str(ent.get("protocol", "")).lower(), "")
            sub = ent.get(proto.lower()) if isinstance(ent.get(proto.lower()), dict) else ent
            if proto in ("TCP", "UDP"):
                ports = sub.get("ports") or sub.get("port") or []
                ports = [str(x).strip() for x in (ports if isinstance(ports, list) else str(ports).split(","))]
                ports = [x for x in ports if x]
                if not ports or any(x.lower() == "any" for x in ports):
                    ports = [""]                        # alle Ports
                items += [{"proto": proto, "dst": x} for x in ports]
            elif proto in ("ICMP", "ICMPV6"):
                items.append({"proto": proto, "icmp_type": str(sub.get("type") or "")})
            elif str(ent.get("protocol", "")).isdigit():
                items.append({"proto": "IP", "ip_proto": str(ent["protocol"])})
            else:
                items.append({"proto": "?", "dst": ""})
        return list({json.dumps(i, sort_keys=True): i for i in items}.values()), refs

    for o in _list(doc.get("services"), "objects", "services"):
        name = str(o.get("name") or "")
        if not name:
            continue
        items, refs = service_items(o)
        if refs:
            members = list(refs)
            if items:
                m["services"].append({"name": f"{name}_ports", "items": items, "comment": str(o.get("comment") or "")})
                members.append(f"{name}_ports")
            m["service_groups"].append({"name": name, "members": members, "comment": str(o.get("comment") or "")})
        else:
            m["services"].append({"name": name, "items": items, "comment": str(o.get("comment") or "")})
    known_svc = {s["name"] for s in m["services"]} | {g["name"] for g in m["service_groups"]}

    def builtin_service(name: str) -> bool:
        """Eingebaute Barracuda-Dienste, die nicht in der Datei stehen, aus den gängigen Ports ergänzen."""
        if name in known_svc:
            return True
        parts = SERVICE_ALIASES.get(name.upper()) or ([name.upper()] if name.upper() in model.COMMON_SERVICES else [])
        if not parts:
            return False
        if len(parts) == 1:
            m["services"].append({"name": name, "items": [{"proto": p, "dst": port} for p, port in model.COMMON_SERVICES[parts[0]]]})
        else:
            for p in parts:
                if p not in known_svc:
                    m["services"].append({"name": p, "items": [{"proto": pr, "dst": port} for pr, port in model.COMMON_SERVICES[p]]})
                    known_svc.add(p)
            m["service_groups"].append({"name": name, "members": parts})
        known_svc.add(name)
        return True

    # --- Regeln --------------------------------------------------------------------------------------------------
    def side(v, rule_name: str, what: str) -> tuple[list[str], list[str]]:
        """Quelle/Ziel → (Adress-/Gruppennamen, Zonen-Hinweise); leer = beliebig."""
        refs: list[str] = []
        if isinstance(v, (str, list)):
            refs = _refs(v)
        elif isinstance(v, dict):
            refs = _refs(v.get("references"))
            exp = v.get("explicit")
            if isinstance(exp, dict):
                inline = f"{rule_name} ({what})"
                members = network_members(exp, inline)
                if members:
                    m["address_groups"].append({"name": inline, "members": members})
                    refs.append(inline)
        addrs, zones = [], []
        for r in refs:
            if r.lower() in ANY:
                continue
            if r in ZONE_OBJECTS and r not in known_net:
                zones.append(ZONE_OBJECTS[r])
                model.add_interface(m, ZONE_OBJECTS[r], ZONE_OBJECTS[r], kind="zone")
            else:
                addrs.append(r)
        return addrs, zones

    def services(v, rule_name: str) -> list[str]:
        refs: list[str] = []
        if isinstance(v, (str, list)):
            refs = _refs(v)
        elif isinstance(v, dict):
            refs = _refs(v.get("references"))
            exp = v.get("explicit")
            if isinstance(exp, dict):
                items, more = service_items(exp)
                inline = f"{rule_name}_svc"
                if items:
                    m["services"].append({"name": inline, "items": items})
                    known_svc.add(inline)
                    refs.append(inline)
                refs += more
        out = []
        for r in refs:
            if r.lower() in ("any", ""):
                return []
            builtin_service(r)
            out.append(r)
        return out

    nat_rules, cascades, ipv6 = [], [], []
    for r in _list(doc.get("rules"), "rules"):
        name = str(r.get("name") or "")
        act = r.get("action") if isinstance(r.get("action"), dict) else {"type": r.get("action")}
        typ = str(act.get("type") or "pass").lower()
        if typ.startswith("cascade"):
            cascades.append(name)
            continue
        if str(r.get("ipVersion") or "IPv4").lower() == "ipv6":
            ipv6.append(name)
            continue
        notes = []
        src_a, src_z = side(r.get("source"), name, tr('Quelle'))
        dst_a, dst_z = side(r.get("destination"), name, tr('Ziel'))
        svcs = services(r.get("service"), name)
        conn = act.get("connection")
        conn = (conn.get("references") if isinstance(conn, dict) else conn) or ""
        if typ in NAT_ACTIONS:
            nat_rules.append(name)
            m["nat"].append({"name": name, "summary": tr('{0}-Regel: {1} → {2}', typ.upper(), ", ".join(src_a + src_z) or "Any",
                                                         ", ".join(dst_a + dst_z) or "Any")})
            notes.append(tr('Barracuda-{0}-Regel – Zugriff übernommen, NAT auf Sophos als NAT-Regel nachbauen', typ.upper()))
        elif conn and str(conn).lower() not in ("original source ip", "original source", "no src nat", ""):
            m["nat"].append({"name": name, "summary": tr('Quell-NAT „{0}“', conn)})
            notes.append(tr('Verbindungsobjekt „{0}“ (Quell-NAT) nicht übernommen – NAT-Regel auf Sophos anlegen', conn))
        if src_z or dst_z:
            notes.append(tr('Eingebaute Objekte (Internet, Trusted LAN) als Zonen übernommen – Netze prüfen'))
        enabled = not (r.get("deactivated") or r.get("disabled")) and typ not in NAT_ACTIONS
        rule = {"name": name, "enabled": enabled, "action": ACTIONS.get(typ, "accept" if typ in NAT_ACTIONS else "drop"),
                "src_zones": list(dict.fromkeys(src_z)), "dst_zones": list(dict.fromkeys(dst_z)),
                "src": list(dict.fromkeys(src_a)), "dst": list(dict.fromkeys(dst_a)), "services": svcs,
                "log": True, "schedule": "", "comment": str(r.get("comment") or ""), "notes": notes}
        m["rules"].append(rule)
        if r.get("bidirectional"):
            # Sophos-Regeln gelten in eine Richtung: Rückrichtung als zweite Regel
            m["rules"].append({**rule, "name": f"{name}_rev", "src_zones": rule["dst_zones"], "dst_zones": rule["src_zones"],
                               "src": rule["dst"], "dst": rule["src"],
                               "notes": notes + [tr('Rückrichtung der bidirektionalen Regel „{0}“', name)]})

    R = model.report
    R(m, "concepts", tr('Eingebaute Objekte als Zonen (Internet, Trusted LAN)'), "partial", len(m["interfaces"]),
      tr('Barracuda kennt keine Zonen – im nächsten Schritt Sophos-Zonen zuordnen.'))
    R(m, "objects", tr('Netzobjekte (IP, Netz, Bereich, FQDN, MAC)'), "supported", len(m["address_groups"]))
    if excluded:
        R(m, "objects", tr('Netzobjekte mit Ausschlüssen'), "manual", len(excluded),
          tr('Sophos kennt keine Ausschlüsse in Gruppen – Regeln damit werden deaktiviert.'), excluded)
    if unsupported:
        R(m, "objects", tr('Geo-, dynamische und sonstige Einträge'), "manual", len(unsupported), "", unsupported)
    R(m, "objects", tr('Dienste und Dienstgruppen'), "supported", len(m["services"]) + len(m["service_groups"]))
    R(m, "rules", tr('Weiterleitungs-Regeln (Pass, Block, Deny)'), "supported", len(m["rules"]))
    if nat_rules:
        R(m, "rules", tr('Dst-NAT-, Map- und Redirect-Regeln'), "manual", len(nat_rules),
          tr('Deaktiviert übernommen – NAT auf Sophos nachbauen.'), nat_rules)
    if cascades:
        R(m, "rules", tr('Cascade-Regeln (Unterregelsätze)'), "unsupported", len(cascades),
          tr('Unterregelsätze bitte einzeln exportieren und übernehmen.'), cascades)
    if ipv6:
        R(m, "rules", tr('IPv6-Regeln'), "manual", len(ipv6), "", ipv6)
    R(m, "interfaces", tr('Interfaces, VLANs, Routen, DHCP'), "manual", 0, tr('Werden von diesem Tool nicht verwaltet.'))
    R(m, "advanced", tr('Anwendungsregeln, IPS, URL-Filter, VPN, HA'), "manual", 0, tr('Bewusst nicht übernommen.'))
    m["warnings"].append(tr('Die Barracuda-Umwandlung ist nicht gegen echte Exporte getestet – Ergebnis besonders sorgfältig prüfen.'))
    return m
