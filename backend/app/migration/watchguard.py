"""WatchGuard (Fireware) – XML-Konfiguration aus dem Policy Manager (Wurzel <profile>) → Zwischenmodell.

Policies verweisen über Aliase (from-alias-list / to-alias-list) auf Adressgruppen und Interfaces. Eingebaute Aliase
wie „Any-Trusted“, „Any-External“, „Any-Optional“ stehen für Zonen; „Any“ bedeutet beliebig. Adressgruppen enthalten
die Adressen direkt (Host, Netz, Bereich, FQDN) und werden zu Sophos-Gruppen mit einzelnen Host-Objekten.
Das XML-Schema ist nicht offiziell dokumentiert – ausgewertet werden die bekannten Elemente; Rest steht im Bericht.
"""
import ipaddress
import xml.etree.ElementTree as ET

from ..i18n import tr
from . import model

ZONE_ALIASES = {"Any-Trusted": "LAN", "Any-External": "WAN", "Any-Optional": "DMZ", "Any-BOVPN": "VPN",
                "Any-MUVPN": "VPN", "Firebox": ""}
ANY = {"Any", "any", ""}


def _t(el, path, default="") -> str:
    n = el.find(path) if el is not None else None
    return (n.text or "").strip() if n is not None and n.text else default


def parse(data: bytes) -> dict:
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise ValueError(tr('XML ungültig: {0}', e))
    if root.tag != "profile" or root.find("policy-list") is None:
        raise ValueError(tr('Keine WatchGuard-Konfiguration erkannt (<profile> mit <policy-list> erwartet)'))
    m = model.new("watchguard")
    m["source"] = {"name": _t(root, "system-parameters/device-conf/system-name") or _t(root, "name")}

    # Interfaces (Zonen-Vorschlag aus Name bzw. Eigenschaft: 0 extern, 1 vertrauenswürdig, 2 optional)
    for itf in root.findall("./interface-list/interface"):
        name = _t(itf, "name")
        prop = _t(itf, ".//if-property")
        hint = {"0": "External", "1": "Trusted", "2": "Optional"}.get(prop, name)
        model.add_interface(m, name, hint, _t(itf, ".//ip"), "interface")
    for alias, zone in ZONE_ALIASES.items():
        if zone:
            model.add_interface(m, alias, alias, kind="zone")

    # Adressgruppen → je Mitglied ein Adressobjekt, Gruppe verweist darauf
    addr_names: set[str] = set()

    def member_address(mem) -> str | None:
        typ = _t(mem, "type")
        if _t(mem, "host-ip-addr"):
            v = _t(mem, "host-ip-addr")
            n = v
            kind = {"name": n, "type": "host", "value": v}
        elif _t(mem, "ip-network-addr"):
            mask = _t(mem, "ip-mask", "255.255.255.255")
            net = ipaddress.IPv4Network(f"{_t(mem, 'ip-network-addr')}/{mask}", strict=False)
            n = str(net)
            kind = {"name": n, "type": "network", "value": n}
        elif _t(mem, "start-ip-addr"):
            n = f"{_t(mem, 'start-ip-addr')}-{_t(mem, 'end-ip-addr')}"
            kind = {"name": n, "type": "range", "start": _t(mem, "start-ip-addr"), "end": _t(mem, "end-ip-addr")}
        elif _t(mem, "domain"):
            n = _t(mem, "domain")
            kind = {"name": n, "type": "fqdn", "value": n}
        else:
            return None if typ in ("", "0") else f"__unsupported_{typ}__"
        if n not in addr_names:
            addr_names.add(n)
            m["addresses"].append(kind)
        return n
    groups: dict[str, list[str]] = {}
    for g in root.findall("./address-group-list/address-group"):
        members = []
        for mem in g.findall("./addr-group-member/member"):
            try:
                a = member_address(mem)
            except ValueError:
                a = "__invalid__"
            if a:
                members.append(a)
        groups[_t(g, "name")] = members
        m["address_groups"].append({"name": _t(g, "name"), "members": members, "comment": _t(g, "description")})

    # Aliase: Adressen (Gruppen, verschachtelte Aliase) und Interfaces/Zonen
    aliases: dict[str, list[tuple[str, str]]] = {}
    for a in root.findall("./alias-list/alias"):
        items = []
        for mem in a.findall("./alias-member-list/alias-member"):
            if _t(mem, "type") == "2" or _t(mem, "alias-name"):
                items.append(("alias", _t(mem, "alias-name")))
            else:
                items.append(("addr", _t(mem, "address")))
                items.append(("iface", _t(mem, "interface")))
        aliases[_t(a, "name")] = items

    def resolve(name: str, seen=None) -> tuple[list[str], list[str]]:
        """Alias → (Adressnamen, Zonen/Interfaces); leer = beliebig."""
        seen = seen or set()
        if name in ZONE_ALIASES or name in ANY:
            return [], ([name] if ZONE_ALIASES.get(name) else [])
        if name in groups:
            return [name], []
        if name in seen or name not in aliases:
            return [name], []                      # unbekannt → Umwandler meldet es (Regel wird deaktiviert)
        seen.add(name)
        addrs, zones = [], []
        for kind, v in aliases[name]:
            if kind == "alias":
                a, z = resolve(v, seen)
                addrs += a
                zones += z
            elif kind == "addr" and v not in ANY:
                a, z = resolve(v, seen)
                addrs += a
                zones += z
            elif kind == "iface" and v not in ANY:
                zones.append(v)
        return addrs, zones

    # Dienste
    for s in root.findall("./service-list/service"):
        items = []
        for mem in s.findall("./service-item/member"):
            proto = {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(_t(mem, "protocol"), "")
            if proto in ("TCP", "UDP"):
                port = _t(mem, "server-port") or (f"{_t(mem, 'start-server-port')}:{_t(mem, 'end-server-port')}"
                                                  if _t(mem, "start-server-port") else "")
                items.append({"proto": proto, "dst": port})
            elif proto == "ICMP":
                items.append({"proto": "ICMP", "icmp_type": _t(mem, "icmp-type")})
            elif _t(mem, "protocol"):
                items.append({"proto": "IP", "ip_proto": _t(mem, "protocol")})
        if _t(s, "name") not in ANY:
            m["services"].append({"name": _t(s, "name"), "items": items, "comment": _t(s, "description")})
    known_svc = {s["name"] for s in m["services"]}

    # Policies
    proxies = []
    for p in root.findall("./policy-list/policy"):
        name, notes = _t(p, "name"), []
        src_a, src_z, dst_a, dst_z = [], [], [], []
        for al in p.findall("./from-alias-list/alias"):
            a, z = resolve((al.text or "").strip())
            src_a += a
            src_z += z
        for al in p.findall("./to-alias-list/alias"):
            a, z = resolve((al.text or "").strip())
            dst_a += a
            dst_z += z
        svc = _t(p, "service")
        if svc and svc not in ANY and svc not in known_svc and svc.upper() in model.COMMON_SERVICES:
            m["services"].append({"name": svc, "items": [{"proto": pr, "dst": port} for pr, port in model.COMMON_SERVICES[svc.upper()]]})
            known_svc.add(svc)
        if "proxy" in name.lower() or _t(p, "proxy") or _t(p, "proxy-action"):
            notes.append(tr('Proxy-Aktion nicht übernommen – Web-/App-Schutz auf der Sophos-Regel setzen'))
            proxies.append(name)
        fw = _t(p, "firewall", "Allowed").lower()
        m["rules"].append({
            "name": name, "enabled": _t(p, "enabled", "true").lower() in ("true", "1", "yes"),
            "action": "accept" if fw.startswith("allow") else ("reject" if "reset" in fw else "drop"),
            "src_zones": list(dict.fromkeys(src_z)), "dst_zones": list(dict.fromkeys(dst_z)),
            "src": list(dict.fromkeys(src_a)), "dst": list(dict.fromkeys(dst_a)),
            "services": [svc] if svc and svc not in ANY else [], "log": _t(p, "log", "true").lower() not in ("false", "0"),
            "schedule": _t(p, "schedule"), "comment": _t(p, "description"), "notes": notes})
        for z in src_z + dst_z:
            model.add_interface(m, z, z)

    R = model.report
    R(m, "concepts", tr('Interfaces und Zonen-Aliase (Any-Trusted, Any-External …)'), "partial", len(m["interfaces"]),
      tr('Werden im nächsten Schritt Sophos-Zonen zugeordnet; Aliase werden aufgelöst.'))
    R(m, "objects", tr('Adressen aus Adressgruppen (Host, Netz, Bereich, FQDN)'), "supported", len(m["addresses"]))
    R(m, "objects", tr('Adressgruppen'), "supported", len(m["address_groups"]))
    R(m, "objects", tr('Dienste'), "supported", len(m["services"]))
    R(m, "interfaces", tr('Interfaces, VLANs, Routen, DHCP'), "manual", 0, tr('Werden von diesem Tool nicht verwaltet.'))
    R(m, "rules", tr('Policies'), "supported", len(m["rules"]))
    if proxies:
        R(m, "rules", tr('Proxy-Policies (HTTP-/HTTPS-Proxy …)'), "manual", len(proxies), "", proxies)
    R(m, "rules", tr('NAT (1-to-1, SNAT, dynamisches NAT)'), "manual", 0, tr('Als NAT-Regeln auf Sophos nachbauen.'))
    R(m, "advanced", tr('VPN, Authentifizierung, HA'), "manual", 0, tr('Bewusst nicht übernommen.'))
    m["warnings"].append(tr('Das WatchGuard-XML-Schema ist nicht offiziell dokumentiert – Ergebnis besonders sorgfältig prüfen.'))
    return m
