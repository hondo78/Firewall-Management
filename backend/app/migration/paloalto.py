"""Palo Alto Networks (PAN-OS) – running-config.xml bzw. benannter Konfigurations-Snapshot → Zwischenmodell.

Objekte aus /config/shared und der ersten vsys; weitere vsys werden im Bericht gemeldet. Regeln referenzieren Zonen
direkt (from/to) – diese werden im nächsten Schritt Sophos-Zonen zugeordnet.
"""
import xml.etree.ElementTree as ET

from ..i18n import tr
from . import model

ANY = {"any", ""}
PREDEFINED = {"service-http": [("TCP", "80"), ("TCP", "8080")], "service-https": [("TCP", "443")]}


def _members(el, tag) -> list[str]:
    node = el.find(tag) if el is not None else None
    if node is None:
        return []
    return [(m.text or "").strip() for m in node.findall("member") if (m.text or "").strip()]


def _text(el, path, default="") -> str:
    n = el.find(path) if el is not None else None
    return (n.text or "").strip() if n is not None and n.text else default


def parse(data: bytes) -> dict:
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise ValueError(tr('XML ungültig: {0}', e))
    if root.tag != "config":
        raise ValueError(tr('Keine PAN-OS-Konfiguration erkannt (Wurzelelement <config> fehlt)'))
    m = model.new("paloalto")
    m["source"] = {"version": root.get("version", "")}
    vsys_all = root.findall("./devices/entry/vsys/entry")
    vsys = vsys_all[0] if vsys_all else None
    shared = root.find("./shared")
    scopes = [s for s in (shared, vsys) if s is not None]

    # Zonen und Interfaces
    if vsys is not None:
        for z in vsys.findall("./zone/entry"):
            ifaces = []
            for kind in ("layer3", "layer2", "virtual-wire", "tap"):
                ifaces += _members(z.find("network"), kind) if z.find("network") is not None else []
            model.add_interface(m, z.get("name"), z.get("name"), kind="zone", note=", ".join(ifaces))

    # Adressen
    bad = []
    for scope in scopes:
        for a in scope.findall("./address/entry"):
            n, c = a.get("name"), _text(a, "description")
            if a.find("ip-netmask") is not None:
                v = _text(a, "ip-netmask")
                v6 = ":" in v
                single = "/" not in v or v.endswith("/32") or v.endswith("/128")
                m["addresses"].append({"name": n, "type": ("host6" if single else "network6") if v6 else ("host" if single else "network"),
                                       "value": v, "comment": c})
            elif a.find("ip-range") is not None:
                s, _, e = _text(a, "ip-range").partition("-")
                m["addresses"].append({"name": n, "type": "range", "start": s.strip(), "end": e.strip(), "comment": c})
            elif a.find("fqdn") is not None:
                m["addresses"].append({"name": n, "type": "fqdn", "value": _text(a, "fqdn"), "comment": c})
            else:
                m["addresses"].append({"name": n, "type": "unsupported", "comment": c,
                                       "note": tr('Adresstyp (z. B. ip-wildcard) hat keine Entsprechung')})
                bad.append(n)
        for g in scope.findall("./address-group/entry"):
            if g.find("dynamic") is not None:
                m["address_groups"].append({"name": g.get("name"), "members": ["__dynamic__" + g.get("name")]})
                bad.append(g.get("name"))
                continue
            m["address_groups"].append({"name": g.get("name"), "members": _members(g, "static"),
                                        "comment": _text(g, "description")})
        for s in scope.findall("./service/entry"):
            items = []
            for proto in ("tcp", "udp"):
                p = s.find(f"protocol/{proto}")
                if p is not None:
                    for port in _text(p, "port").split(","):
                        if port.strip():
                            items.append({"proto": proto.upper(), "dst": port.strip(), "src": _text(p, "source-port")})
            m["services"].append({"name": s.get("name"), "items": items, "comment": _text(s, "description")})
        for g in scope.findall("./service-group/entry"):
            m["service_groups"].append({"name": g.get("name"), "members": _members(g, "members")})
    known_svc = {s["name"] for s in m["services"]} | {g["name"] for g in m["service_groups"]}

    # Security-Regeln
    sec_prof, app_rules, user_rules, sched = [], [], [], []
    rules = vsys.findall("./rulebase/security/rules/entry") if vsys is not None else []
    for r in rules:
        name, notes = r.get("name"), []
        apps = [a for a in _members(r, "application") if a not in ANY]
        if apps:
            notes.append(tr('App-ID ({0}) nicht übernommen – Anwendungsfilter auf der Sophos-Regel setzen', ", ".join(apps[:5])))
            app_rules.append(name)
        if r.find("profile-setting") is not None:
            notes.append(tr('Sicherheitsprofile nicht übernommen – Web/IPS/AV auf der Sophos-Regel setzen'))
            sec_prof.append(name)
        users = [u for u in _members(r, "source-user") if u not in ANY]
        if users:
            notes.append(tr('Benutzer ({0}) nicht übernommen', ", ".join(users[:5])))
            user_rules.append(name)
        services = []
        for s in _members(r, "service"):
            if s in ANY or s == "application-default":
                if s == "application-default" and apps:
                    notes.append(tr('„application-default“: Ports der Anwendungen – Dienste auf Sophos prüfen'))
                continue
            if s not in known_svc and s in PREDEFINED:
                m["services"].append({"name": s, "items": [{"proto": p, "dst": port} for p, port in PREDEFINED[s]],
                                      "comment": tr('Vordefinierter Dienst')})
                known_svc.add(s)
            services.append(s)
        action = _text(r, "action", "deny")
        if r.find("schedule") is not None:
            sched.append(name)
        neg = [k for k in ("negate-source", "negate-destination") if _text(r, k) == "yes"]
        if neg:
            notes.append(tr('Negation ({0}) nicht übertragbar – Regel prüfen', ", ".join(neg)))
        m["rules"].append({
            "name": name, "enabled": _text(r, "disabled", "no") != "yes",
            "action": "accept" if action == "allow" else ("reject" if action.startswith("reset") else "drop"),
            "src_zones": [z for z in _members(r, "from") if z not in ANY], "dst_zones": [z for z in _members(r, "to") if z not in ANY],
            "src": [a for a in _members(r, "source") if a not in ANY], "dst": [a for a in _members(r, "destination") if a not in ANY],
            "services": services, "log": _text(r, "log-end", "yes") != "no", "schedule": _text(r, "schedule"),
            "comment": _text(r, "description"), "notes": notes, "hard": bool(neg)})
        for z in _members(r, "from") + _members(r, "to"):
            if z not in ANY:
                model.add_interface(m, z, z, kind="zone")
    for r in m["rules"]:
        # Negierte Quellen/Ziele lassen sich nicht abbilden → nicht weiter fassen, sondern deaktivieren
        if r.pop("hard", False):
            r["src"].append("__negated__")

    for n in (vsys.findall("./rulebase/nat/rules/entry") if vsys is not None else []):
        st = n.find("source-translation")
        dt = n.find("destination-translation")
        kind = "SNAT" if st is not None else ("DNAT" if dt is not None else "NAT")
        m["nat"].append({"name": n.get("name"), "summary": f"{kind}: {', '.join(_members(n, 'source'))} → "
                                                           f"{', '.join(_members(n, 'destination'))} ({', '.join(_members(n, 'to'))})"})

    R = model.report
    R(m, "concepts", tr('Zonen'), "supported", len(m["interfaces"]), tr('PAN-OS-Zonen werden im nächsten Schritt Sophos-Zonen zugeordnet.'))
    if len(vsys_all) > 1:
        R(m, "concepts", tr('Mehrere virtuelle Systeme (vsys)'), "partial", len(vsys_all),
          tr('Nur die erste vsys wird übernommen.'), [v.get("name") for v in vsys_all[1:]])
    R(m, "objects", tr('Adressen (ip-netmask, ip-range, FQDN)'), "supported",
      sum(1 for a in m["addresses"] if a["type"] != "unsupported"))
    if bad:
        R(m, "objects", tr('Wildcard-Adressen und dynamische Gruppen'), "unsupported", len(bad), "", bad)
    R(m, "objects", tr('Statische Adressgruppen'), "supported", sum(1 for g in m["address_groups"] if g["name"] not in bad))
    R(m, "objects", tr('Dienste und Dienstgruppen'), "supported", len(m["services"]) + len(m["service_groups"]))
    R(m, "interfaces", tr('Interfaces, Subinterfaces, Routen'), "manual", 0,
      tr('Werden von diesem Tool nicht verwaltet – auf der Sophos Firewall einrichten.'))
    R(m, "rules", tr('Security-Regeln'), "supported", len(m["rules"]))
    if app_rules:
        R(m, "rules", tr('App-ID'), "manual", len(app_rules), tr('Als Anwendungsfilter-Richtlinie nachbauen.'), app_rules)
    if sec_prof:
        R(m, "rules", tr('Sicherheitsprofile'), "manual", len(sec_prof), "", sec_prof)
    if user_rules:
        R(m, "rules", tr('Benutzerbezogene Regeln'), "manual", len(user_rules), "", user_rules)
    if sched:
        R(m, "rules", tr('Zeitpläne in Regeln'), "manual", len(sched), tr('Regeln gelten nach der Übernahme immer.'), sched)
    if m["nat"]:
        R(m, "rules", tr('NAT-Regeln'), "manual", len(m["nat"]), tr('Als NAT-Regeln auf Sophos nachbauen.'),
          [f"{n['name']}: {n['summary']}" for n in m["nat"]])
    R(m, "advanced", tr('VPN, GlobalProtect, Panorama, HA'), "manual", 0,
      tr('Bewusst nicht übernommen – nach Sophos-Best-Practice neu einrichten.'))
    return m
