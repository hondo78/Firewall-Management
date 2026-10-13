"""FortiGate (FortiOS) – unverschlüsseltes Konfigurations-Backup (.conf) → Zwischenmodell.

Format: verschachtelte Blöcke  config <pfad> / edit "<name>" / set <key> <werte…> / next / end.
"""
import shlex

from ..i18n import tr
from . import model

ANY_ADDR = {"all", "any", "none", ""}
ANY_SVC = {"ALL", "ANY", "all", "any"}


def parse_tree(text: str) -> dict:
    """{ "firewall address": { "name": { "subnet": [...], ... } }, ... } – nur die oberste Ebene der config-Blöcke
    mit edit-Einträgen; verschachtelte config-Blöcke landen als dict unter ihrem Pfad im Eintrag."""
    root: dict = {}
    stack: list[tuple[str, dict]] = []          # (art, knoten) – art: config | edit
    cur: dict = root
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tok = shlex.split(line, posix=True)
        except ValueError:
            tok = line.split()
        if not tok:
            continue
        cmd = tok[0]
        if cmd == "config":
            path = " ".join(tok[1:])
            node = cur.setdefault(path, {})
            stack.append(("config", cur))
            cur = node
        elif cmd == "edit":
            name = tok[1] if len(tok) > 1 else ""
            node = cur.setdefault(name, {})
            stack.append(("edit", cur))
            cur = node
        elif cmd == "set":
            if len(tok) >= 2:
                cur[tok[1]] = tok[2:]
        elif cmd == "unset":
            pass
        elif cmd in ("next", "end"):
            if stack:
                _, cur = stack.pop()
    return root


def _v(entry: dict, key: str, default: str = "") -> str:
    v = entry.get(key)
    return " ".join(v) if isinstance(v, list) else (default if v is None else str(v))


def _list(entry: dict, key: str) -> list[str]:
    v = entry.get(key)
    return list(v) if isinstance(v, list) else []


def _portrange(spec: str) -> tuple[str, str]:
    """FortiOS „dst[:src]“, z. B. „1000-2000:1024-65535“."""
    dst, _, src = spec.partition(":")
    return dst.replace("-", ":"), (src.replace("-", ":") if src else "")


def parse(data: bytes) -> dict:
    text = data.decode("utf-8", errors="replace")
    if "config firewall" not in text and "config system" not in text:
        raise ValueError(tr('Keine FortiGate-Konfiguration erkannt (config firewall … fehlt)'))
    t = parse_tree(text)
    m = model.new("fortigate")
    gl = t.get("system global", {})
    m["source"] = {"hostname": _v(gl, "hostname"), "version": text.splitlines()[0][:120] if text else ""}

    # Interfaces und Zonen
    zone_of: dict[str, str] = {}
    for zname, z in t.get("system zone", {}).items():
        for i in _list(z, "interface"):
            zone_of[i] = zname
    vlans = 0
    for name, i in t.get("system interface", {}).items():
        kind = _v(i, "type", "physical")
        if kind in ("tunnel", "loopback") or name in ("ssl.root", "l2t.root", "naf.root", "l2t.root"):
            continue
        ip = " ".join(_list(i, "ip")[:2])
        role = _v(i, "role")
        model.add_interface(m, name, zone_of.get(name) or role or _v(i, "alias") or name, ip, kind,
                            tr('Rolle {0}', role) if role else "")
        vlans += kind == "vlan"
    for zname in t.get("system zone", {}):
        model.add_interface(m, zname, zname, kind="zone")

    # Adressen
    unsupported = []
    for name, a in t.get("firewall address", {}).items():
        typ = _v(a, "type", "ipmask")
        c = _v(a, "comment")
        if typ == "ipmask":
            sub = _list(a, "subnet") or ["0.0.0.0", "0.0.0.0"]
            if name.lower() in ANY_ADDR:
                continue
            import ipaddress
            net = ipaddress.IPv4Network(f"{sub[0]}/{sub[1] if len(sub) > 1 else '32'}", strict=False)
            m["addresses"].append({"name": name, "type": "host" if net.prefixlen == 32 else "network",
                                   "value": str(net), "comment": c})
        elif typ == "iprange":
            m["addresses"].append({"name": name, "type": "range", "start": _v(a, "start-ip"), "end": _v(a, "end-ip"), "comment": c})
        elif typ == "fqdn":
            m["addresses"].append({"name": name, "type": "fqdn", "value": _v(a, "fqdn"), "comment": c})
        elif typ == "mac":
            m["addresses"].append({"name": name, "type": "mac", "value": (_list(a, "macaddr") or [""])[0], "comment": c})
        elif typ == "geography":
            m["addresses"].append({"name": name, "type": "country", "value": _v(a, "country"), "comment": c,
                                   "note": tr('Länderobjekt ({0}) – auf Sophos als Ländergruppe anlegen', _v(a, "country"))})
            unsupported.append(name)
        else:
            m["addresses"].append({"name": name, "type": "unsupported", "comment": c,
                                   "note": tr('Adresstyp „{0}“ (z. B. dynamisch/SDN) hat keine Entsprechung', typ)})
            unsupported.append(name)
    for name, a in t.get("firewall address6", {}).items():
        if name.lower() in ANY_ADDR:
            continue
        ip6 = _v(a, "ip6")
        if ip6:
            m["addresses"].append({"name": name, "type": "network6" if not ip6.endswith("/128") else "host6", "value": ip6,
                                   "comment": _v(a, "comment")})
    for path in ("firewall addrgrp", "firewall addrgrp6"):
        for name, g in t.get(path, {}).items():
            m["address_groups"].append({"name": name, "members": [x for x in _list(g, "member") if x.lower() not in ANY_ADDR],
                                        "comment": _v(g, "comment")})

    # Dienste
    for name, s in t.get("firewall service custom", {}).items():
        if name in ANY_SVC:
            continue
        proto = _v(s, "protocol", "TCP/UDP/SCTP").upper()
        items = []
        if proto.startswith("TCP"):
            for spec in _list(s, "tcp-portrange"):
                d, src = _portrange(spec)
                items.append({"proto": "TCP", "dst": d, "src": src})
            for spec in _list(s, "udp-portrange"):
                d, src = _portrange(spec)
                items.append({"proto": "UDP", "dst": d, "src": src})
        elif proto in ("ICMP", "ICMP6"):
            items.append({"proto": "ICMPV6" if proto == "ICMP6" else "ICMP", "icmp_type": _v(s, "icmptype")})
        elif proto == "IP":
            items.append({"proto": "IP", "ip_proto": _v(s, "protocol-number")})
        m["services"].append({"name": name, "items": items, "comment": _v(s, "comment")})
    for name, g in t.get("firewall service group", {}).items():
        m["service_groups"].append({"name": name, "members": [x for x in _list(g, "member") if x not in ANY_SVC],
                                    "comment": _v(g, "comment")})
    known_svc = {s["name"] for s in m["services"]} | {g["name"] for g in m["service_groups"]}

    # Regeln
    profiles = ("av-profile", "webfilter-profile", "ips-sensor", "application-list", "dnsfilter-profile",
                "emailfilter-profile", "file-filter-profile", "dlp-sensor", "waf-profile")
    sec, ident, nat_policies, sched = [], [], [], []
    for pid, p in t.get("firewall policy", {}).items():
        name = _v(p, "name") or f"Policy {pid}"
        notes = []
        used = [k for k in profiles if p.get(k)]
        if used or _v(p, "utm-status") == "enable":
            notes.append(tr('Sicherheitsprofile nicht übernommen ({0}) – Web/IPS/AV/App auf der Sophos-Regel setzen', ", ".join(used) or "UTM"))
            sec.append(name)
        if p.get("groups") or p.get("users"):
            notes.append(tr('Benutzer/Gruppen nicht übernommen – „Übereinstimmung mit bekannten Benutzern“ einrichten'))
            ident.append(name)
        if _v(p, "nat") == "enable":
            notes.append(tr('NAT war in der Policy aktiv – als verknüpfte NAT-Regel nachbauen'))
            nat_policies.append(name)
        if _v(p, "schedule", "always").lower() != "always":
            sched.append(name)
        services = [x for x in _list(p, "service") if x not in ANY_SVC]
        for s in services:
            if s not in known_svc and s.upper() in model.COMMON_SERVICES:
                m["services"].append({"name": s, "items": [{"proto": pr, "dst": port} for pr, port in model.COMMON_SERVICES[s.upper()]],
                                      "comment": tr('Vordefinierter Dienst')})
                known_svc.add(s)
        m["rules"].append({
            "name": name, "enabled": _v(p, "status", "enable") != "disable",
            "action": "accept" if _v(p, "action", "deny") == "accept" else "drop",
            "src_zones": [x for x in _list(p, "srcintf") if x != "any"], "dst_zones": [x for x in _list(p, "dstintf") if x != "any"],
            "src": [x for x in _list(p, "srcaddr") + _list(p, "srcaddr6") if x.lower() not in ANY_ADDR],
            "dst": [x for x in _list(p, "dstaddr") + _list(p, "dstaddr6") if x.lower() not in ANY_ADDR],
            "services": services, "log": _v(p, "logtraffic", "utm") != "disable",
            "schedule": _v(p, "schedule", "always"), "comment": _v(p, "comments"), "notes": notes})
        for side in ("srcintf", "dstintf"):
            for i in _list(p, side):
                if i != "any":
                    model.add_interface(m, i, i)

    # NAT (nur Bericht)
    for name, v in t.get("firewall vip", {}).items():
        m["nat"].append({"name": name, "summary": f"VIP {_v(v, 'extip')} → {_v(v, 'mappedip')} ({_v(v, 'extintf')})"
                                                 + (f" Port {_v(v, 'extport')}→{_v(v, 'mappedport')}" if _v(v, 'portforward') == 'enable' else "")})
    for name, v in t.get("firewall ippool", {}).items():
        m["nat"].append({"name": name, "summary": f"IP-Pool {_v(v, 'startip')}–{_v(v, 'endip')}"})
    for n in nat_policies:
        m["nat"].append({"name": n, "summary": tr('Policy mit „set nat enable“ (Masquerading)')})

    # Bericht
    R = model.report
    R(m, "concepts", tr('Netzsegmentierung (Interface → Zone)'), "partial", len(m["interfaces"]),
      tr('Interfaces und FortiGate-Zonen werden im nächsten Schritt Sophos-Zonen zugeordnet; die Regeln übernehmen diese Zonen.'))
    R(m, "objects", tr('Adressen (IP, Netz, Bereich, FQDN, MAC, IPv6)'), "supported",
      sum(1 for a in m["addresses"] if a["type"] not in ("country", "unsupported")))
    if unsupported:
        R(m, "objects", tr('Länder- und dynamische Adressen'), "manual", len(unsupported),
          tr('Keine direkte Entsprechung – Regeln damit werden deaktiviert übernommen.'), unsupported)
    R(m, "objects", tr('Adressgruppen'), "supported", len(m["address_groups"]),
      tr('Verschachtelte Gruppen werden aufgelöst, gemischte IP/FQDN-Gruppen getrennt.'))
    R(m, "objects", tr('Dienste und Dienstgruppen'), "supported", len(m["services"]) + len(m["service_groups"]))
    R(m, "interfaces", tr('Interfaces, VLANs, Routen, DHCP, DNS'), "manual", len(m["interfaces"]),
      tr('Werden von diesem Tool nicht verwaltet – auf der Sophos Firewall einrichten (Port-Zuordnung beachten).'),
      [f"{i['name']} {i['ip']}".strip() for i in m["interfaces"]])
    R(m, "rules", tr('Firewall-Policies'), "supported", len(m["rules"]),
      tr('Quell-/Ziel-Interface → Zone, Adressen, Dienste, Aktion, Protokollierung.'))
    if sec:
        R(m, "rules", tr('Sicherheitsprofile (AV, IPS, Web, App)'), "manual", len(sec), "", sec)
    if ident:
        R(m, "rules", tr('Benutzerbezogene Regeln'), "manual", len(ident), "", ident)
    if sched:
        R(m, "rules", tr('Zeitpläne in Regeln'), "manual", len(sched), tr('Regeln gelten nach der Übernahme immer.'), sched)
    if m["nat"]:
        R(m, "rules", tr('NAT (VIP, IP-Pools, Policy-NAT)'), "manual", len(m["nat"]),
          tr('Als NAT-Regeln auf Sophos nachbauen.'), [f"{n['name']}: {n['summary']}" for n in m["nat"]])
    adv = [k for k in ("vpn ipsec phase1-interface", "vpn ssl settings", "system sdwan", "user local", "user group",
                       "system ha", "log syslogd setting") if t.get(k)]
    if adv:
        R(m, "advanced", tr('VPN, SD-WAN, Benutzer, HA, Logging'), "manual", len(adv),
          tr('Bewusst nicht übernommen – nach Sophos-Best-Practice neu einrichten.'), adv)
    return m
