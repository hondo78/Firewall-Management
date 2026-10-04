"""Verbindungsanalyse: Verbindungen eines Zeitraums, Einstufung (legitim / nicht legitim) und Regel-Vorlagen.

- Ebene „host“: je Quell-/Ziel-IP; Ebene „net“: IPv4 auf /24 zusammengefasst (übersichtlicher bei vielen Clients).
- Einstufungen (FlowDecision) gelten für IP oder Netz; eine genauere Einstufung schlägt eine allgemeinere.
- Vorlage: legitime Verbindungen → Allow-Regeln, nicht legitime → Drop-Regeln (optional). Je Ziel und Dienst eine
  Regel mit allen Quellen – so erlaubt die Regel nur, was tatsächlich beobachtet wurde (kein Kreuzprodukt aus
  Quellen und Zielen). Vorhandene Host-/Dienstobjekte werden wiederverwendet, fehlende mit Präfix angelegt.
"""
import ipaddress
import re
from collections import defaultdict
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from ..i18n import tr
from ..models import FlowBucket, FlowDecision
from ..sophos import entities

LEVELS = ("host", "net")
MAX_EDGES = 5000


def _net(ip: str, level: str) -> str:
    if level != "net":
        return ip
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return str(ipaddress.ip_network(f"{ip}/{24 if addr.version == 4 else 64}", strict=False))


def _contains(spec: str, ip_or_net: str) -> bool:
    try:
        return ipaddress.ip_network(ip_or_net, strict=False).subnet_of(ipaddress.ip_network(spec, strict=False))
    except (ValueError, TypeError):
        return spec == ip_or_net


def _specificity(spec: str) -> int:
    try:
        return ipaddress.ip_network(spec, strict=False).prefixlen
    except ValueError:
        return 0


def edge_key(src: str, dst: str, protocol: str, dst_port: int) -> str:
    return f"{src}|{dst}|{protocol}|{dst_port}"


# --- Namen aus der Konfiguration -----------------------------------------------------------------------------

def address_names(config: dict[str, list[dict]]) -> dict[str, str]:
    """IP bzw. Netz (CIDR) → Name des Host-/Netzobjekts der Firewall (REST- und XML-Format)."""
    out: dict[str, str] = {}
    for o in config.get("addressesIpv4", []):
        if o.get("type") == "ipv4Address" and o.get("ipv4Address"):
            out.setdefault(o["ipv4Address"], o["name"])
        elif o.get("type") == "ipv4Network" and o.get("ipv4NetworkAddress"):
            out.setdefault(f"{o['ipv4NetworkAddress']}/{o.get('cidr')}", o["name"])
    for o in config.get("IPHost", []):
        if o.get("HostType") == "IP" and o.get("IPAddress"):
            out.setdefault(o["IPAddress"], o["Name"])
        elif o.get("HostType") == "Network" and o.get("IPAddress") and o.get("Subnet"):
            try:
                cidr = ipaddress.IPv4Network(f"0.0.0.0/{o['Subnet']}").prefixlen
                out.setdefault(f"{o['IPAddress']}/{cidr}", o["Name"])
            except ValueError:
                pass
    return out


def service_names(config: dict[str, list[dict]]) -> dict[tuple[str, int], str]:
    """(Protokoll, Zielport) → Name eines Dienstes mit genau diesem einen Port (REST- und XML-Format)."""
    out: dict[tuple[str, int], str] = {}

    def port(v) -> int | None:
        if isinstance(v, dict):
            return v.get("from") if v.get("from") == v.get("to") else None
        s = str(v or "")
        return int(s) if s.isdigit() else None
    for o in config.get("services", []):
        details = o.get("services") or []
        if o.get("type") == "tcpOrUdp" and len(details) == 1:
            p = port(details[0].get("destinationPort"))
            if p:
                out.setdefault(((details[0].get("protocol") or "").upper(), p), o["name"])
    for o in config.get("Services", []):
        details = (o.get("ServiceDetails") or {}).get("ServiceDetail") or []
        details = details if isinstance(details, list) else [details]
        if o.get("Type") == "TCPorUDP" and len(details) == 1:
            p = port(details[0].get("DestinationPort"))
            if p:
                out.setdefault(((details[0].get("Protocol") or "").upper(), p), o["Name"])
    return out


def _name_for(names: dict[str, str], spec: str) -> str:
    if spec in names:
        return names[spec]
    if "/" not in spec:
        best = None
        for net, name in names.items():
            if "/" in net and _contains(net, spec) and (best is None or _specificity(net) > _specificity(best[0])):
                best = (net, name)
        if best:
            return f"({best[1]})"
    return ""


# --- Abfrage -------------------------------------------------------------------------------------------------

def decisions(db: DbSession, firewall_id: str) -> list[FlowDecision]:
    return list(db.execute(select(FlowDecision).where(FlowDecision.firewall_id == firewall_id)).scalars())


def verdict_for(decs: list[FlowDecision], src: str, dst: str, protocol: str, dst_port: int) -> tuple[FlowDecision | None, bool]:
    """Passende Einstufung: genau (True) oder geerbt von einem umfassenderen Netz (False); die genaueste gewinnt."""
    best, best_score = None, -1
    for d in decs:
        if d.protocol != protocol or d.dst_port != dst_port:
            continue
        if not (_contains(d.src, src) and _contains(d.dst, dst)):
            continue
        score = _specificity(d.src) + _specificity(d.dst)
        if score > best_score:
            best, best_score = d, score
    exact = bool(best and best.src == src and best.dst == dst)
    return best, exact


def query(db: DbSession, firewall_id: str, start: datetime, end: datetime, level: str = "host",
          config: dict | None = None) -> dict:
    """Verbindungen im Zeitraum, zusammengefasst je Quelle/Ziel/Protokoll/Port (und Zonen, Aktion)."""
    hour_start = start.replace(minute=0, second=0, microsecond=0)
    rows = db.execute(
        select(FlowBucket.src_ip, FlowBucket.dst_ip, FlowBucket.protocol, FlowBucket.dst_port, FlowBucket.src_zone,
               FlowBucket.dst_zone, FlowBucket.action, func.sum(FlowBucket.count), func.sum(FlowBucket.bytes),
               func.min(FlowBucket.first_seen), func.max(FlowBucket.last_seen),
               func.group_concat(FlowBucket.rule_name) if db.bind.dialect.name == "sqlite"
               else func.string_agg(FlowBucket.rule_name, ","))
        .where(FlowBucket.firewall_id == firewall_id, FlowBucket.hour >= hour_start, FlowBucket.hour <= end,
               FlowBucket.last_seen >= start)
        .group_by(FlowBucket.src_ip, FlowBucket.dst_ip, FlowBucket.protocol, FlowBucket.dst_port, FlowBucket.src_zone,
                  FlowBucket.dst_zone, FlowBucket.action)).all()
    edges: dict[tuple, dict] = {}
    for src, dst, proto, port, sz, dz, action, count, nbytes, first, last, rules in rows:
        s, d = _net(src, level), _net(dst, level)
        k = (s, d, proto, port, sz, dz, action)
        e = edges.get(k)
        if e is None:
            e = edges[k] = {"src": s, "dst": d, "protocol": proto, "dst_port": port, "src_zone": sz, "dst_zone": dz,
                            "action": action, "count": 0, "bytes": 0, "first_seen": first, "last_seen": last,
                            "rules": set(), "hosts": set()}
        e["count"] += int(count or 0)
        e["bytes"] += int(nbytes or 0)
        e["first_seen"] = min(e["first_seen"], first)
        e["last_seen"] = max(e["last_seen"], last)
        e["rules"] |= {r for r in (rules or "").split(",") if r}
        e["hosts"] |= {src, dst}
    names = address_names(config or {})
    svcs = service_names(config or {})
    decs = decisions(db, firewall_id)
    out = []
    for e in sorted(edges.values(), key=lambda x: -x["count"])[:MAX_EDGES]:
        dec, exact = verdict_for(decs, e["src"], e["dst"], e["protocol"], e["dst_port"])
        out.append({**e, "key": edge_key(e["src"], e["dst"], e["protocol"], e["dst_port"]),
                    "rules": sorted(e["rules"]), "hosts": len(e["hosts"]),
                    "src_name": _name_for(names, e["src"]), "dst_name": _name_for(names, e["dst"]),
                    "service": svcs.get((e["protocol"], e["dst_port"]), ""),
                    "verdict": dec.verdict if dec else None, "verdict_exact": exact,
                    "note": dec.note if dec else "", "decided_at": dec.decided_at if dec else None})
    counts = {v: sum(1 for e in out if e["verdict"] == v) for v in ("legit", "illegit")}
    counts["open"] = sum(1 for e in out if not e["verdict"])
    return {"edges": out, "total": len(edges), "truncated": len(edges) > MAX_EDGES, "counts": counts}


def decide(db: DbSession, firewall_id: str, user_id: str, items: list[dict], verdict: str | None, note: str) -> int:
    """Einstufung setzen (verdict legit/illegit) oder entfernen (None). items: {src, dst, protocol, dst_port}."""
    n = 0
    for it in items:
        src, dst = str(it["src"]).strip(), str(it["dst"]).strip()
        for spec in (src, dst):
            try:
                ipaddress.ip_network(spec, strict=False)
            except ValueError:
                raise ValueError(tr('Ungültige Adresse „{0}“', spec))
        proto, port = str(it["protocol"]).upper()[:12], int(it.get("dst_port") or 0)
        row = db.execute(select(FlowDecision).where(
            FlowDecision.firewall_id == firewall_id, FlowDecision.src == src, FlowDecision.dst == dst,
            FlowDecision.protocol == proto, FlowDecision.dst_port == port)).scalar()
        if verdict is None:
            if row:
                db.delete(row)
                n += 1
            continue
        if row is None:
            row = FlowDecision(firewall_id=firewall_id, src=src, dst=dst, protocol=proto, dst_port=port)
            db.add(row)
        row.verdict, row.note, row.decided_by = verdict, note.strip()[:2000], user_id
        from ..models import utcnow
        row.decided_at = utcnow()
        n += 1
    return n


# --- Vorlage -------------------------------------------------------------------------------------------------

def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s).strip("_")


def build_template_items(edges: list[dict], config: dict[str, list[dict]], fmt: str, *, prefix: str,
                         include_allow: bool = True, include_deny: bool = True, log_traffic: bool = True,
                         position: str = "top", per_connection: bool = False) -> tuple[list[dict], list[str], dict]:
    """Vorlagen-Einträge (ensure) für Objekte und Regeln aus eingestuften Verbindungen.
    Rückgabe: (Einträge, Hinweise, Zähler)."""
    from ..importer import Skip, to_rest
    names = address_names(config)
    svcs = service_names(config)
    xml_objs: dict[tuple[str, str], dict] = {}          # (Entität, Name) → XML-Objekt (neu anzulegen)
    notes: list[str] = []

    def host(spec: str) -> str:
        if spec in names:
            return names[spec]
        net = ipaddress.ip_network(spec, strict=False)
        if net.version != 4:
            raise ValueError(tr('IPv6 wird für Regeln noch nicht unterstützt'))
        if net.num_addresses == 1:
            name = f"{prefix}H_{net.network_address}"
            obj = {"Name": name, "IPFamily": "IPv4", "HostType": "IP", "IPAddress": str(net.network_address)}
        else:
            name = f"{prefix}N_{net.network_address}_{net.prefixlen}"
            obj = {"Name": name, "IPFamily": "IPv4", "HostType": "Network", "IPAddress": str(net.network_address),
                   "Subnet": str(net.netmask)}
        xml_objs[("IPHost", name)] = {**obj, "Description": tr('Aus Verbindungsanalyse')}
        names[spec] = name
        return name

    def service(proto: str, port: int) -> str:
        if (proto, port) in svcs:
            return svcs[(proto, port)]
        name = f"{prefix}{proto}_{port}"
        xml_objs[("Services", name)] = {"Name": name, "Description": tr('Aus Verbindungsanalyse'), "Type": "TCPorUDP",
                                        "ServiceDetails": {"ServiceDetail": [
                                            {"SourcePort": "1:65535", "DestinationPort": str(port), "Protocol": proto}]}}
        svcs[(proto, port)] = name
        return name

    groups: dict[tuple, dict] = {}
    skipped = 0
    for e in edges:
        verdict = e.get("verdict")
        if not ((verdict == "legit" and include_allow) or (verdict == "illegit" and include_deny)):
            continue
        if e["protocol"] not in ("TCP", "UDP") or not e["dst_port"]:
            skipped += 1
            continue
        try:
            src, dst = host(e["src"]), host(e["dst"])
        except ValueError:
            skipped += 1
            continue
        svc = service(e["protocol"], e["dst_port"])
        action = "Accept" if verdict == "legit" else "Drop"
        key = (action, e["src_zone"], e["dst_zone"], dst, svc) + ((src,) if per_connection else ())
        g = groups.setdefault(key, {"sources": [], "count": 0})
        if src not in g["sources"]:
            g["sources"].append(src)
        g["count"] += e["count"]
    if skipped:
        notes.append(tr('{0} Verbindungen ohne TCP/UDP-Port bzw. mit IPv6 übersprungen', skipped))

    rules: list[tuple[str, dict]] = []
    used: set[str] = {entities.oname(r) for r in config.get(entities.PRIMARY_RULES[fmt], [])}
    # Drop-Regeln zuerst – oben in der Regelliste wirken sie vor allgemeineren Allow-Regeln
    for key, g in sorted(groups.items(), key=lambda kv: (kv[0][0] != "Drop", kv[0][1], kv[0][2], kv[0][3], kv[0][4])):
        action, sz, dz, dst, svc = key[:5]
        short = lambda n: _safe(n[len(prefix):] if prefix and n.startswith(prefix) else n)  # noqa: E731 – Präfix nur einmal
        base = f"{prefix}{'DENY' if action == 'Drop' else 'ALLOW'}_{_safe(sz or 'any')}-{_safe(dz or 'any')}_{short(dst)}_{short(svc)}"
        if per_connection:
            base += f"_{short(key[5])}"
        base = base[:80]
        name, i = base, 2
        while name in used:
            name, i = f"{base[:76]}_{i}", i + 1
        used.add(name)
        pol = {"Action": action, "LogTraffic": "Enable" if log_traffic else "Disable", "SkipLocalDestined": "Disable",
               "SourceNetworks": {"Network": g["sources"]}, "DestinationNetworks": {"Network": [dst]},
               "Services": {"Service": [svc]}, "Schedule": "All The Time"}
        if sz:
            pol["SourceZones"] = {"Zone": [sz]}
        if dz:
            pol["DestinationZones"] = {"Zone": [dz]}
        rules.append((name, {"Name": name, "Description": tr('Aus Verbindungsanalyse: {0} Verbindungen', g["count"]),
                             "IPFamily": "IPv4", "Status": "Enable", "PolicyType": "Network", "NetworkPolicy": pol}))

    items: list[dict] = []
    pos = {"type": "top" if position == "top" else "bottom"}
    if fmt == "xml":
        for (entity, name), obj in xml_objs.items():
            items.append({"entity": entity, "name": name, "action": "ensure", "data": obj})
        for name, rule in (reversed(rules) if position == "top" else rules):
            items.append({"entity": "FirewallRule", "name": name, "action": "ensure", "data": rule, "position": pos})
    else:
        lookup: dict[str, str] = {}
        for ent in entities.REST_RESOURCES:
            for o in config.get(ent, []):
                lookup.setdefault(o.get("name", ""), ent)
        for (entity, name), obj in xml_objs.items():
            target, data = to_rest(entity, obj, lookup)
            lookup[name] = target
            items.append({"entity": target, "name": name, "action": "ensure", "data": data})
        for name, rule in (reversed(rules) if position == "top" else rules):
            try:
                target, data = to_rest("FirewallRule", rule, lookup)
            except Skip as e:
                notes.append(f"{name}: {e}")
                continue
            items.append({"entity": target, "name": name, "action": "ensure", "data": data, "position": pos})
    counts = {"rules": len(rules), "allow": sum(1 for k in groups if k[0] == "Accept"),
              "deny": sum(1 for k in groups if k[0] == "Drop"), "objects": len(xml_objs)}
    return items, notes, counts
