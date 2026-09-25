"""Regel-Analyse („Linting“) für beide Formate.

Regeln werden in ein gemeinsames Modell übersetzt (Zonen, Netze, Dienste als Mengen; None = beliebig).
Prüfungen:
- any_any / wan_open     : zu offene Freigaben
- shadowed               : Regel wird von einer früheren, aktiven Regel vollständig abgedeckt (nie getroffen)
- no_log_wan             : Freigabe aus dem Internet ohne Protokollierung
- disabled / unused / duplicate_address : Aufräum-Hinweise (nur im Gesamtbericht)
Die Mengenprüfung ist bewusst namensbasiert (keine IP-Arithmetik) – Befunde sind Hinweise, keine Beweise.
"""
import json
import re
from dataclasses import dataclass

from .sophos import entities

SEVERITY_ORDER = {"high": 0, "medium": 1, "info": 2}
ALL_TIME = {None, "", "All The Time"}


@dataclass
class Rule:
    entity: str
    name: str
    index: int
    enabled: bool
    action: str            # accept | drop | reject
    src_zones: frozenset | None
    dst_zones: frozenset | None
    src_nets: frozenset | None
    dst_nets: frozenset | None
    services: frozenset | None
    schedule: str | None
    log: bool
    kind: str = "firewall"


def _set(values) -> frozenset | None:
    values = [v for v in values if v and v != "Any"]
    return frozenset(values) if values else None


def _names(items) -> list[str]:
    items = items if isinstance(items, list) else ([items] if items else [])
    return [i.get("name") if isinstance(i, dict) else i for i in items]


def _rest_nets(nets: dict | None) -> frozenset | None:
    if not nets or nets.get("any"):
        return None
    out = []
    for k, v in nets.items():
        if isinstance(v, list):
            out += _names(v)
    return _set(out)


def normalize(entity: str, obj: dict, index: int) -> Rule:
    if entity == "FirewallRule":
        r = entities.rule_references(obj)
        pol = obj.get("NetworkPolicy") or obj.get("UserPolicy") or {}

        def lst(container, key):
            v = (pol.get(container) or {})
            v = v.get(key) if isinstance(v, dict) else v
            return v if isinstance(v, list) else ([v] if v else [])
        return Rule(entity, obj.get("Name", ""), index, obj.get("Status") != "Disable",
                    (pol.get("Action") or "accept").lower(),
                    _set(lst("SourceZones", "Zone")), _set(lst("DestinationZones", "Zone")),
                    _set(lst("SourceNetworks", "Network")), _set(lst("DestinationNetworks", "Network")),
                    _set(r["services"]), pol.get("Schedule"), pol.get("LogTraffic") == "Enable",
                    (obj.get("PolicyType") or "Network").lower())
    svc = obj.get("servicesOrGroups") or {}
    return Rule(entity, obj.get("name", ""), index, obj.get("enabled", True) is not False,
                (obj.get("action") or "accept").lower(),
                None if (obj.get("sourceZones") or {}).get("any") else _set(_names((obj.get("sourceZones") or {}).get("zones"))),
                None if (obj.get("destinationZones") or {}).get("any") else _set(_names((obj.get("destinationZones") or {}).get("zones"))),
                _rest_nets(obj.get("sourceNetworks")), _rest_nets(obj.get("destinationNetworks")),
                None if svc.get("any") or not svc else _set(_names(svc.get("services")) + _names(svc.get("serviceGroups"))),
                (obj.get("schedule") or {}).get("name"), bool(obj.get("logTraffic")),
                obj.get("ruleType") or "firewall")


def _covers(outer: frozenset | None, inner: frozenset | None) -> bool:
    return outer is None or (inner is not None and inner <= outer)


def covers(p: Rule, r: Rule) -> bool:
    return (_covers(p.src_zones, r.src_zones) and _covers(p.dst_zones, r.dst_zones)
            and _covers(p.src_nets, r.src_nets) and _covers(p.dst_nets, r.dst_nets)
            and _covers(p.services, r.services)
            and (p.schedule in ALL_TIME or p.schedule == r.schedule))


def wan_zones(config: dict) -> set[str]:
    out = {"WAN", "wan"}
    for z in config.get("zones", []):
        if (z.get("type") or "").lower() == "wan":
            out.add(z["name"])
    for z in config.get("Zone", []):
        if (z.get("Type") or "").upper() == "WAN":
            out.add(z["Name"])
    return out


def rules_of(config: dict) -> list[Rule]:
    out = []
    for entity in ("FirewallRule", "firewallRulesIpv4", "firewallRulesIpv6"):
        out += [normalize(entity, o, i) for i, o in enumerate(config.get(entity, []))]
    return out


def _f(severity, code, entity, name, message) -> dict:
    return {"severity": severity, "code": code, "entity": entity, "label": entities.LABELS.get(entity, entity),
            "name": name, "message": message}


def check_rule(r: Rule, earlier: list[Rule], wan: set[str]) -> list[dict]:
    out = []
    if not r.enabled or r.kind == "waf":
        return out
    if r.action == "accept":
        if r.src_nets is None and r.dst_nets is None and r.services is None:
            zones = "" if r.src_zones is None and r.dst_zones is None else " (nur Zonen eingeschränkt)"
            out.append(_f("high", "any_any", r.entity, r.name,
                          f"Erlaubt beliebige Quelle → beliebiges Ziel mit beliebigen Diensten{zones}"))
        from_wan = r.src_zones is None or bool(r.src_zones & wan)
        if from_wan and r.src_zones is not None and (r.dst_nets is None or r.services is None):
            out.append(_f("high", "wan_open", r.entity, r.name,
                          "Zugriff aus dem Internet (WAN) auf "
                          + ("beliebige Ziele" if r.dst_nets is None else "beliebige Dienste")))
        if from_wan and r.src_zones is not None and not r.log:
            out.append(_f("medium", "no_log_wan", r.entity, r.name,
                          "Freigabe aus dem Internet ohne Protokollierung"))
    for p in earlier:
        if p.entity != r.entity or not p.enabled or p.kind == "waf" or not covers(p, r):
            continue
        if p.action == r.action:
            out.append(_f("medium", "shadowed", r.entity, r.name,
                          f"Wird nie getroffen: Regel „{p.name}“ (Position {p.index + 1}) deckt sie bereits ab "
                          "(gleiche Aktion – redundant)"))
        else:
            out.append(_f("high", "shadowed", r.entity, r.name,
                          f"Wird nie getroffen: Regel „{p.name}“ (Position {p.index + 1}) deckt sie ab und "
                          f"{'verwirft' if p.action != 'accept' else 'erlaubt'} den Verkehr vorher"))
        break
    return out


def _referenced_names(config: dict) -> set[str]:
    names = set()
    for entity in entities.REFERRING_ENTITIES:
        for obj in config.get(entity, []):
            names |= {n for _, n in entities.references(entity, obj)}
    # NAT-Regeln werden nicht strukturiert ausgewertet – jeder dort vorkommende Name gilt als verwendet
    for entity in ("NATRule", "natRulesIpv4"):
        for obj in config.get(entity, []):
            text = json.dumps(obj, ensure_ascii=False)
            names |= {n for n in _all_object_names(config) if f'"{n}"' in text}
    return names


_OBJECT_ENTITIES = ("IPHost", "IPHostGroup", "FQDNHost", "FQDNHostGroup", "MACHost", "Services", "ServiceGroup",
                    "addressesIpv4", "addressGroupsIpv4", "addressesIpv6", "addressGroupsIpv6", "addressesFqdn",
                    "addressGroupsFqdn", "addressesMac", "services", "serviceGroups")


def _all_object_names(config: dict) -> set[str]:
    return {entities.oname(o) for e in _OBJECT_ENTITIES for o in config.get(e, [])}


def _address_key(entity: str, o: dict) -> str | None:
    if entity == "IPHost":
        return "|".join(str(o.get(k, "")) for k in ("HostType", "IPAddress", "Subnet", "StartIPAddress", "EndIPAddress"))
    if entity in ("addressesIpv4", "addressesIpv6"):
        return "|".join(str(o.get(k, "")) for k in ("type", "ipv4Address", "ipv4NetworkAddress", "cidr",
                                                    "ipv4AddressStart", "ipv4AddressEnd", "ipv6Address"))
    return None


def analyze(config: dict) -> list[dict]:
    """Gesamtbericht einer Konfiguration."""
    wan = wan_zones(config)
    findings = []
    rules = rules_of(config)
    for r in rules:
        findings += check_rule(r, [p for p in rules if p.index < r.index], wan)
        if not r.enabled:
            findings.append(_f("info", "disabled", r.entity, r.name, "Deaktiviert – löschen, falls nicht mehr benötigt"))
    used = _referenced_names(config)
    for entity in _OBJECT_ENTITIES:
        seen: dict[str, str] = {}
        for o in config.get(entity, []):
            name = entities.oname(o)
            if o.get("isInternal"):
                continue
            if name not in used:
                findings.append(_f("info", "unused", entity, name, "Wird von keiner Regel, Gruppe oder NAT-Regel verwendet"))
            key = _address_key(entity, o)
            if key and key.strip("|"):
                if key in seen:
                    findings.append(_f("info", "duplicate_address", entity, name,
                                       f"Gleiche Adresse wie „{seen[key]}“"))
                else:
                    seen[key] = name
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["label"], f["name"]))


def for_change(before: dict, after: dict, ops: list[dict]) -> list[dict]:
    """Befunde, die ein Antrag neu einführt (nur geänderte/neue Regeln, Vergleich mit dem Stand davor)."""
    touched = {(o["entity"], o["name"]) for o in ops if o["action"] != "remove"}
    moved_or_changed_rules = {o["entity"] for o in ops if o["entity"] in entities.RULE_ENTITIES}
    wan = wan_zones(after)
    rules = rules_of(after)
    old_keys = {_key(f) for f in _rule_findings(before)}
    out = []
    for r in rules:
        # geänderte Regeln prüfen – und bei Regeländerungen auch nachfolgende, die neu verdeckt sein könnten
        if (r.entity, r.name) not in touched and r.entity not in moved_or_changed_rules:
            continue
        for f in check_rule(r, [p for p in rules if p.index < r.index], wan):
            if _key(f) not in old_keys:
                out.append(f)
    return sorted(out, key=lambda f: SEVERITY_ORDER[f["severity"]])


def _key(f: dict) -> tuple:
    # Positionsnummern verschieben sich durch den Antrag – für den Vergleich ignorieren
    return f["code"], f["entity"], f["name"], re.sub(r" \(Position \d+\)", "", f["message"])


def _rule_findings(config: dict) -> list[dict]:
    wan = wan_zones(config)
    rules = rules_of(config)
    out = []
    for r in rules:
        out += check_rule(r, [p for p in rules if p.index < r.index], wan)
    return out
