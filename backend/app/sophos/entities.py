"""Verwaltete Sophos-Entitäten in zwei Formaten.

- **xml**: XML-API (alt) und Sophos-Central-Import/Export – Namen wie im ExportableEntity-Enum, Schlüssel „Name“.
- **rest**: SFOS REST-API (`/api/firewall-config/v1`) – eigene Ressourcen und JSON-Strukturen, Schlüssel „name“.

Die Entitätsnamen beider Formate überschneiden sich nicht; LABELS & Co. gelten daher für beide.
Welches Format eine Firewall nutzt, bestimmt ihr Connector (`fmt_for`).
"""

# (Entität, Anzeigename, Bereich) – Reihenfolge = Reihenfolge in der Navigation
XML_MANAGED: list[tuple[str, str, str]] = [
    ("FirewallRule", "Firewall-Regeln", "Regeln & Richtlinien"),
    ("FirewallRuleGroup", "Regelgruppen", "Regeln & Richtlinien"),
    ("NATRule", "NAT-Regeln", "Regeln & Richtlinien"),
    ("IPHost", "IP-Hosts", "Hosts & Dienste"),
    ("IPHostGroup", "IP-Host-Gruppen", "Hosts & Dienste"),
    ("FQDNHost", "FQDN-Hosts", "Hosts & Dienste"),
    ("FQDNHostGroup", "FQDN-Host-Gruppen", "Hosts & Dienste"),
    ("MACHost", "MAC-Hosts", "Hosts & Dienste"),
    ("Services", "Dienste", "Hosts & Dienste"),
    ("ServiceGroup", "Dienstgruppen", "Hosts & Dienste"),
    ("Zone", "Zonen", "Netzwerk"),
    ("Schedule", "Zeitpläne", "System"),
]

# REST: Entität → (API-Pfad, Anzeigename, Bereich)
REST_RESOURCES: dict[str, tuple[str, str, str]] = {
    "firewallRulesIpv4": ("/firewall/rules/ipv4", "Firewall-Regeln IPv4", "Regeln & Richtlinien"),
    "firewallRulesIpv6": ("/firewall/rules/ipv6", "Firewall-Regeln IPv6", "Regeln & Richtlinien"),
    "natRulesIpv4": ("/nat/rules/ipv4", "NAT-Regeln IPv4", "Regeln & Richtlinien"),
    "addressesIpv4": ("/network/addresses/ipv4", "IPv4-Adressen", "Hosts & Dienste"),
    "addressGroupsIpv4": ("/network/address-groups/ipv4", "IPv4-Adressgruppen", "Hosts & Dienste"),
    "addressesIpv6": ("/network/addresses/ipv6", "IPv6-Adressen", "Hosts & Dienste"),
    "addressGroupsIpv6": ("/network/address-groups/ipv6", "IPv6-Adressgruppen", "Hosts & Dienste"),
    "addressesFqdn": ("/network/addresses/fqdn", "FQDN-Adressen", "Hosts & Dienste"),
    "addressGroupsFqdn": ("/network/address-groups/fqdn", "FQDN-Gruppen", "Hosts & Dienste"),
    "addressesMac": ("/network/addresses/mac", "MAC-Adressen", "Hosts & Dienste"),
    "countryGroups": ("/network/address-groups/country", "Ländergruppen", "Hosts & Dienste"),
    "services": ("/network/services", "Dienste", "Hosts & Dienste"),
    "serviceGroups": ("/network/service-groups", "Dienstgruppen", "Hosts & Dienste"),
    "zones": ("/network/zones", "Zonen", "Netzwerk"),
    "schedules": ("/administration/schedules", "Zeitpläne", "System"),
    # Richtlinien – in Regeln auswählbar (Bearbeitung als JSON)
    "webPolicies": ("/web/policies", "Web-Richtlinien", "Richtlinien"),
    "applicationPolicies": ("/application/policies", "Anwendungs-Richtlinien", "Richtlinien"),
    "ipsPolicies": ("/intrusion-prevention/policies", "IPS-Richtlinien", "Richtlinien"),
    "trafficShapingPolicies": ("/traffic-shaping/policies", "Traffic-Shaping", "Richtlinien"),
    # Benutzer & Schnittstellen – nur als Auswahl für Regeln/NAT (nicht über dieses Tool änderbar)
    "userGroups": ("/authentication/user-groups", "Benutzergruppen", "Benutzer & Schnittstellen"),
    "users": ("/authentication/users", "Benutzer", "Benutzer & Schnittstellen"),
    "interfaces": ("/network/interfaces/network-interfaces", "Schnittstellen", "Benutzer & Schnittstellen"),
}
# Nur lesend – werden synchronisiert, aber nicht über Anträge geändert
REST_READ_ONLY_ENTITIES = {"users", "interfaces"}
REST_MANAGED = [(e, label, section) for e, (_, label, section) in REST_RESOURCES.items()]
# Nur lesend von der API geliefert – nie mitsenden und nicht speichern (sonst Diff-Rauschen).
# ruleId liefert die echte Firewall zusätzlich (nicht in der Spezifikation). isInternal (eingebautes Objekt)
# bleibt gespeichert, damit die Oberfläche Löschen ausblenden kann; per PATCH wird es nie gesendet (unverändert).
REST_READ_ONLY = ("id", "createdAt", "updatedAt", "ruleId")

LABELS = {e: label for e, label, _ in XML_MANAGED + REST_MANAGED}

# Kompatibilität: bisherige Aufrufer meinen das XML-Format
MANAGED = XML_MANAGED
NAMES = [e for e, _, _ in XML_MANAGED]
REST_NAMES = list(REST_RESOURCES)


def fmt_for(connector: str) -> str:
    return "rest" if connector == "rest" else "xml"


def managed(fmt: str) -> list[tuple[str, str, str]]:
    return REST_MANAGED if fmt == "rest" else XML_MANAGED


def names(fmt: str) -> list[str]:
    return [e for e, _, _ in managed(fmt)]


def oname(obj: dict) -> str:
    """Objektname unabhängig vom Format."""
    return obj.get("Name") if "Name" in obj else obj.get("name", "")


def name_key(entity: str) -> str:
    return "name" if entity in REST_RESOURCES else "Name"


# Regeln mit Reihenfolge (Positionsangaben beim Anlegen/Verschieben)
RULE_ENTITIES = {"FirewallRule", "firewallRulesIpv4", "firewallRulesIpv6", "natRulesIpv4"}
PRIMARY_RULES = {"xml": "FirewallRule", "rest": "firewallRulesIpv4"}

# Schreibreihenfolge: Abhängigkeiten zuerst anlegen, beim Löschen umgekehrt
WRITE_ORDER = ["Zone", "Schedule", "IPHost", "FQDNHost", "MACHost", "IPHostGroup", "FQDNHostGroup",
               "Services", "ServiceGroup", "NATRule", "FirewallRule", "FirewallRuleGroup",
               "zones", "schedules", "addressesIpv4", "addressesIpv6", "addressesFqdn", "addressesMac",
               "addressGroupsIpv4", "addressGroupsIpv6", "addressGroupsFqdn", "countryGroups",
               "services", "serviceGroups", "webPolicies", "applicationPolicies", "ipsPolicies",
               "trafficShapingPolicies", "userGroups", "natRulesIpv4", "firewallRulesIpv4", "firewallRulesIpv6"]
_RULE_LEVEL = {"NATRule", "FirewallRule", "FirewallRuleGroup", "natRulesIpv4", "firewallRulesIpv4",
               "firewallRulesIpv6"}

# Vordefinierte Objekte, die in Regeln ohne eigenes Objekt verwendet werden dürfen
BUILTIN_REFS = {"Any", "All The Time"}

# Art eines Verweises → Entitäten, in denen das Ziel liegen kann
REF_ENTITIES = {
    "zone": ("Zone", "zones"),
    "network": ("IPHost", "IPHostGroup", "FQDNHost", "FQDNHostGroup", "MACHost",
                "addressesIpv4", "addressGroupsIpv4", "addressesIpv6", "addressGroupsIpv6", "addressesFqdn",
                "addressGroupsFqdn", "addressesMac", "countryGroups"),
    "service": ("Services", "ServiceGroup", "services", "serviceGroups"),
    "schedule": ("Schedule", "schedules"),
    "webpolicy": ("webPolicies",),
    "apppolicy": ("applicationPolicies",),
    "ipspolicy": ("ipsPolicies",),
    "tspolicy": ("trafficShapingPolicies",),
    "user": ("users", "userGroups"),
    "interface": ("interfaces",),
    "rule": ("firewallRulesIpv4", "firewallRulesIpv6"),
}


def kind_of(entity: str) -> str | None:
    return next((k for k, ents in REF_ENTITIES.items() if entity in ents), None)


def order_operations(ops: list[dict]) -> list[dict]:
    rank = {e: i for i, e in enumerate(WRITE_ORDER)}
    adds = [o for o in ops if o["action"] != "remove"]
    removes = [o for o in ops if o["action"] == "remove"]
    # stabil sortieren, damit die Reihenfolge der Regeln im Entwurf erhalten bleibt
    adds.sort(key=lambda o: rank.get(o["entity"], 100))
    removes.sort(key=lambda o: -rank.get(o["entity"], 100))
    # Regeln zuerst löschen (geben Objekte frei), Objekte erst nach allen Anlagen/Updates
    # (eine geänderte Regel verweist dann nicht mehr auf das zu löschende Objekt)
    return ([o for o in removes if o["entity"] in _RULE_LEVEL] + adds
            + [o for o in removes if o["entity"] not in _RULE_LEVEL])


# --- Verweise ------------------------------------------------------------------------------------------------

def _as_list(v) -> list:
    return v if isinstance(v, list) else ([v] if v else [])


def rule_references(rule: dict) -> dict[str, list[str]]:
    """Objekt-Referenzen einer XML-Firewall-Regel."""
    pol = rule.get("NetworkPolicy") or rule.get("UserPolicy") or {}

    def lst(container, key):
        v = (pol.get(container) or {})
        if isinstance(v, dict):
            v = v.get(key) or []
        return _as_list(v)
    return {
        "zones": lst("SourceZones", "Zone") + lst("DestinationZones", "Zone"),
        "networks": lst("SourceNetworks", "Network") + lst("DestinationNetworks", "Network"),
        "services": lst("Services", "Service"),
        "schedule": [pol["Schedule"]] if pol.get("Schedule") else [],
    }


def _names(items) -> list[str]:
    return [i.get("name") for i in _as_list(items) if isinstance(i, dict) and i.get("name")]


# REST: Schlüssel innerhalb von source/destinationNetworks → Art (Länder sind eingebaut, keine Objekte)
_REST_NET_KEYS = ("ipv4Addresses", "ipv4Groups", "ipv6Addresses", "ipv6Groups", "fqdnAddresses", "fqdnGroups",
                  "macAddresses", "countryGroups")


def rest_rule_references(rule: dict) -> list[tuple[str, str]]:
    refs: list[tuple[str, str]] = []
    for key in ("sourceZones", "destinationZones"):
        refs += [("zone", n) for n in _names((rule.get(key) or {}).get("zones"))]
    for key in ("sourceNetworks", "destinationNetworks"):
        nets = rule.get(key) or {}
        for k in _REST_NET_KEYS:
            refs += [("network", n) for n in _names(nets.get(k))]
    svc = rule.get("servicesOrGroups") or {}
    refs += [("service", n) for n in _names(svc.get("services")) + _names(svc.get("serviceGroups"))]
    if isinstance(rule.get("schedule"), dict) and rule["schedule"].get("name"):
        refs.append(("schedule", rule["schedule"]["name"]))
    sec = rule.get("securityFeatures") or {}
    for key, kind in (("webPolicy", "webpolicy"), ("applicationPolicy", "apppolicy"), ("ipsPolicy", "ipspolicy")):
        if isinstance(sec.get(key), dict) and sec[key].get("name"):
            refs.append((kind, sec[key]["name"]))
    ts = (rule.get("qos") or {}).get("trafficShapingPolicy")
    if isinstance(ts, dict) and ts.get("name"):
        refs.append(("tspolicy", ts["name"]))
    uo = ((rule.get("userAuthentication") or {}).get("usersOrGroups") or {})
    refs += [("user", n) for n in _names(uo.get("users")) + _names(uo.get("userGroups"))]
    return refs


def rest_nat_references(nat: dict) -> list[tuple[str, str]]:
    refs: list[tuple[str, str]] = []
    for key in ("originalSourceNetworks", "originalDestinationNetworks"):
        nets = nat.get(key) or {}
        for k in _REST_NET_KEYS:
            refs += [("network", n) for n in _names(nets.get(k))]
    svc = nat.get("originalServicesOrGroups") or {}
    refs += [("service", n) for n in _names(svc.get("services")) + _names(svc.get("serviceGroups"))]
    for key in ("translatedSource", "translatedDestination"):
        t = nat.get(key) or {}
        for sub in ("ipv4Address", "fqdnAddress"):
            if isinstance(t.get(sub), dict) and t[sub].get("name"):
                refs.append(("network", t[sub]["name"]))
    if isinstance(nat.get("translatedService"), dict) and nat["translatedService"].get("name"):
        refs.append(("service", nat["translatedService"]["name"]))
    for key in ("inboundInterfaces", "outboundInterfaces"):
        refs += [("interface", n) for n in _names((nat.get(key) or {}).get("interfaces"))]
    if isinstance(nat.get("linkedFirewallRule"), dict) and nat["linkedFirewallRule"].get("name"):
        refs.append(("rule", nat["linkedFirewallRule"]["name"]))
    return refs


def references(entity: str, obj: dict) -> list[tuple[str, str]]:
    """[(Art, Name)] der Objekte, auf die ein Objekt verweist."""
    if entity == "FirewallRule":
        r = rule_references(obj)
        return ([("zone", z) for z in r["zones"]] + [("network", n) for n in r["networks"]]
                + [("service", s) for s in r["services"]] + [("schedule", s) for s in r["schedule"]])
    if entity == "IPHostGroup":
        return [("network", h) for h in _as_list((obj.get("HostList") or {}).get("Host"))]
    if entity == "ServiceGroup":
        return [("service", s) for s in _as_list((obj.get("ServiceList") or {}).get("Service"))]
    if entity == "FQDNHostGroup":
        return [("network", h) for h in _as_list((obj.get("FQDNHostList") or {}).get("FQDNHost"))]
    if entity in ("firewallRulesIpv4", "firewallRulesIpv6"):
        return rest_rule_references(obj)
    if entity == "natRulesIpv4":
        return rest_nat_references(obj)
    if entity in ("addressGroupsIpv4", "addressGroupsIpv6"):
        return [("network", n) for n in _names(obj.get("ipv4Addresses") or obj.get("ipv6Addresses"))]
    if entity == "addressGroupsFqdn":
        return [("network", n) for n in _names(obj.get("fqdns"))]
    if entity == "serviceGroups":
        return [("service", n) for n in _names(obj.get("services"))]
    return []


REFERRING_ENTITIES = ("FirewallRule", "IPHostGroup", "ServiceGroup", "FQDNHostGroup", "firewallRulesIpv4",
                      "firewallRulesIpv6", "addressGroupsIpv4", "addressGroupsIpv6", "addressGroupsFqdn",
                      "serviceGroups", "natRulesIpv4")
