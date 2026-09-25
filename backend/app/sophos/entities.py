"""Verwaltete Sophos-Entitäten (Namen wie im ExportableEntity-Enum bzw. in der XML-API)."""

# (Entität, Anzeigename, Bereich) – Reihenfolge = Reihenfolge in der Navigation
MANAGED: list[tuple[str, str, str]] = [
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
NAMES = [e for e, _, _ in MANAGED]
LABELS = {e: label for e, label, _ in MANAGED}

# Schreibreihenfolge: Abhängigkeiten zuerst anlegen, beim Löschen umgekehrt
WRITE_ORDER = ["Zone", "Schedule", "IPHost", "FQDNHost", "MACHost", "IPHostGroup", "FQDNHostGroup",
               "Services", "ServiceGroup", "NATRule", "FirewallRule", "FirewallRuleGroup"]

# Vordefinierte Objekte, die in Regeln ohne eigenes Objekt verwendet werden dürfen
BUILTIN_REFS = {"Any", "All The Time"}


def order_operations(ops: list[dict]) -> list[dict]:
    rank = {e: i for i, e in enumerate(WRITE_ORDER)}
    adds = [o for o in ops if o["action"] != "remove"]
    removes = [o for o in ops if o["action"] == "remove"]
    # stabil sortieren, damit die Reihenfolge der Regeln im Entwurf erhalten bleibt
    adds.sort(key=lambda o: rank.get(o["entity"], 50))
    removes.sort(key=lambda o: -rank.get(o["entity"], 50))
    # Regeln zuerst löschen (geben Objekte frei), Objekte erst nach allen Anlagen/Updates
    # (eine geänderte Regel verweist dann nicht mehr auf das zu löschende Objekt)
    rule_rank = rank["NATRule"]
    return ([o for o in removes if rank.get(o["entity"], 50) >= rule_rank] + adds
            + [o for o in removes if rank.get(o["entity"], 50) < rule_rank])


def rule_references(rule: dict) -> dict[str, list[str]]:
    """Objekt-Referenzen einer Firewall-Regel (für Abhängigkeitsprüfung und Anzeige)."""
    pol = rule.get("NetworkPolicy") or rule.get("UserPolicy") or {}

    def lst(container, key):
        v = (pol.get(container) or {})
        if isinstance(v, dict):
            v = v.get(key) or []
        return v if isinstance(v, list) else ([v] if v else [])
    return {
        "zones": lst("SourceZones", "Zone") + lst("DestinationZones", "Zone"),
        "networks": lst("SourceNetworks", "Network") + lst("DestinationNetworks", "Network"),
        "services": lst("Services", "Service"),
        "schedule": [pol["Schedule"]] if pol.get("Schedule") else [],
    }
