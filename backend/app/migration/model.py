"""Migrationsassistent (wie im Sophos Firewall Config Studio): Konfigurationen anderer Hersteller übernehmen.

Jeder Hersteller-Parser liefert ein neutrales Zwischenmodell (Migration). Der Umwandler (convert.py) macht daraus
Sophos-Objekte im XML-Format (wie Entities.xml); für REST-Firewalls wandelt der vorhandene Import (importer.to_rest)
weiter um. Übernommen wird nie direkt: Ergebnis ist ein Entwurf (Vier-Augen-Freigabe), eine Vorlage oder eine
Entities.xml zum Herunterladen.

Zwischenmodell (alles einfache dicts, damit es sich im Speicher halten und als JSON ausgeben lässt):
  interfaces:  {name, zone, ip, kind, note}           – Quell-Interfaces bzw. -Zonen; zone = Vorschlag (LAN/WAN/DMZ…)
  addresses:   {name, type, value…, comment}           – type: host | network | range | fqdn | mac | host6 | network6
                                                         | country | unsupported
  address_groups: {name, members, comment}
  services:    {name, items: [{proto, dst, src, icmp_type, ip_proto}], comment}   – proto: TCP | UDP | ICMP | ICMPV6 | IP
  service_groups: {name, members, comment}
  rules:       {name, enabled, action, src_zones, dst_zones, src, dst, services, log, schedule, comment, notes}
               – src_zones/dst_zones: Namen aus interfaces (leer = beliebig); src/dst/services: Objektnamen (leer = Any)
  nat:         {name, summary}                         – nur für den Bericht (NAT wird manuell nachgebaut)
  report:      {section, feature, status, count, note, items}  – status: supported | partial | manual | unsupported
"""

STATUSES = ("supported", "partial", "manual", "unsupported")
SECTIONS = ("concepts", "objects", "interfaces", "rules", "advanced")


def new(vendor: str) -> dict:
    return {"vendor": vendor, "source": {}, "interfaces": [], "addresses": [], "address_groups": [], "services": [],
            "service_groups": [], "rules": [], "nat": [], "report": [], "warnings": []}


def report(m: dict, section: str, feature: str, status: str, count: int = 0, note: str = "",
           items: list[str] | None = None) -> None:
    m["report"].append({"section": section, "feature": feature, "status": status, "count": count, "note": note,
                        "items": (items or [])[:200]})


def add_interface(m: dict, name: str, zone: str = "", ip: str = "", kind: str = "", note: str = "") -> None:
    if name and not any(i["name"] == name for i in m["interfaces"]):
        m["interfaces"].append({"name": name, "zone": guess_zone(zone or name), "source_zone": zone, "ip": ip,
                                "kind": kind, "note": note})


def guess_zone(hint: str) -> str:
    """Vorschlag für die Sophos-Zone aus Rolle, Zonen- oder Interfacename."""
    h = (hint or "").lower()
    if any(w in h for w in ("wan", "untrust", "external", "internet", "outside", "x1")):
        return "WAN"
    if "dmz" in h or "optional" in h:
        return "DMZ"
    if any(w in h for w in ("vpn", "ssl", "tunnel", "ipsec")):
        return "VPN"
    if any(w in h for w in ("wlan", "wifi", "wireless", "guest")):
        return "WiFi"
    if any(w in h for w in ("lan", "trust", "internal", "inside", "x0")):
        return "LAN"
    return "LAN"


# Gängige vordefinierte Dienste der Hersteller (Name → Ports), falls die Konfiguration sie nicht selbst enthält
COMMON_SERVICES = {
    "HTTP": [("TCP", "80")], "HTTPS": [("TCP", "443")], "DNS": [("TCP", "53"), ("UDP", "53")],
    "SSH": [("TCP", "22")], "TELNET": [("TCP", "23")], "FTP": [("TCP", "21")], "SMTP": [("TCP", "25")],
    "SMTPS": [("TCP", "465")], "SUBMISSION": [("TCP", "587")], "POP3": [("TCP", "110")], "POP3S": [("TCP", "995")],
    "IMAP": [("TCP", "143")], "IMAPS": [("TCP", "993")], "NTP": [("UDP", "123")], "SNMP": [("UDP", "161")],
    "RDP": [("TCP", "3389")], "LDAP": [("TCP", "389")], "LDAPS": [("TCP", "636")], "SMB": [("TCP", "445")],
    "SYSLOG": [("UDP", "514")], "DHCP": [("UDP", "67:68")], "TFTP": [("UDP", "69")], "KERBEROS": [("TCP", "88"), ("UDP", "88")],
    "MYSQL": [("TCP", "3306")], "MS-SQL": [("TCP", "1433")], "SIP": [("UDP", "5060"), ("TCP", "5060")],
    "PING": [("ICMP", "")], "ICMP": [("ICMP", "")], "IKE": [("UDP", "500"), ("UDP", "4500")],
}
