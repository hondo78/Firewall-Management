"""Demo-Konfigurationen für die Sophos-Attrappe (Struktur wie SFOS-XML-API / Entities.xml)."""


def zone(name, ztype="LAN", desc=""):
    return "Zone", {"Name": name, "Type": ztype, "Description": desc}


def host(name, ip, subnet=None, desc=""):
    if subnet:
        return "IPHost", {"Name": name, "IPFamily": "IPv4", "HostType": "Network", "IPAddress": ip,
                          "Subnet": subnet, "Description": desc}
    return "IPHost", {"Name": name, "IPFamily": "IPv4", "HostType": "IP", "IPAddress": ip, "Description": desc}


def host_range(name, start, end, desc=""):
    return "IPHost", {"Name": name, "IPFamily": "IPv4", "HostType": "IPRange", "StartIPAddress": start,
                      "EndIPAddress": end, "Description": desc}


def host_group(name, hosts, desc=""):
    return "IPHostGroup", {"Name": name, "Description": desc, "HostList": {"Host": hosts}, "IPFamily": "IPv4"}


def fqdn(name, value, desc=""):
    return "FQDNHost", {"Name": name, "FQDN": value, "Description": desc}


def service(name, proto, dport, desc=""):
    return "Services", {"Name": name, "Description": desc, "Type": "TCPorUDP", "ServiceDetails": {
        "ServiceDetail": [{"SourcePort": "1:65535", "DestinationPort": dport, "Protocol": proto}]}}


def service_group(name, services, desc=""):
    return "ServiceGroup", {"Name": name, "Description": desc, "ServiceList": {"Service": services}}


def schedule(name, desc=""):
    return "Schedule", {"Name": name, "Description": desc, "Type": "Recurring"}


def rule(name, src_zones, dst_zones, src_nets=None, dst_nets=None, services=None, action="Accept", log=True,
         status="Enable", desc="", sched="All The Time"):
    pol = {
        "Action": action, "LogTraffic": "Enable" if log else "Disable", "SkipLocalDestined": "Disable",
        "SourceZones": {"Zone": src_zones}, "DestinationZones": {"Zone": dst_zones}, "Schedule": sched,
    }
    if src_nets:
        pol["SourceNetworks"] = {"Network": src_nets}
    if dst_nets:
        pol["DestinationNetworks"] = {"Network": dst_nets}
    if services:
        pol["Services"] = {"Service": services}
    pol.update({"DSCPMarking": "-1", "WebFilter": "None", "ApplicationControl": "None",
                "IntrusionPrevention": "None", "ScanVirus": "Disable", "ZeroDayProtection": "Disable",
                "ProxyMode": "Disable", "DecryptHTTPS": "Disable"})
    return "FirewallRule", {"Name": name, "Description": desc, "IPFamily": "IPv4", "Status": status,
                            "PolicyType": "Network", "NetworkPolicy": pol}


BASE = [
    zone("LAN", "LAN", "Internes Netz"), zone("WAN", "WAN", "Internet"), zone("DMZ", "DMZ", "Server-DMZ"),
    zone("VPN", "VPN", "Site-to-Site und Remote Access"), zone("WiFi", "WiFi", "Gäste-WLAN"),
    schedule("All The Time", "Immer"), schedule("Work hours (5 Day week)", "Mo–Fr 08–18 Uhr"),
    service("HTTP", "TCP", "80"), service("HTTPS", "TCP", "443"), service("DNS", "UDP", "53"),
    service("SMTP", "TCP", "25"), service("SSH", "TCP", "22"), service("RDP", "TCP", "3389"),
    service("NTP", "UDP", "123"), service("IMAPS", "TCP", "993"),
    service_group("Web", ["HTTP", "HTTPS"], "Web-Zugriff"),
    fqdn("sophos-update", "*.sophos.com", "Sophos-Updates"),
]

FIREWALLS = [
    {
        "serial": "X21002ZENTRALE1", "name": "FW-Zentrale", "hostname": "fw-zentrale.example.local",
        "model": "XGS2300_SO01_SFOS 21.0.1 MR-1-Build272", "firmware": "SF01V_SO01_21.0.1.272",
        "ips": ["203.0.113.10"], "group": "Zentrale",
        "objects": BASE + [
            host("LAN-Netz", "192.168.10.0", "255.255.255.0", "Clients Zentrale"),
            host("Webserver-DMZ", "10.10.20.10", desc="Öffentlicher Webserver"),
            host("Mailserver", "10.10.20.25", desc="Exchange-Relay"),
            host("DNS-Server", "192.168.10.2"),
            host_range("Admin-PCs", "192.168.10.200", "192.168.10.220", "IT-Administration"),
            host_group("DMZ-Server", ["Webserver-DMZ", "Mailserver"]),
            rule("LAN nach Internet", ["LAN"], ["WAN"], ["LAN-Netz"], None, ["Web", "DNS", "NTP"],
                 desc="Standard-Internetzugang"),
            rule("Internet nach Webserver", ["WAN"], ["DMZ"], None, ["Webserver-DMZ"], ["HTTPS"],
                 desc="Veröffentlichung Webseite"),
            rule("Mail eingehend", ["WAN"], ["DMZ"], None, ["Mailserver"], ["SMTP"]),
            rule("Admin SSH in DMZ", ["LAN"], ["DMZ"], ["Admin-PCs"], ["DMZ-Server"], ["SSH", "RDP"],
                 desc="Wartungszugang", sched="Work hours (5 Day week)"),
            rule("Gäste-WLAN Internet", ["WiFi"], ["WAN"], None, None, ["Web", "DNS"]),
            rule("VPN nach LAN", ["VPN"], ["LAN"], None, ["LAN-Netz"], None, desc="Filialen-Zugriff"),
            rule("Alte Testregel", ["LAN"], ["DMZ"], None, None, None, status="Disable",
                 desc="Kann weg – Projekt beendet"),
        ],
    },
    {
        "serial": "X11600HAMBURG01", "name": "FW-Filiale-Hamburg", "hostname": "fw-hh.example.local",
        "model": "XGS116_SO01_SFOS 21.0.1 MR-1-Build272", "firmware": "SF01V_SO01_21.0.1.272",
        "ips": ["198.51.100.20"], "group": "Filialen",
        "objects": BASE + [
            host("LAN-Netz", "192.168.20.0", "255.255.255.0", "Clients Hamburg"),
            host("Drucker-HH", "192.168.20.50"),
            rule("LAN nach Internet", ["LAN"], ["WAN"], ["LAN-Netz"], None, ["Web", "DNS", "NTP"]),
            rule("LAN nach Zentrale", ["LAN"], ["VPN"], ["LAN-Netz"], None, None, desc="Site-to-Site"),
            rule("Gäste-WLAN Internet", ["WiFi"], ["WAN"], None, None, ["Web", "DNS"]),
        ],
    },
    {
        "serial": "X11600MUENCHEN1", "name": "FW-Filiale-München", "hostname": "fw-muc.example.local",
        "model": "XGS116_SO01_SFOS 20.0.2 MR-2-Build378", "firmware": "SF01V_SO01_20.0.2.378",
        "ips": ["192.0.2.30"], "group": "Filialen",
        "objects": BASE + [
            host("LAN-Netz", "192.168.30.0", "255.255.255.0", "Clients München"),
            rule("LAN nach Internet", ["LAN"], ["WAN"], ["LAN-Netz"], None, ["Web", "DNS", "NTP", "IMAPS"]),
            rule("LAN nach Zentrale", ["LAN"], ["VPN"], ["LAN-Netz"], None, None),
        ],
    },
    {
        # Nicht in Sophos Central registriert – nur über die lokale XML-API erreichbar
        "serial": "C0100LABOR00001", "name": "FW-Labor", "hostname": "fw-labor.example.local",
        "model": "SFVUNL_SO01_SFOS 21.0.1 MR-1-Build272", "firmware": "SF01V_SO01_21.0.1.272",
        "ips": [], "group": None, "central": False,
        "objects": BASE + [
            host("Labornetz", "172.16.0.0", "255.255.0.0"),
            rule("Labor nach Internet", ["LAN"], ["WAN"], ["Labornetz"], None, ["Web", "DNS"]),
        ],
    },
]


# WAF-Regel im XML-Format (Webserver-Schutz) – passend zur REST-Demo „shop.example.com“
WAF_RULE = {
    "Name": "shop.example.com", "Description": "Webserver-Schutz", "IPFamily": "IPv4", "Status": "Enable",
    "PolicyType": "HTTPBased",
    "HTTPBasedPolicy": {
        "HostedAddress": "#Port2", "HTTPS": "Enable", "ListenPort": "443", "Domains": {"Domain": ["shop.example.com"]},
        "AccessPaths": {"AccessPath": [{"allowed_networks": "Any IPv4", "auth_profile": "", "backend": "shop-web", "be_path": "",
                                        "block_unknown_country": "1", "hot_standby": "0", "path": "/",
                                        "stickysession_status": "0", "websocket_passthrough": "0"}]},
        "Exceptions": {"Exception": [{"op": "and", "path": ["/api/*"], "skip_threats_filter_categories": ["sql_injection_attacks"],
                                      "skipav": "0", "skipbadclients": "0", "skipcookie": "1", "skipform": "1",
                                      "skipform_missingtoken": "0", "skiphtmlrewrite": "0", "skipurl": "1", "source": "Any IPv4"}]},
        "ProtocolSecurity": "shop", "CompressionSupport": "Disable", "RewriteHTML": "0", "PassHostHeader": "Enable",
        "RewriteCookies": "Enable", "IntrusionPrevention": "generalpolicy", "TrafficShapingPolicy": "None",
        "Certificate": "shop.example.com", "RedirectHTTP": "Enable", "InterfaceUnavailable": "0", "BackendsUnavailable": "0",
        "ResponseFieldSize": "8192",
    },
}
