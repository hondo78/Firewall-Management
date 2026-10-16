"""Migrationsassistent: Hersteller-Parser, Umwandlung in Sophos-Objekte, Bericht, Ziele Entwurf/Vorlage/Download."""
import base64
import json
from urllib.parse import quote_plus

import pytest

from app.migration import barracuda, convert, fortigate, paloalto, service, sonicwall, watchguard

from .test_workflow import make_user, setup_firewall

FORTIGATE = b'''#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
config system global
    set hostname "FGT-Branch"
end
config system interface
    edit "port1"
        set ip 203.0.113.2 255.255.255.0
        set role wan
    next
    edit "internal"
        set ip 192.168.1.1 255.255.255.0
        set role lan
    next
    edit "dmz"
        set ip 10.10.10.1 255.255.255.0
        set role dmz
    next
end
config firewall address
    edit "all"
        set subnet 0.0.0.0 0.0.0.0
    next
    edit "Webserver"
        set subnet 10.10.10.10 255.255.255.255
        set comment "DMZ Web"
    next
    edit "LAN_Net"
        set subnet 192.168.1.0 255.255.255.0
    next
    edit "DHCP_Range"
        set type iprange
        set start-ip 192.168.1.100
        set end-ip 192.168.1.200
    next
    edit "update.example.com"
        set type fqdn
        set fqdn "update.example.com"
    next
    edit "Russia"
        set type geography
        set country "RU"
    next
end
config firewall addrgrp
    edit "Servers"
        set member "Webserver" "update.example.com"
    next
end
config firewall service custom
    edit "HTTPS"
        set tcp-portrange 443
    next
    edit "Custom-App"
        set tcp-portrange 8080-8090 9000:1024-65535
        set udp-portrange 9001
    next
    edit "PING"
        set protocol ICMP
        set icmptype 8
    next
end
config firewall service group
    edit "Web"
        set member "HTTPS" "Custom-App"
    next
end
config firewall policy
    edit 1
        set name "LAN-to-Internet"
        set srcintf "internal"
        set dstintf "port1"
        set srcaddr "LAN_Net"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat enable
        set av-profile "default"
        set logtraffic all
    next
    edit 2
        set name "Web-in"
        set srcintf "port1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "Servers"
        set action accept
        set schedule "always"
        set service "Web" "HTTP"
    next
    edit 3
        set name "Block-RU"
        set srcintf "port1"
        set dstintf "dmz"
        set srcaddr "Russia"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "ALL"
    next
end
config firewall vip
    edit "Web-VIP"
        set extip 203.0.113.10
        set mappedip "10.10.10.10"
        set extintf "port1"
    next
end
'''

PALOALTO = b'''<config version="10.2.0"><shared><address><entry name="DNS-Google"><ip-netmask>8.8.8.8</ip-netmask></entry></address></shared>
<devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<zone><entry name="trust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
<entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
<entry name="dmz"><network><layer3><member>ethernet1/3</member></layer3></network></entry></zone>
<address><entry name="web-srv"><ip-netmask>10.1.1.10/32</ip-netmask><description>Web</description></entry>
<entry name="lan-net"><ip-netmask>192.168.10.0/24</ip-netmask></entry>
<entry name="pool"><ip-range>192.168.10.50-192.168.10.60</ip-range></entry>
<entry name="vendor"><fqdn>api.vendor.example</fqdn></entry></address>
<address-group><entry name="servers"><static><member>web-srv</member><member>vendor</member></static></entry>
<entry name="dyn"><dynamic><filter>'web'</filter></dynamic></entry></address-group>
<service><entry name="tcp-8443"><protocol><tcp><port>8443</port></tcp></protocol></entry>
<entry name="multi"><protocol><udp><port>500,4500</port></udp></protocol></entry></service>
<service-group><entry name="vpn-svc"><members><member>multi</member></members></entry></service-group>
<rulebase><security><rules>
<entry name="Outbound"><from><member>trust</member></from><to><member>untrust</member></to><source><member>lan-net</member></source>
<destination><member>any</member></destination><application><member>web-browsing</member><member>ssl</member></application>
<service><member>application-default</member></service><action>allow</action><profile-setting><group><member>default</member></group></profile-setting></entry>
<entry name="Web-In"><from><member>untrust</member></from><to><member>dmz</member></to><source><member>any</member></source>
<destination><member>servers</member></destination><application><member>any</member></application>
<service><member>service-https</member><member>tcp-8443</member></service><action>allow</action></entry>
<entry name="Admin"><from><member>trust</member></from><to><member>dmz</member></to><source><member>192.168.10.5</member></source>
<destination><member>web-srv</member></destination><application><member>any</member></application>
<service><member>any</member></service><action>allow</action><disabled>yes</disabled></entry>
<entry name="Dyn"><from><member>untrust</member></from><to><member>dmz</member></to><source><member>dyn</member></source>
<destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><action>deny</action></entry>
</rules></security><nat><rules><entry name="Outbound-NAT"><to><member>untrust</member></to><source><member>lan-net</member></source>
<destination><member>any</member></destination><source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface></interface-address></dynamic-ip-and-port></source-translation></entry></rules></nat>
</rulebase></entry></vsys></entry></devices></config>'''

WATCHGUARD = b'''<?xml version="1.0"?><profile><name>WG-Office</name>
<interface-list><interface><name>External</name><if-item-list><item><physical-if><if-property>0</if-property><ip>198.51.100.2</ip></physical-if></item></if-item-list></interface>
<interface><name>Trusted</name><if-item-list><item><physical-if><if-property>1</if-property><ip>10.0.1.1</ip></physical-if></item></if-item-list></interface></interface-list>
<address-group-list>
<address-group><name>Web.1.to</name><addr-group-member><member><type>1</type><host-ip-addr>10.0.2.10</host-ip-addr></member></addr-group-member></address-group>
<address-group><name>Office.1.from</name><addr-group-member><member><type>2</type><ip-network-addr>10.0.1.0</ip-network-addr><ip-mask>255.255.255.0</ip-mask></member>
<member><type>3</type><start-ip-addr>10.0.5.1</start-ip-addr><end-ip-addr>10.0.5.9</end-ip-addr></member></addr-group-member></address-group>
</address-group-list>
<alias-list><alias><name>Web.1.to</name><alias-member-list><alias-member><type>1</type><address>Web.1.to</address><interface>Any</interface></alias-member></alias-member-list></alias>
<alias><name>OfficeNets</name><alias-member-list><alias-member><type>1</type><address>Office.1.from</address><interface>Trusted</interface></alias-member></alias-member-list></alias></alias-list>
<service-list><service><name>HTTPS</name><service-item><member><type>1</type><protocol>6</protocol><server-port>443</server-port></member></service-item></service>
<service><name>Ping</name><service-item><member><type>1</type><protocol>1</protocol></member></service-item></service></service-list>
<policy-list>
<policy><name>HTTPS-In</name><enabled>true</enabled><firewall>Allowed</firewall><service>HTTPS</service>
<from-alias-list><alias>Any-External</alias></from-alias-list><to-alias-list><alias>Web.1.to</alias></to-alias-list></policy>
<policy><name>Office-Ping</name><enabled>true</enabled><firewall>Denied</firewall><service>Ping</service>
<from-alias-list><alias>OfficeNets</alias></from-alias-list><to-alias-list><alias>Any-External</alias></to-alias-list></policy>
<policy><name>HTTP-proxy</name><enabled>false</enabled><firewall>Allowed</firewall><service>HTTP</service>
<from-alias-list><alias>Any-Trusted</alias></from-alias-list><to-alias-list><alias>Any-External</alias></to-alias-list></policy>
</policy-list></profile>'''


def sonicwall_exp() -> bytes:
    pairs = {
        "shortProdName": "TZ 470", "buildNum": "7.0.1-5035",
        "addrObjId_0": "X0 Subnet", "addrObjType_0": "4", "addrObjZone_0": "LAN", "addrObjIp1_0": "192.168.168.0", "addrObjIp2_0": "255.255.255.0",
        "addrObjId_1": "Mail Server", "addrObjType_1": "1", "addrObjZone_1": "DMZ", "addrObjIp1_1": "172.16.0.25", "addrObjIp2_1": "0.0.0.0",
        "addrObjId_2": "Servers", "addrObjType_2": "8",
        "addrObjFqdnId_0": "Updates", "addrObjFqdn_0": "upd.example.com",
        "addro_atomToGrp_0": "Mail Server", "addro_grpToGrp_0": "Servers",
        "svcObjId_0": "SMTP", "svcObjType_0": "1", "svcObjIpType_0": "6", "svcObjPort1_0": "25", "svcObjPort2_0": "25",
        "svcObjId_1": "Web Ports", "svcObjType_1": "1", "svcObjIpType_1": "6", "svcObjPort1_1": "8000", "svcObjPort2_1": "8010",
        "svcObjId_2": "Mail Services", "svcObjType_2": "2",
        "so_atomToGrp_0": "SMTP", "so_grpToGrp_0": "Mail Services",
        "zoneObjId_0": "LAN", "zoneObjId_1": "WAN", "zoneObjId_2": "DMZ",
        "iface_name_0": "X0", "iface_zone_0": "LAN", "iface_lan_ip_0": "192.168.168.168",
        "iface_name_1": "X1", "iface_zone_1": "WAN",
        "policyAction_0": "2", "policySrcZone_0": "WAN", "policyDstZone_0": "DMZ", "policySrcNet_0": "",
        "policyDstNet_0": "Servers", "policyDstSvc_0": "Mail Services", "policyEnabled_0": "1", "policyComment_0": "Mail in",
        "policyAction_1": "1", "policySrcZone_1": "LAN", "policyDstZone_1": "WAN", "policySrcNet_1": "X0 Subnet",
        "policyDstNet_1": "", "policyDstSvc_1": "Web Ports", "policyEnabled_1": "1", "policyName_1": "Block-Web-Alt",
    }
    return base64.b64encode("&".join(f"{quote_plus(k)}={quote_plus(v)}" for k, v in pairs.items()).encode())


def _zones(m):
    return {i["name"]: i["zone"] for i in m["interfaces"]}


def test_fortigate_parse_and_convert():
    m = fortigate.parse(FORTIGATE)
    assert m["source"]["hostname"] == "FGT-Branch"
    z = _zones(m)
    assert z["port1"] == "WAN" and z["internal"] == "LAN" and z["dmz"] == "DMZ"
    assert {a["name"]: a["type"] for a in m["addresses"]}["DHCP_Range"] == "range"
    out, notes = convert.convert(m, z)
    hosts = {o["Name"]: o for o in out["IPHost"]}
    assert hosts["Webserver"]["HostType"] == "IP" and hosts["LAN_Net"]["Subnet"] == "255.255.255.0"
    # gemischte Gruppe: IP- und FQDN-Teil getrennt
    assert [g["Name"] for g in out["IPHostGroup"]] == ["Servers"]
    assert out["FQDNHostGroup"][0]["FQDNHostList"]["FQDNHost"] == ["update.example.com"]
    svc = {s["Name"]: s for s in out["Services"]}
    details = svc["Custom-App"]["ServiceDetails"]["ServiceDetail"]
    assert {"SourcePort": "1024:65535", "DestinationPort": "9000", "Protocol": "TCP"} in details
    assert {"SourcePort": "1:65535", "DestinationPort": "8080:8090", "Protocol": "TCP"} in details
    assert svc["HTTP"]["ServiceDetails"]["ServiceDetail"][0]["DestinationPort"] == "80"   # vordefiniert ergänzt
    rules = {r["Name"]: r for r in out["FirewallRule"]}
    web = rules["Web-in"]["NetworkPolicy"]
    assert web["SourceZones"] == {"Zone": ["WAN"]} and web["DestinationZones"] == {"Zone": ["DMZ"]}
    assert sorted(web["DestinationNetworks"]["Network"]) == ["Servers", "Servers_FQDN"]
    assert "SourceNetworks" not in web                               # „all“ = beliebig
    # Länderobjekt → Regel wird deaktiviert, nicht weiter gefasst
    assert rules["Block-RU"]["Status"] == "Disable"
    assert any(n["name"] == "Block-RU" and n["status"] == "manual" for n in notes)
    assert rules["LAN-to-Internet"]["Status"] == "Enable"
    assert any(n["name"] == "LAN-to-Internet" and "NAT" in n["note"] for n in notes)
    report = {r["feature"]: r for r in m["report"]}
    assert any("NAT" in f and r["count"] == 2 for f, r in report.items())    # VIP + Policy-NAT


def test_paloalto_parse_and_convert():
    m = paloalto.parse(PALOALTO)
    z = _zones(m)
    assert z["untrust"] == "WAN" and z["trust"] == "LAN" and z["dmz"] == "DMZ"
    out, notes = convert.convert(m, z, prefix="PA_")
    rules = {r["Name"]: r for r in out["FirewallRule"]}
    assert set(rules) == {"PA_Outbound", "PA_Web-In", "PA_Admin", "PA_Dyn"}
    assert rules["PA_Admin"]["Status"] == "Disable"                  # im Original deaktiviert
    # Inline-IP in der Regel → eigenes Host-Objekt
    assert rules["PA_Admin"]["NetworkPolicy"]["SourceNetworks"]["Network"] == ["PA_192.168.10.5"]
    assert rules["PA_Dyn"]["Status"] == "Disable"                    # dynamische Gruppe nicht übertragbar
    svcs = rules["PA_Web-In"]["NetworkPolicy"]["Services"]["Service"]
    assert svcs == ["PA_service-https", "PA_tcp-8443"]
    assert any(n["name"] == "Outbound" and "App-ID" in n["note"] for n in notes)
    assert any(r["feature"].startswith("NAT") for r in m["report"])


def test_sonicwall_parse_and_convert():
    m = sonicwall.parse(sonicwall_exp())
    assert m["source"]["model"] == "TZ 470"
    out, notes = convert.convert(m, _zones(m))
    assert {g["Name"]: g["HostList"]["Host"] for g in out["IPHostGroup"]} == {"Servers": ["Mail Server"]}
    assert out["FQDNHost"][0]["FQDN"] == "upd.example.com"
    rules = {r["NetworkPolicy"]["Action"]: r for r in out["FirewallRule"]}
    assert rules["Accept"]["NetworkPolicy"]["Services"]["Service"] == ["Mail Services"]
    assert rules["Drop"]["Name"] == "Block-Web-Alt"
    assert rules["Drop"]["NetworkPolicy"]["SourceNetworks"]["Network"] == ["X0 Subnet"]
    svc = {s["Name"]: s for s in out["Services"]}
    assert svc["Web Ports"]["ServiceDetails"]["ServiceDetail"][0]["DestinationPort"] == "8000:8010"
    assert m["warnings"]


def test_watchguard_parse_and_convert():
    m = watchguard.parse(WATCHGUARD)
    z = _zones(m)
    assert z["Any-External"] == "WAN" and z["Any-Trusted"] == "LAN" and z["Trusted"] == "LAN"
    out, notes = convert.convert(m, z)
    rules = {r["Name"]: r for r in out["FirewallRule"]}
    https = rules["HTTPS-In"]["NetworkPolicy"]
    assert https["SourceZones"] == {"Zone": ["WAN"]} and https["DestinationNetworks"]["Network"] == ["Web.1.to"]
    ping = rules["Office-Ping"]["NetworkPolicy"]
    assert ping["Action"] == "Drop" and ping["SourceZones"] == {"Zone": ["LAN"]}
    assert ping["SourceNetworks"]["Network"] == ["Office.1.from"]
    office = next(g for g in out["IPHostGroup"] if g["Name"] == "Office.1.from")
    assert office["HostList"]["Host"] == ["10.0.1.0/24", "10.0.5.1-10.0.5.9"]
    assert rules["HTTP-proxy"]["Status"] == "Disable"
    assert any(n["name"] == "HTTP-proxy" for n in notes)


BARRACUDA = json.dumps({
    "name": "CGF-Office",
    "networks": {"objects": [
        {"name": "Webserver", "type": "generic", "included": [{"entry": {"ip": "10.0.2.10"}}]},
        {"name": "Office", "included": [{"entry": {"ip": "10.0.1.0/24"}}, {"entry": {"ip": "10.0.5.1-10.0.5.9"}},
                                        {"references": "Webserver"}]},
        {"name": "Ohne-Gast", "included": [{"entry": {"ip": "10.0.0.0/16"}}], "excluded": [{"entry": {"ip": "10.0.9.0/24"}}]},
    ]},
    "services": {"objects": [
        {"name": "Web-Ports", "entries": [{"entry": {"protocol": "TCP", "tcp": {"ports": ["8000-8010", "8443"]}}}]},
        {"name": "Web-All", "entries": [{"references": "Web-Ports"}, {"entry": {"protocol": "TCP", "tcp": {"ports": ["80"]}}}]},
    ]},
    "rules": {"rules": [
        {"name": "LAN-2-INTERNET", "action": {"type": "pass", "connection": {"references": "Dynamic NAT"}},
         "source": {"references": "Trusted LAN"}, "destination": {"references": "Internet"}, "service": {"references": "HTTP+S"}},
        {"name": "Web-In", "action": {"type": "pass"}, "source": {"references": "Any"},
         "destination": {"explicit": {"entries": [{"entry": {"ip": "10.0.2.11"}}]}}, "service": {"references": "Web-All"}},
        {"name": "Office-Sync", "action": {"type": "block"}, "bidirectional": True, "source": {"references": "Office"},
         "destination": {"references": "Private 192"}, "service": {"references": "Any"}},
        {"name": "Gast", "action": {"type": "deny"}, "source": {"references": "Ohne-Gast"}, "destination": {"references": "Any"},
         "service": {"references": "Any"}},
        {"name": "DNAT-Web", "action": {"type": "dnat"}, "source": {"references": "Internet"},
         "destination": {"references": "Webserver"}, "service": {"references": "HTTPS"}},
        {"name": "Sub", "action": {"type": "cascade"}},
    ]},
}).encode()


def test_barracuda_parse_and_convert():
    m = barracuda.parse(BARRACUDA)
    z = _zones(m)
    assert z["Internet"] == "WAN" and z["Trusted LAN"] == "LAN"
    out, notes = convert.convert(m, z)
    rules = {r["Name"]: r for r in out["FirewallRule"]}
    lan = rules["LAN-2-INTERNET"]["NetworkPolicy"]
    assert lan["SourceZones"] == {"Zone": ["LAN"]} and lan["DestinationZones"] == {"Zone": ["WAN"]}
    assert lan["Services"] == {"Service": ["HTTP+S"]} and rules["LAN-2-INTERNET"]["Status"] == "Enable"
    assert {g["Name"]: g["ServiceList"]["Service"] for g in out["ServiceGroup"]}["HTTP+S"] == ["HTTP", "HTTPS"]
    web = rules["Web-In"]["NetworkPolicy"]
    assert "SourceNetworks" not in web and web["DestinationNetworks"]["Network"] == ["Web-In (Ziel)"]
    assert web["Services"] == {"Service": ["Web-All"]}
    svc = {s["Name"]: s for s in out["Services"]}
    assert [d["DestinationPort"] for d in svc["Web-Ports"]["ServiceDetails"]["ServiceDetail"]] == ["8000:8010", "8443"]
    office = next(g for g in out["IPHostGroup"] if g["Name"] == "Office")
    assert office["HostList"]["Host"] == ["10.0.1.0/24", "10.0.5.1-10.0.5.9", "10.0.2.10"]
    # bidirektional → zwei Regeln, „Any“ als Dienst = beliebig
    assert rules["Office-Sync"]["NetworkPolicy"]["Action"] == "Drop" and "Services" not in rules["Office-Sync"]["NetworkPolicy"]
    assert rules["Office-Sync_rev"]["NetworkPolicy"]["SourceNetworks"]["Network"] == ["Private 192"]
    # Ausschlüsse → nie weiter gefasst: Regel deaktiviert
    assert rules["Gast"]["Status"] == "Disable" and rules["Gast"]["NetworkPolicy"]["Action"] == "Reject"
    assert rules["DNAT-Web"]["Status"] == "Disable" and [n["name"] for n in m["nat"]] == ["LAN-2-INTERNET", "DNAT-Web"]
    assert "Sub" not in rules and any(r["status"] == "unsupported" for r in m["report"])
    with pytest.raises(ValueError):
        barracuda.parse(b'{"networks": []}')


def test_names_are_sanitized_and_unique():
    n = convert.Names("")
    assert n.get("addr", "a,b") == "a_b"
    assert n.get("addr", "x" * 80) == "x" * 60
    assert n.get("grp", "x" * 81) == "x" * 58 + "_2"
    assert n.get("addr", "#intern") == "intern"


def test_migration_api_draft_template_download(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    vend = client.get("/api/migration/vendors", headers=admin).json()
    assert [v["id"] for v in vend] == ["fortigate", "paloalto", "sonicwall", "watchguard", "barracuda", "utm", "sophos"]
    ap = make_user(client, admin, "approver", [("Approver", None)])
    assert client.post("/api/migration/parse", headers=ap, data={"vendor": "fortigate"},
                       files={"file": ("fgt.conf", FORTIGATE)}).status_code == 403
    r = client.post("/api/migration/parse", headers=admin, data={"vendor": "fortigate"}, files={"file": ("fgt.conf", FORTIGATE)})
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["needs_zones"] and p["counts"]["rules"] == 3
    bad = client.post("/api/migration/parse", headers=admin, data={"vendor": "paloalto"}, files={"file": ("x.xml", b"<foo/>")})
    assert bad.status_code == 400
    zones = {"port1": "WAN", "internal": "LAN", "dmz": "DMZ"}
    prev = client.post("/api/migration/preview", headers=admin, json={"token": p["token"], "zone_map": zones}).json()
    assert prev["counts"]["FirewallRule"] == 3 and prev["notes"]

    # Entwurf: Vergleich mit der Firewall, dann Übernahme über den vorhandenen Import
    d = client.post("/api/migration/to-draft", headers=admin, json={"token": p["token"], "zone_map": zones, "firewall_id": fw_id})
    assert d.status_code == 200, d.text
    review = d.json()
    assert review["counts"]["new"] > 0
    keys = [i["key"] for i in review["items"] if i["status"] == "new" and i["entity"] in ("IPHost", "Services", "Zone")]
    ap_r = client.post(f"/api/firewalls/{fw_id}/import/apply", headers=admin, json={"token": review["token"], "keys": keys})
    assert ap_r.status_code == 200 and ap_r.json()["added"] == len(keys), ap_r.text

    # Vorlage im REST-Format
    t = client.post("/api/migration/to-template", headers=admin,
                    json={"token": p["token"], "zone_map": zones, "name": "Aus FortiGate", "format": "rest", "prefix": "FGT_"})
    assert t.status_code == 200, t.text
    tpl = client.get(f"/api/templates/{t.json()['id']}", headers=admin).json()
    names = [i["name"] for i in tpl["items"]]
    assert "FGT_Web-in" in names and all(n.startswith("FGT_") for n in names)

    dl = client.post("/api/migration/download", headers=admin, json={"token": p["token"], "zone_map": zones})
    assert dl.status_code == 200 and b"<FirewallRule" in dl.content and b"<IPHost" in dl.content
    actions = {e["action"] for e in client.get("/api/audit", headers=admin).json()["items"]}
    assert {"migration.parsed", "migration.to_draft_review", "migration.downloaded", "template.created"} <= actions


def test_sophos_entities_xml_source(client, admin, fake):
    xml = (b'<?xml version="1.0"?><Configuration APIVersion="2000.1"><IPHost><Name>UTM-Host</Name><IPFamily>IPv4</IPFamily>'
           b'<HostType>IP</HostType><IPAddress>10.9.9.9</IPAddress></IPHost><DHCPServer><Name>x</Name></DHCPServer></Configuration>')
    r = client.post("/api/migration/parse", headers=admin, data={"vendor": "utm"}, files={"file": ("Entities.xml", xml)}).json()
    assert r["needs_zones"] is False and r["counts"] == {"IPHost": 1, "DHCPServer": 1}
    assert {x["feature"]: x["status"] for x in r["report"]} == {"IPHost": "supported", "DHCPServer": "unsupported"}
    prev = client.post("/api/migration/preview", headers=admin, json={"token": r["token"]}).json()
    assert prev["counts"] == {"IPHost": 1}
