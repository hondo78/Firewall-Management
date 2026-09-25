"""Import einer Entities.xml: Vergleich, Umwandlung XML → REST und Übernahme in den Entwurf."""
from app import importer
from app.sophos import xmlconv

from .conftest import rule
from .test_workflow import setup_firewall

XML = xmlconv.build_entities_xml([
    ("IPHost", {"Name": "Server", "IPFamily": "IPv4", "HostType": "IP", "IPAddress": "10.0.0.9"}),   # geändert
    ("IPHost", {"Name": "Netz", "IPFamily": "IPv4", "HostType": "Network", "IPAddress": "10.1.0.0",
                "Subnet": "255.255.0.0"}),                                                            # neu
    ("IPHost", {"Name": "#Port1", "IPFamily": "IPv4", "HostType": "System Host"}),                     # System
    ("IPHost", {"Name": "Liste", "IPFamily": "IPv4", "HostType": "IPList", "ListOfIPAddresses": "1.1.1.1,2.2.2.2"}),
    ("Services", {"Name": "Web8080", "Type": "TCPorUDP", "ServiceDetails": {"ServiceDetail": [
        {"SourcePort": "1:65535", "DestinationPort": "8080", "Protocol": "TCP"}]}}),
    ("Services", {"Name": "GRE", "Type": "IP", "ServiceDetails": {"ServiceDetail": [{"ProtocolName": "GRE"}]}}),
    ("FirewallRule", rule("Neu-Regel", src="LAN", dst="WAN", services=["Web8080"])),
    ("Certificate", {"Name": "Geheim"}),
])


def test_review_rest_conversion():
    cfg = {"addressesIpv4": [{"name": "Server", "type": "ipv4Address", "ipv4Address": "10.0.0.1", "isInternal": False}],
           "zones": [{"name": "LAN"}, {"name": "WAN"}]}
    parsed, version = importer.parse_upload(xmlconv.build_tar(XML))
    items = {i["name"]: i for i in importer.review(cfg, "rest", parsed)}
    assert items["Server"]["status"] == "changed" and items["Server"]["diff"][0]["field"] == "ipv4Address"
    assert items["Netz"]["status"] == "new" and items["Netz"]["data"]["cidr"] == 16
    assert items["Liste"]["data"]["ipv4Addresses"] == ["1.1.1.1", "2.2.2.2"]
    assert items["#Port1"]["status"] == "unsupported" and items["GRE"]["status"] == "unsupported"
    assert items["Geheim"]["status"] == "unsupported"
    r = items["Neu-Regel"]["data"]
    assert r["servicesOrGroups"] == {"services": [{"name": "Web8080"}]} and r["sourceZones"] == {"zones": [{"name": "LAN"}]}
    assert items["Web8080"]["data"]["services"][0] == {"protocol": "tcp", "sourcePort": "1:65535", "destinationPort": "8080"}


def test_import_into_draft_xml_firewall(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    r = client.post(f"/api/firewalls/{fw_id}/import/review", headers=admin,
                    files={"file": ("Entities.xml", XML, "application/xml")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "data" not in body["items"][0]
    by_name = {i["name"]: i for i in body["items"]}
    assert by_name["Server"]["status"] == "changed" and by_name["Netz"]["status"] == "new"
    keys = [by_name[n]["key"] for n in ("Netz", "Web8080", "Neu-Regel", "Server")]
    r = client.post(f"/api/firewalls/{fw_id}/import/apply", headers=admin, json={"token": body["token"], "keys": keys})
    assert r.status_code == 200 and r.json()["added"] == 4, r.json()
    ops = [(o["action"], o["name"]) for o in r.json()["draft"]["operations"]]
    # Schreibreihenfolge: Hosts, Dienste, dann die Regel
    assert ops == [("update", "Server"), ("add", "Netz"), ("add", "Web8080"), ("add", "Neu-Regel")]
    # Token gehört nur diesem Benutzer/dieser Firewall
    assert client.post(f"/api/firewalls/{fw_id}/import/apply", headers=admin,
                       json={"token": "falsch", "keys": keys}).status_code == 410


def test_country_names_keep_their_key():
    cfg = {"firewallRulesIpv4": [{"name": "Geo", "sourceNetworks": {"countries": [{"name": "Austria"}]}}]}
    parsed, _ = importer.parse_upload(xmlconv.build_entities_xml([("FirewallRule", {
        "Name": "Geo", "IPFamily": "IPv4", "Status": "Enable", "PolicyType": "Network", "NetworkPolicy": {
            "Action": "Accept", "SourceZones": {"Zone": ["WAN"]}, "SourceNetworks": {"Network": ["Austria"]}}})]))
    item = importer.review(cfg, "rest", parsed)[0]
    assert item["data"]["sourceNetworks"] == {"countries": [{"name": "Austria"}]}
