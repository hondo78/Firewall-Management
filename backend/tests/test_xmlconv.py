import xml.etree.ElementTree as ET

from app.sophos import xmlconv
from app.sophos.xmlapi import normalize_base_url

RULE_XML = """
<FirewallRule transactionid="">
  <Name>Web</Name>
  <Description>Test</Description>
  <IPFamily>IPv4</IPFamily>
  <Status>Enable</Status>
  <Position>Top</Position>
  <PolicyType>Network</PolicyType>
  <NetworkPolicy>
    <Action>Accept</Action>
    <SourceZones><Zone>LAN</Zone></SourceZones>
    <DestinationZones><Zone>WAN</Zone><Zone>DMZ</Zone></DestinationZones>
    <Services><Service>HTTPS</Service></Services>
  </NetworkPolicy>
</FirewallRule>
"""


def test_single_item_list_container_is_list():
    data = xmlconv.element_to_value(ET.fromstring(RULE_XML))
    assert data["NetworkPolicy"]["SourceZones"] == {"Zone": ["LAN"]}
    assert data["NetworkPolicy"]["DestinationZones"] == {"Zone": ["WAN", "DMZ"]}
    assert data["NetworkPolicy"]["Services"] == {"Service": ["HTTPS"]}


def test_roundtrip_without_position():
    data = xmlconv.strip_position(xmlconv.element_to_value(ET.fromstring(RULE_XML)))
    assert "Position" not in data
    again = xmlconv.element_to_value(ET.fromstring(xmlconv.to_xml("FirewallRule", data)))
    assert again == data


def test_repeated_tags_in_mixed_element():
    el = ET.fromstring("<Services><Name>X</Name><ServiceDetails><ServiceDetail><Protocol>TCP</Protocol>"
                       "</ServiceDetail></ServiceDetails></Services>")
    data = xmlconv.element_to_value(el)
    assert data == {"Name": "X", "ServiceDetails": {"ServiceDetail": [{"Protocol": "TCP"}]}}


def test_position_fields_inserted_after_status():
    data = {"Name": "R", "Description": "", "IPFamily": "IPv4", "Status": "Enable", "PolicyType": "Network"}
    out = xmlconv.with_position(data, {"type": "after", "ref": "Andere"})
    assert list(out) == ["Name", "Description", "IPFamily", "Status", "Position", "After", "PolicyType"]
    assert out["After"] == {"Name": "Andere"}
    assert xmlconv.with_position(data, {"type": "top"})["Position"] == "Top"


def test_entities_tar_roundtrip():
    objs = [("IPHost", {"Name": "H1", "IPAddress": "10.0.0.1"}), ("FirewallRule", {"Name": "R1", "Status": "Enable"})]
    tar = xmlconv.build_tar(xmlconv.build_entities_xml(objs, "2100.1"))
    parsed, version = xmlconv.parse_entities_xml(xmlconv.read_tar_entities(tar))
    assert version == "2100.1"
    assert parsed == {"IPHost": [{"Name": "H1", "IPAddress": "10.0.0.1"}],
                      "FirewallRule": [{"Name": "R1", "Status": "Enable"}]}


def test_normalize_base_url():
    assert normalize_base_url("10.0.0.1") == "https://10.0.0.1:4444"
    assert normalize_base_url("https://fw.local:4443") == "https://fw.local:4443"
    assert normalize_base_url("http://sophos-mock:8000/fw/SN1/") == "http://sophos-mock:8000/fw/SN1"
