"""SFOS REST-API: Client (Präfix, Paging, Fehler), Connector (PATCH/Move/Rollback) und Workflow im REST-Format."""
import json

import httpx
import pytest

from app.sophos import connector, entities, restapi
from app.sophos.restapi import RestApiClient, RestApiError

BASE = "https://fw.test:4444"


def client_for(handler, base=BASE):
    restapi._PREFIX_BY_BASE.clear()
    return RestApiClient(base, "sfos_test_key", transport=httpx.MockTransport(handler))


def test_prefix_fallback_on_html_404_and_paging():
    calls = []

    def handler(req: httpx.Request):
        calls.append(req.url.path)
        assert req.headers["authorization"] == "Bearer sfos_test_key"
        if req.url.path.startswith("/api/"):
            return httpx.Response(404, text="<html>Error:404 Page not found</html>", headers={"content-type": "text/html"})
        page = int(req.url.params["page"])
        items = [{"id": f"id{page}{i}", "name": f"z{page}{i}"} for i in range(100 if page == 1 else 3)]
        return httpx.Response(200, json={"items": items, "pages": {"current": page, "total": 2, "size": 100, "maxSize": 1000}})

    c = client_for(handler)
    items = c.list("/network/zones")
    assert len(items) == 103
    assert c.prefix == "/firewall-config/v1"
    # danach nur noch das funktionierende Präfix
    assert calls.count("/api/firewall-config/v1/network/zones") == 1


def test_page_size_fallback():
    """Echte SFOS: /application/policies lehnt pageSize=100 mit 400 „Invalid page size.“ ab."""
    sizes = []

    def handler(req: httpx.Request):
        size = int(req.url.params["pageSize"])
        sizes.append(size)
        if size > 50:
            return httpx.Response(400, json={"error": "badRequest", "message": "Invalid page size."})
        page = int(req.url.params["page"])
        items = [{"name": f"p{page}{i}"} for i in range(50 if page == 1 else 2)]
        return httpx.Response(200, json={"items": items, "pages": {"current": page, "total": 2, "size": size}})

    restapi._PAGE_SIZES.clear()
    c = client_for(handler)
    assert len(c.list("/application/policies")) == 52
    assert sizes == [100, 50, 50]
    # gelernte Größe wird beim nächsten Mal direkt verwendet
    sizes.clear()
    c.list("/application/policies")
    assert sizes == [50, 50]
    restapi._PAGE_SIZES.clear()


def test_json_404_is_object_not_found_and_errors_are_readable():
    def handler(req):
        if req.method == "DELETE":
            return httpx.Response(404, json={"error": "notFound", "message": "Object not found"})
        return httpx.Response(401, json={"error": "unauthenticated", "message": "Token missing or invalid."})

    c = client_for(handler)
    with pytest.raises(RestApiError) as e:
        c.delete("/network/zones", "Gäste WLAN")
    assert e.value.status == 404 and c.prefix == "/api/firewall-config/v1"
    with pytest.raises(RestApiError) as e:
        c.test()
    assert e.value.status == 401 and "API-Key ungültig" in str(e.value)


def test_name_is_url_encoded():
    seen = []

    def handler(req):
        seen.append(req.url.raw_path.decode())
        return httpx.Response(200, json={})

    client_for(handler).update("/firewall/rules/ipv4", "LAN nach Internet/HTTP", {"enabled": False})
    assert seen == ["/api/firewall-config/v1/firewall/rules/ipv4/LAN%20nach%20Internet%2FHTTP"]


RULE = {"name": "R1", "ruleType": "firewall", "enabled": True, "action": "accept",
        "sourceZones": {"zones": [{"name": "LAN"}]}, "destinationZones": {"zones": [{"name": "WAN"}]},
        "sourceNetworks": {"any": True}, "destinationNetworks": {"any": True}, "servicesOrGroups": {"any": True}}


def test_rest_apply_patch_move_and_rollback():
    log, calls = [], []
    state = {"fail_on": None}

    def handler(req):
        body = json.loads(req.content) if req.content else None
        calls.append((req.method, req.url.path.replace("/api/firewall-config/v1", ""), body))
        if state["fail_on"] and req.url.path.endswith(state["fail_on"]) and req.method == "POST":
            return httpx.Response(409, json={"error": "conflict", "message": "Name exists"})
        return httpx.Response(201 if req.method == "POST" else 200, json={})

    restapi._PREFIX_BY_BASE.clear()
    c = RestApiClient(BASE, "k", transport=httpx.MockTransport(handler))
    ops = [
        {"entity": "firewallRulesIpv4", "action": "update", "name": "R1", "before": RULE,
         "data": {**RULE, "enabled": False}, "position": {"type": "top"}, "before_position": {"type": "after", "ref": "R0"}},
        {"entity": "addressesIpv4", "action": "add", "name": "H1",
         "data": {"name": "H1", "type": "ipv4Address", "ipv4Address": "10.0.0.1"}},
    ]
    connector._rest_apply(c, entities.order_operations(ops), log.append)
    assert calls == [
        ("POST", "/network/addresses/ipv4", {"name": "H1", "type": "ipv4Address", "ipv4Address": "10.0.0.1"}),
        ("PATCH", "/firewall/rules/ipv4/R1", {"enabled": False}),
        ("POST", "/firewall/rules/ipv4/move", {"name": "R1", "position": "top"}),
    ]
    # Fehler beim zweiten Schritt → erster wird zurückgerollt (Host löschen)
    calls.clear()
    state["fail_on"] = "/firewall/rules/ipv4"
    new_rule = {"entity": "firewallRulesIpv4", "action": "add", "name": "R2", "data": {**RULE, "name": "R2"},
                "position": {"type": "after", "ref": "R1"}}
    with pytest.raises(connector.DeployError):
        connector._rest_apply(c, entities.order_operations([new_rule, ops[1]]), log.append)
    assert calls[1][2]["position"] == "after" and calls[1][2]["referenceItem"] == {"name": "R1"}
    assert calls[-1][:2] == ("DELETE", "/network/addresses/ipv4/H1")


def test_rest_references_and_diff():
    from app import changes, diff
    rule = {**RULE, "destinationNetworks": {"ipv4Addresses": [{"name": "H1"}], "fqdnGroups": [{"name": "Updates"}]},
            "servicesOrGroups": {"services": [{"name": "HTTPS"}]}, "schedule": {"name": "Work"}}
    refs = entities.references("firewallRulesIpv4", rule)
    assert ("network", "H1") in refs and ("network", "Updates") in refs and ("service", "HTTPS") in refs
    assert ("zone", "LAN") in refs and ("schedule", "Work") in refs
    cfg = {"firewallRulesIpv4": [rule], "addressesIpv4": [{"name": "H1"}]}
    assert changes.used_by(cfg, "addressesIpv4", "H1") == ["Firewall-Regeln IPv4 „R1“"]
    rows = diff.diff_objects(RULE, {**RULE, "sourceZones": {"zones": [{"name": "LAN"}, {"name": "DMZ"}]}})
    assert rows == [{"field": "sourceZones › zones", "before": "LAN", "after": "LAN, DMZ"}]
    preview = restapi.request_preview("/firewall/rules/ipv4", "update", {**RULE, "enabled": False}, "R1",
                                      {"type": "top"}, RULE, True)
    assert preview.startswith("PATCH /api/firewall-config/v1/firewall/rules/ipv4/R1") and "/move" in preview


def test_real_sfos_shapes():
    """Echte SFOS-Antworten weichen von der Spezifikation ab: Ports als Text, ruleId/isInternal zusätzlich."""
    from app.sophos import connector as conn
    svc = {"id": "u", "name": "H323", "isInternal": True, "type": "tcpOrUdp", "ruleId": 5,
           "services": [{"destinationPort": "1719", "protocol": "udp", "sourcePort": "1:65535"}]}
    stored = conn.strip_read_only(svc)
    assert "ruleId" not in stored and "id" not in stored and stored["isInternal"] is True
    assert restapi.patch_body(stored, {**stored, "description": "x"}) == {"description": "x"}


def test_policy_and_nat_references():
    from app import changes
    rule = {**RULE, "securityFeatures": {"webPolicy": {"name": "Allow All"}, "ipsPolicy": {"name": "LAN TO WAN"}},
            "qos": {"trafficShapingPolicy": {"name": "Voice"}},
            "userAuthentication": {"usersOrGroups": {"userGroups": [{"name": "Admins"}]}}}
    nat = {"name": "DNAT", "originalDestinationNetworks": {"ipv4Addresses": [{"name": "WAN-IP"}]},
           "translatedDestination": {"ipv4Address": {"name": "Server"}}, "translatedService": {"name": "HTTPS"},
           "inboundInterfaces": {"interfaces": [{"name": "Port2"}]}, "linkedFirewallRule": {"name": "R1"}}
    cfg = {"firewallRulesIpv4": [rule], "natRulesIpv4": [nat], "webPolicies": [{"name": "Allow All"}],
           "addressesIpv4": [{"name": "Server"}]}
    assert changes.used_by(cfg, "webPolicies", "Allow All") == ["Firewall-Regeln IPv4 „R1“"]
    assert changes.used_by(cfg, "addressesIpv4", "Server") == ["NAT-Regeln IPv4 „DNAT“"]
    refs = entities.references("natRulesIpv4", nat)
    assert ("interface", "Port2") in refs and ("rule", "R1") in refs and ("service", "HTTPS") in refs


def test_read_only_entities_rejected(client, admin, monkeypatch):
    from app.sophos import connector as conn
    monkeypatch.setattr(conn, "fetch_config", lambda db, fw, log=None: (
        {e: [] for e in conn.entities.REST_NAMES}, "REST v1"))
    fw = client.post("/api/firewalls", headers=admin, json={"name": "R", "connector": "rest", "api_url": "x.test",
                                                           "api_password": "k"}).json()
    client.post(f"/api/firewalls/{fw['id']}/sync", headers=admin)
    r = client.post(f"/api/firewalls/{fw['id']}/draft/operations", headers=admin, json={
        "entity": "users", "action": "add", "name": "u", "data": {"name": "u"}})
    assert r.status_code == 400 and "auf der Firewall gepflegt" in r.json()["detail"]


# --- WAF-Regeln über den zusätzlichen XML-API-Zugang ------------------------------------------------------

class FakeXml:
    def __init__(self, rules=None, fail_on=None):
        self.rules = rules or []
        self.calls = []
        self.fail_on = fail_on

    def get(self, entity):
        if self.fail_on == "get":
            from app.sophos.xmlapi import XmlApiError
            raise XmlApiError("534: Api operations are not allowed from the requester IP address")
        return self.rules

    def set(self, entity, data, op, position=None):
        self.calls.append(("set", entity, op, data.get("Name"), position))
        if self.fail_on == op:
            from app.sophos.xmlapi import XmlApiError
            raise XmlApiError("500: Operation failed")
        return "ok"

    def remove(self, entity, name):
        self.calls.append(("remove", entity, name))
        return "ok"

    def test(self):
        return "2200.1"


WAF = {"Name": "n8n", "PolicyType": "HTTPBased", "Status": "Enable", "Position": "Bottom",
       "HTTPBasedPolicy": {"HostedAddress": "#Port2", "ListenPort": "443", "Domains": {"Domain": ["n8n.example.com"]},
                           "AccessPaths": {"AccessPath": [{"path": "/", "backend": "n8n", "auth_profile": ""}]},
                           "ProtocolSecurity": "n8n", "IntrusionPrevention": "None"}}


def test_rest_fetch_reads_waf_rules_via_xml(monkeypatch):
    from app.models import Firewall

    def handler(req):
        return httpx.Response(200, json={"items": [], "pages": {"current": 1, "total": 1, "size": 100}})
    monkeypatch.setattr(connector, "rest_client", lambda fw: client_for(handler))
    xml = FakeXml([WAF, {"Name": "LAN", "PolicyType": "Network"}])
    monkeypatch.setattr(connector, "waf_xml_client", lambda fw: xml)
    fw = Firewall(id="f1", connector="rest", xml_username="apiadmin", xml_password_enc="x")
    out, _ = connector.fetch_config(None, fw)
    assert [r["Name"] for r in out["wafRules"]] == ["n8n"] and "Position" not in out["wafRules"][0]
    assert fw.xml_status == "ok"
    assert ("wafserver", "n8n") in entities.references("wafRules", out["wafRules"][0])
    assert ("wafprotection", "n8n") in entities.references("wafRules", out["wafRules"][0])
    # Ohne XML-Zugang: leer, kein Fehler
    fw2 = Firewall(id="f2", connector="rest")
    assert connector.fetch_config(None, fw2)[0]["wafRules"] == []


def test_rest_apply_waf_rule_and_rollback(monkeypatch):
    calls = []

    def handler(req):
        calls.append((req.method, req.url.path))
        if req.method == "PATCH" and "fail" in req.url.path:
            return httpx.Response(400, json={"error": "badRequest", "message": "kaputt"})
        return httpx.Response(200, json={})
    c = client_for(handler)
    xml = FakeXml()
    ops = [{"entity": "wafRules", "action": "add", "name": "n8n", "data": WAF, "position": {"type": "after", "ref": "LAN"}},
           {"entity": "firewallRulesIpv4", "action": "update", "name": "fail", "data": {"name": "fail", "enabled": False},
            "before": {"name": "fail", "enabled": True}}]
    logs = []
    with pytest.raises(connector.DeployError):
        connector._rest_apply(c, ops, logs.append, xml)
    # WAF-Regel per XML angelegt (mit Position) und nach dem REST-Fehler wieder entfernt
    assert xml.calls == [("set", "FirewallRule", "add", "n8n", {"type": "after", "ref": "LAN"}), ("remove", "FirewallRule", "n8n")]


def test_waf_access_superadmin_only_and_position_scope(client, admin, fake):
    from .test_workflow import make_user
    r = client.post("/api/firewalls", headers=admin, json={"name": "R", "connector": "rest", "api_url": "x.test",
                                                          "api_password": "sfos_k", "xml_username": "apiadmin", "xml_password": "geheim"})
    assert r.status_code == 200, r.text
    fw = r.json()
    assert fw["waf_xml"] is True and fw["xml_username"] == "apiadmin" and fw["has_xml_password"] is True
    fwa = make_user(client, admin, "fwadmin", [("Firewall-Administrator", None)])
    seen = client.get(f"/api/firewalls/{fw['id']}", headers=fwa).json()
    assert seen["xml_username"] is None and seen["waf_xml"] is True
    assert client.put(f"/api/firewalls/{fw['id']}", headers=fwa, json={"name": "R", "xml_username": "anderer"}).status_code == 403
    assert client.put(f"/api/firewalls/{fw['id']}", headers=fwa, json={"name": "R2"}).status_code == 200
    # Zugang entfernen (Superadmin)
    r = client.put(f"/api/firewalls/{fw['id']}", headers=admin, json={"name": "R2", "connector": "rest", "api_url": "x.test",
                                                                      "xml_username": ""})
    assert r.status_code == 200 and r.json()["waf_xml"] is False

    from app import changes
    from app.models import Firewall
    cfg = {"firewallRulesIpv4": [{"name": "LAN"}], "wafRules": []}
    op = changes.validate_operation(Firewall(connector="rest"), {"entity": "wafRules", "action": "add", "name": "n8n",
                                                                 "data": WAF, "position": {"type": "after", "ref": "LAN"}}, cfg)
    assert op["position"] == {"type": "after", "ref": "LAN"}
