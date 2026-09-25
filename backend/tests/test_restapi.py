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
