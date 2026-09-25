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
