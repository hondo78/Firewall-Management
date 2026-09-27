"""Vorlagen: Soll-Zustand bearbeiten, Vorschau je Firewall, Ausrollen als Sammelantrag über die Freigabe."""
from .conftest import rule
from .test_batch import setup_two
from .test_workflow import deploy_sync, make_user

HOST_NEW = {"Name": "NTP", "IPFamily": "IPv4", "HostType": "IP", "IPAddress": "10.0.0.123"}
SERVER = {"Name": "Server", "IPFamily": "IPv4", "HostType": "IP", "IPAddress": "10.0.0.2"}


def items():
    return [{"entity": "IPHost", "name": "NTP", "data": HOST_NEW},
            {"entity": "IPHost", "name": "Server", "data": SERVER},
            {"entity": "FirewallRule", "name": "Regel-A", "data": rule("Regel-A", services=["HTTPS"])},
            {"entity": "FirewallRule", "name": "Std", "data": rule("Std"), "position": {"type": "after", "ref": "Gibt-es-nicht"}},
            {"entity": "FirewallRule", "name": "Regel-B", "action": "remove"}]


def test_template_edit_preview_push(client, admin, monkeypatch):
    g, (a, b), fakes = setup_two(client, admin, monkeypatch)
    op = make_user(client, admin, "operator", [("Operator", None)])
    ap = make_user(client, admin, "approver", [("Approver", None)])
    viewer = make_user(client, admin, "leser", [("Betrachter", None)])

    r = client.post("/api/templates", headers=op, json={"name": "Filial-Standard", "format": "xml", "items": items()})
    assert r.status_code == 200, r.text
    t = r.json()
    assert t["version"] == 1 and len(t["items"]) == 5
    assert client.get("/api/templates", headers=viewer).json() == []
    # ungültige Einträge werden abgewiesen
    bad = client.post("/api/templates", headers=op, json={"name": "X", "format": "xml",
                                                          "items": [{"entity": "firewallRulesIpv4", "name": "x", "data": {"name": "x"}}]})
    assert bad.status_code == 400

    # Vorschau: NTP neu, Server geändert, Regel-A gleich, Std neu (Bezugsregel fehlt → unten), Regel-B entfernen
    p = client.post(f"/api/templates/{t['id']}/preview", headers=op, json={"firewall_ids": [a, b]}).json()
    fa = p["firewalls"][0]
    assert fa["counts"] == {"add": 2, "update": 1, "remove": 1, "same": 1, "absent": 0, "error": 0}
    std = next(r for r in fa["rows"] if r["name"] == "Std")
    assert "Gibt-es-nicht" in std["note"]
    server = next(r for r in fa["rows"] if r["name"] == "Server")
    assert any(d["after"] == "10.0.0.2" for d in server["diff"])

    # Ausrollen: Sammelantrag über beide Firewalls, Vier-Augen wie immer
    r = client.post(f"/api/templates/{t['id']}/push", headers=op, json={
        "firewall_ids": [a, b], "title": "Filial-Standard", "justification": "Rollout", "version": 1})
    assert r.status_code == 200, r.text
    res = r.json()
    assert len(res["changes"]) == 2 and res["unchanged"] == []
    cid = res["changes"][0]["id"]
    cr = client.get(f"/api/changes/{cid}", headers=admin).json()
    assert cr["status"] == "pending" and cr["template"] == "Filial-Standard" and cr["template_version"] == 1 and cr["batch_id"]
    assert client.post(f"/api/changes/{cid}/decision", headers=op, json={"decision": "approve"}).status_code == 403
    assert client.post(f"/api/changes/{cid}/decision", headers=ap, json={"decision": "approve"}).status_code == 200
    for c in res["changes"]:
        deploy_sync(c["id"])
    cfg = fakes["FW-A"].config
    assert {h["Name"] for h in cfg["IPHost"]} == {"Server", "NTP"}
    assert next(h for h in cfg["IPHost"] if h["Name"] == "Server")["IPAddress"] == "10.0.0.2"
    assert [r["Name"] for r in cfg["FirewallRule"]] == ["Regel-A", "Std"]

    # Danach konform: erneutes Ausrollen hat nichts zu tun
    client.post(f"/api/firewalls/{a}/sync", headers=admin)
    client.post(f"/api/firewalls/{b}/sync", headers=admin)
    r = client.post(f"/api/templates/{t['id']}/push", headers=op, json={
        "firewall_ids": [a, b], "title": "x", "justification": "y", "version": 1})
    assert r.status_code == 409

    # Bearbeiten: Versionsschutz, nur Ersteller/Admin
    upd = {"name": "Filial-Standard", "description": "v2", "items": items()[:2], "version": 1}
    assert client.put(f"/api/templates/{t['id']}", headers=ap, json=upd).status_code == 403
    r = client.put(f"/api/templates/{t['id']}", headers=op, json=upd)
    assert r.status_code == 200 and r.json()["version"] == 2
    assert client.put(f"/api/templates/{t['id']}", headers=op, json=upd).status_code == 409
    detail = client.get(f"/api/templates/{t['id']}", headers=op).json()
    assert len(detail["history"]) == 2 and detail["items"][0]["data"]["IPAddress"] == "10.0.0.123"
    actions = {e["action"] for e in client.get("/api/audit", headers=admin).json()["items"]}
    assert {"template.created", "template.updated", "template.pushed"} <= actions


def test_dependencies_and_apply_to_draft(client, admin, monkeypatch):
    g, (a, b), fakes = setup_two(client, admin, monkeypatch)
    deps = client.post("/api/templates/dependencies", headers=admin, json={
        "firewall_id": a, "items": [{"entity": "FirewallRule", "name": "Regel-A"}]}).json()["items"]
    assert {(d["entity"], d["name"]) for d in deps} == {("Zone", "LAN"), ("Zone", "WAN"), ("Services", "HTTPS")}
    t = client.post("/api/templates", headers=admin, json={"name": "NTP", "format": "xml",
                                                          "items": [{"entity": "IPHost", "name": "NTP", "data": HOST_NEW}]}).json()
    r = client.post(f"/api/firewalls/{a}/templates/{t['id']}/apply", headers=admin)
    assert r.status_code == 200 and r.json()["draft"]["operations"][0]["action"] == "add"
