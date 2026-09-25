"""Sammelanträge (mehrere Firewalls), Vorlagen und Gruppen-Abgleich."""
from app.sophos import connector

from .conftest import FakeFirewall, rule
from .test_workflow import login, make_user


def setup_two(client, admin, monkeypatch):
    """Zwei Firewalls mit je eigener Fake-Konfiguration."""
    fakes = {}

    def fetch(db, fw, log=None):
        return fakes.setdefault(fw.name, FakeFirewall()).fetch(db, fw, log)

    def apply(db, fw, ops, log):
        fakes[fw.name].apply(db, fw, ops, log)
    monkeypatch.setattr(connector, "fetch_config", fetch)
    monkeypatch.setattr(connector, "apply", apply)
    g = client.post("/api/groups", headers=admin, json={"name": "Filialen"}).json()["id"]
    ids = []
    for name in ("FW-A", "FW-B"):
        fw = client.post("/api/firewalls", headers=admin, json={
            "name": name, "group_id": g, "connector": "xmlapi", "api_url": "fw.test", "api_username": "a",
            "api_password": "p"}).json()
        client.post(f"/api/firewalls/{fw['id']}/sync", headers=admin)
        ids.append(fw["id"])
    return g, ids, fakes


def test_batch_request_approved_once_deployed_per_firewall(client, admin, monkeypatch):
    from app.db import SessionLocal
    from app import changes
    g, (a, b), fakes = setup_two(client, admin, monkeypatch)
    op = make_user(client, admin, "operator", [("Operator", None)])
    ap_a = make_user(client, admin, "approver-a", [("Approver", None)])
    r = client.post(f"/api/firewalls/{a}/draft/operations", headers=op, json={
        "entity": "FirewallRule", "action": "add", "name": "Std", "data": rule("Std"), "position": {"type": "top"}})
    draft = r.json()["draft"]
    r = client.post(f"/api/changes/{draft['id']}/submit", headers=op, json={
        "title": "Standardregel", "justification": "alle Filialen", "extra_firewall_ids": [b]})
    assert r.status_code == 200, r.text
    batch = r.json()["batch"]
    assert [m["firewall"] for m in batch] == ["FW-A", "FW-B"] and all(m["status"] == "pending" for m in batch)
    # eine Entscheidung genehmigt den ganzen Sammelantrag
    r = client.post(f"/api/changes/{draft['id']}/decision", headers=ap_a, json={"decision": "approve"})
    assert all(m["status"] == "approved" for m in r.json()["batch"])
    for m in batch:
        with SessionLocal() as db:
            changes.claim_for_deploy(db, m["id"])
            changes.deploy(db, m["id"])
    assert fakes["FW-A"].config["FirewallRule"][0]["Name"] == "Std"
    assert fakes["FW-B"].config["FirewallRule"][0]["Name"] == "Std"


def test_batch_all_or_nothing_and_scoped_approver(client, admin, monkeypatch):
    g, (a, b), fakes = setup_two(client, admin, monkeypatch)
    op = make_user(client, admin, "operator", [("Operator", None)])
    # Objekt existiert auf B schon → Sammelantrag wird komplett abgelehnt
    fakes["FW-B"].config["IPHost"].append({"Name": "Neu", "IPAddress": "1.1.1.1"})
    client.post(f"/api/firewalls/{b}/sync", headers=admin)
    d = client.post(f"/api/firewalls/{a}/draft/operations", headers=op, json={
        "entity": "IPHost", "action": "add", "name": "Neu", "data": {"Name": "Neu", "IPAddress": "2.2.2.2"}}).json()["draft"]
    r = client.post(f"/api/changes/{d['id']}/submit", headers=op, json={"title": "x", "justification": "y",
                                                                       "extra_firewall_ids": [b]})
    assert r.status_code == 409 and "FW-B" in r.json()["detail"]
    assert client.get(f"/api/changes/{d['id']}", headers=op).json()["status"] == "draft"


def test_template_apply_and_group_drift(client, admin, monkeypatch):
    g, (a, b), fakes = setup_two(client, admin, monkeypatch)
    d = client.post(f"/api/firewalls/{a}/draft/operations", headers=admin, json={
        "entity": "IPHost", "action": "add", "name": "NTP", "data": {"Name": "NTP", "IPAddress": "10.0.0.123"}}).json()["draft"]
    t = client.post("/api/templates", headers=admin, json={"name": "NTP-Server", "change_id": d["id"]}).json()
    assert t["format"] == "xml" and t["operations"][0]["name"] == "NTP"
    r = client.post(f"/api/firewalls/{b}/templates/{t['id']}/apply", headers=admin)
    assert r.status_code == 200 and r.json()["draft"]["operations"][0]["name"] == "NTP" and r.json()["skipped"] == []
    # Abgleich: B weicht bei den Regeln ab
    fakes["FW-B"].config["FirewallRule"].pop()
    client.post(f"/api/firewalls/{b}/sync", headers=admin)
    drift = client.get(f"/api/groups/{g}/drift", headers=admin, params={"reference": a}).json()
    row = drift["firewalls"][0]
    assert row["name"] == "FW-B" and row["entities"]["FirewallRule"]["missing"] == 1
