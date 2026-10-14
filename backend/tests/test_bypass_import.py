"""Superadmin rollt ohne Freigabe aus; große Importe werden in Teilen in den Entwurf übernommen."""
from app import changes, worker
from app.db import SessionLocal
from app.models import AuditLog
from app.sophos import xmlconv

from .conftest import rule
from .test_workflow import make_user, setup_firewall


def _draft_rule(client, headers, fw_id, name="Bypass"):
    r = client.post(f"/api/firewalls/{fw_id}/draft/operations", headers=headers, json={
        "entity": "FirewallRule", "action": "add", "name": name, "data": rule(name, services=["HTTPS"])})
    assert r.status_code == 200, r.text
    return r.json()["draft"]["id"]


def _sync_deploy(monkeypatch):
    def run(change_id, actor_id):
        with SessionLocal() as db:
            changes.deploy(db, change_id)
    monkeypatch.setattr(worker, "deploy_in_background", run)


def test_superadmin_bypass_deploys_immediately(client, admin, fake, monkeypatch):
    _sync_deploy(monkeypatch)
    fw_id = setup_firewall(client, admin)
    cid = _draft_rule(client, admin, fw_id)
    r = client.post(f"/api/changes/{cid}/submit", headers=admin,
                    json={"title": "Notfall", "justification": "Störung", "bypass_approval": True})
    assert r.status_code == 200, r.text
    detail = client.get(f"/api/changes/{cid}", headers=admin).json()
    assert detail["status"] == "deployed", detail.get("deploy_log")
    assert "Bypass" in [x["Name"] for x in fake.config["FirewallRule"]]
    assert any(e["kind"] == "approval_bypassed" for e in detail["events"])
    with SessionLocal() as db:
        assert db.query(AuditLog).filter(AuditLog.action == "change.approval_bypassed").count() == 1


def test_bypass_only_for_superadmin_and_switchable(client, admin, fake, monkeypatch):
    _sync_deploy(monkeypatch)
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    cid = _draft_rule(client, op, fw_id)
    body = {"title": "x", "justification": "y", "bypass_approval": True}
    assert client.post(f"/api/changes/{cid}/submit", headers=op, json=body).status_code == 403
    assert client.get(f"/api/changes/{cid}", headers=op).json()["status"] == "draft"

    assert client.put("/api/settings", headers=admin, json={"superadmin_bypass_approval": False}).status_code == 200
    cid2 = _draft_rule(client, admin, fw_id, "Zwei")
    assert client.post(f"/api/changes/{cid2}/submit", headers=admin, json=body).status_code == 403
    # ohne Bypass ganz normal: wartet auf Genehmigung
    r = client.post(f"/api/changes/{cid2}/submit", headers=admin, json={"title": "x", "justification": "y"})
    assert r.status_code == 200 and r.json()["status"] == "pending"


def test_import_apply_in_chunks(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    hosts = [("IPHost", {"Name": f"H{n:04d}", "IPFamily": "IPv4", "HostType": "IP", "IPAddress": f"10.9.{n // 250}.{n % 250 + 1}"})
             for n in range(600)]
    xml = xmlconv.build_entities_xml(hosts)
    review = client.post(f"/api/firewalls/{fw_id}/import/review", headers=admin,
                         files={"file": ("Entities.xml", xml, "application/xml")}).json()
    keys = [i["key"] for i in review["items"] if i["status"] == "new"]
    assert len(keys) == 600
    total = 0
    for p in range(0, 600, 250):
        r = client.post(f"/api/firewalls/{fw_id}/import/apply", headers=admin,
                        json={"token": review["token"], "keys": keys[p:p + 250], "chunk": f"{p // 250 + 1}/3"})
        assert r.status_code == 200, r.text
        total += r.json()["added"]
        assert r.json()["draft"]["operations"] == total     # nur Entwurfskopf bei Teil-Aufrufen
    assert total == 600
    # derselbe Teil nochmal: im Entwurf schon vorhanden → wird zusammengeführt, nicht doppelt
    r = client.post(f"/api/firewalls/{fw_id}/import/apply", headers=admin,
                    json={"token": review["token"], "keys": keys[:10], "chunk": "x"})
    assert r.json()["draft"]["operations"] == 600
