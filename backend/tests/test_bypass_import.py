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


def test_deploy_skips_rejected_objects_with_followup_checklist(client, admin, fake, monkeypatch):
    _sync_deploy(monkeypatch)
    fw_id = setup_firewall(client, admin)
    for name, ip in (("Bad", "10.0.0.66"), ("Good", "10.0.0.7")):
        r = client.post(f"/api/firewalls/{fw_id}/draft/operations", headers=admin, json={
            "entity": "IPHost", "action": "add", "name": name,
            "data": {"Name": name, "IPFamily": "IPv4", "HostType": "IP", "IPAddress": ip}})
        assert r.status_code == 200, r.text
    r = client.post(f"/api/firewalls/{fw_id}/draft/operations", headers=admin, json={
        "entity": "IPHostGroup", "action": "add", "name": "Grp",
        "data": {"Name": "Grp", "IPFamily": "IPv4", "HostList": {"Host": ["Bad"]}}})
    cid = r.json()["draft"]["id"]
    fake.reject = {"Bad"}
    client.post(f"/api/changes/{cid}/submit", headers=admin, json={"title": "t", "justification": "j", "bypass_approval": True})
    cr = client.get(f"/api/changes/{cid}", headers=admin).json()
    assert cr["status"] == "deployed", cr["deploy_log"]
    assert [o["name"] for o in cr["operations"]] == ["Good"]          # nur Ausgerolltes bleibt im Antrag
    assert [(s["name"], s["done"]) for s in cr["skipped"]] == [("Bad", False), ("Grp", False)]
    assert cr["followups_open"] == 2 and cr["can"]["followup"]
    assert [c["id"] for c in client.get("/api/changes?followups=true", headers=admin).json()] == [cid]

    # abhaken mit Notiz
    r = client.put(f"/api/changes/{cid}/skipped/0", headers=admin, json={"done": True, "note": "manuell angelegt"})
    assert r.status_code == 200 and r.json()["skipped"][0]["done_by"] == "admin" and r.json()["followups_open"] == 1
    # Rest erneut in den Entwurf
    r = client.post(f"/api/changes/{cid}/skipped/to-draft", headers=admin, json={"indexes": [1]})
    assert r.status_code == 200 and r.json()["added"] == 1, r.text
    # nur Lesen (Auditor) darf nicht abhaken
    viewer = make_user(client, admin, "auditor", [("Auditor", None)])
    assert client.put(f"/api/changes/{cid}/skipped/1", headers=viewer, json={"done": True}).status_code == 403


def test_deploy_fails_when_everything_rejected(client, admin, fake, monkeypatch):
    _sync_deploy(monkeypatch)
    fw_id = setup_firewall(client, admin)
    cid = _draft_rule(client, admin, fw_id, "Nix")
    fake.reject = {"Nix"}
    client.post(f"/api/changes/{cid}/submit", headers=admin, json={"title": "t", "justification": "j", "bypass_approval": True})
    cr = client.get(f"/api/changes/{cid}", headers=admin).json()
    assert cr["status"] == "failed" and cr["skipped"] == [] and len(cr["operations"]) == 1


def test_deploy_progress_is_reported_while_deploying(client, admin, fake, monkeypatch):
    from app.sophos import connector
    _sync_deploy(monkeypatch)
    fw_id = setup_firewall(client, admin)
    _draft_rule(client, admin, fw_id, "P1")
    cid = _draft_rule(client, admin, fw_id, "P2")
    seen = []

    def apply(db, fw, ops, log, skipper=None):
        for o in ops:
            connector._step(log, o)
            seen.append(changes.deploy_progress(cid))
            # die Detailansicht liefert den Fortschritt mit, solange ausgerollt wird
            seen.append(client.get(f"/api/changes/{cid}", headers=admin).json()["progress"])
        fake.config = changes.effective_config(fake.config, ops)
    monkeypatch.setattr(connector, "apply", apply)
    client.post(f"/api/changes/{cid}/submit", headers=admin, json={"title": "t", "justification": "j", "bypass_approval": True})
    assert [(p["phase"], p["done"], p["total"]) for p in seen[::2]] == [("apply", 1, 2), ("apply", 2, 2)]
    assert "P2" in seen[-1]["current"] and seen[-1]["log"]
    cr = client.get(f"/api/changes/{cid}", headers=admin).json()
    assert cr["status"] == "deployed" and cr["progress"] is None and changes.deploy_progress(cid) is None
