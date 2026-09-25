"""Befristete Anträge: automatische Rücknahme nach Ablauf."""
from datetime import datetime, timedelta, timezone

from app import worker
from app.db import SessionLocal
from app.models import ChangeRequest

from .test_workflow import deploy_sync, make_user, rule, setup_firewall


def iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def submit_temp(client, fw_id, headers, expires: str, name="Wartung"):
    r = client.post(f"/api/firewalls/{fw_id}/draft/operations", headers=headers, json={
        "entity": "FirewallRule", "action": "add", "name": name, "data": rule(name), "position": {"type": "top"}})
    draft = r.json()["draft"]
    return client.post(f"/api/changes/{draft['id']}/submit", headers=headers, json={
        "title": "Wartungszugang", "justification": "Dienstleister", "expires_at": expires})


def expire_now(cid):
    with SessionLocal() as db:
        db.get(ChangeRequest, cid).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()


def test_temporary_change_is_reverted_automatically(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    r = submit_temp(client, fw_id, op, iso(timedelta(hours=4)))
    assert r.status_code == 200 and r.json()["expires_at"]
    cid = r.json()["id"]
    client.post(f"/api/changes/{cid}/decision", headers=admin, json={"decision": "approve"})
    deploy_sync(cid)
    assert fake.config["FirewallRule"][0]["Name"] == "Wartung"
    worker._expire_due()                      # noch nicht abgelaufen → nichts passiert
    assert client.get(f"/api/changes/{cid}", headers=op).json()["expiry_state"] == ""
    expire_now(cid)
    worker._expire_due()
    worker._deploy_due()                      # vorab genehmigt → wird direkt ausgerollt
    orig = client.get(f"/api/changes/{cid}", headers=op).json()
    assert orig["expiry_state"] == "reverted"
    rev = client.get(f"/api/changes/{orig['reverted_by']['id']}", headers=op).json()
    assert rev["status"] == "deployed" and rev["created_by"] == "system"
    assert any(e["kind"] == "preapproved" for e in rev["events"])
    assert [x["Name"] for x in fake.config["FirewallRule"]] == ["Regel-A", "Regel-B"]
    log = client.get("/api/audit", headers=admin, params={"action": "change.revert"}).json()["items"]
    assert log[0]["details"]["automatic"] is True
    assert client.get("/api/audit/verify", headers=admin).json()["ok"]


def test_temporary_revert_needs_approval_when_configured(client, admin, fake):
    client.put("/api/settings", headers=admin, json={"temp_revert_preapproved": False})
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    cid = submit_temp(client, fw_id, op, iso(timedelta(hours=1))).json()["id"]
    client.post(f"/api/changes/{cid}/decision", headers=admin, json={"decision": "approve"})
    deploy_sync(cid)
    expire_now(cid)
    worker._expire_due()
    rev_id = client.get(f"/api/changes/{cid}", headers=op).json()["reverted_by"]["id"]
    assert client.get(f"/api/changes/{rev_id}", headers=op).json()["status"] == "pending"
    # System-Rücknahme darf jeder Approver genehmigen (niemand ist „Antragsteller“)
    assert client.post(f"/api/changes/{rev_id}/decision", headers=admin,
                       json={"decision": "approve"}).json()["status"] == "approved"


def test_expiry_validation_and_manual_revert(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    assert submit_temp(client, fw_id, op, iso(timedelta(minutes=1))).status_code == 400
    assert submit_temp(client, fw_id, op, iso(timedelta(days=400)), "Lang").status_code == 400
    cid = submit_temp(client, fw_id, op, iso(timedelta(days=1)), "Kurz").json()["id"]
    client.post(f"/api/changes/{cid}/decision", headers=admin, json={"decision": "approve"})
    deploy_sync(cid)
    # vor Ablauf manuell zurückgenommen → beim Ablauf keine zweite Rücknahme
    client.post(f"/api/changes/{cid}/revert", headers=op, json={"justification": "früher fertig"})
    expire_now(cid)
    worker._expire_due()
    reverts = [c for c in client.get("/api/changes", headers=admin).json() if c["reverts_id"] == cid]
    assert len(reverts) == 1
    assert client.get(f"/api/changes/{cid}", headers=op).json()["expiry_state"] == "reverted"
