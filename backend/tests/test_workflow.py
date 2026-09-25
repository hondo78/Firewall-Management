"""Ende-zu-Ende über die HTTP-API: Rechte, Entwurf, Vier-Augen-Genehmigung, Ausrollen, Drift, Audit."""
from app import changes
from app.db import SessionLocal

from .conftest import login, rule


def role_id(client, admin, name):
    return next(r["id"] for r in client.get("/api/roles", headers=admin).json() if r["name"] == name)


def make_user(client, admin, username, roles):
    r = client.post("/api/users", headers=admin, json={
        "username": username, "password": "secret-password-1",
        "assignments": [{"role_id": role_id(client, admin, rn), "group_id": g} for rn, g in roles]})
    assert r.status_code == 200, r.text
    return login(client, username, "secret-password-1")


def setup_firewall(client, admin, group_id=None):
    r = client.post("/api/firewalls", headers=admin, json={
        "name": "FW-Test", "group_id": group_id, "connector": "xmlapi", "api_url": "fw.test",
        "api_username": "api", "api_password": "pw"})
    assert r.status_code == 200, r.text
    fw_id = r.json()["id"]
    assert client.post(f"/api/firewalls/{fw_id}/sync", headers=admin).status_code == 200
    return fw_id


def deploy_sync(change_id):
    with SessionLocal() as db:
        assert changes.claim_for_deploy(db, change_id)
        changes.deploy(db, change_id)


def submit_new_rule(client, fw_id, op_headers, name="Neu"):
    r = client.post(f"/api/firewalls/{fw_id}/draft/operations", headers=op_headers, json={
        "entity": "FirewallRule", "action": "add", "name": name, "data": rule(name, services=["HTTPS"]),
        "position": {"type": "after", "ref": "Regel-A"}})
    assert r.status_code == 200, r.text
    draft = r.json()["draft"]
    assert draft["operations"][0]["xml"].startswith('<Set operation="add">')
    r = client.post(f"/api/changes/{draft['id']}/submit", headers=op_headers,
                    json={"title": "Neue Regel", "justification": "Ticket 42", "ticket_ref": "INC-42"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "pending"
    return draft["id"]


def test_four_eyes_and_deploy(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    ap = make_user(client, admin, "approver", [("Approver", None)])
    cid = submit_new_rule(client, fw_id, op)

    # Operator darf nicht genehmigen – schon gar nicht den eigenen Antrag
    r = client.post(f"/api/changes/{cid}/decision", headers=op, json={"decision": "approve"})
    assert r.status_code == 403
    # Ein Approver ohne change.create darf keine Entwürfe anlegen
    r = client.post(f"/api/firewalls/{fw_id}/draft/operations", headers=ap, json={
        "entity": "IPHost", "action": "remove", "name": "Server"})
    assert r.status_code == 403
    r = client.post(f"/api/changes/{cid}/decision", headers=ap, json={"decision": "approve", "comment": "ok"})
    assert r.status_code == 200 and r.json()["status"] == "approved"

    deploy_sync(cid)
    r = client.get(f"/api/changes/{cid}", headers=op).json()
    assert r["status"] == "deployed", r["deploy_log"]
    assert [x["Name"] for x in fake.config["FirewallRule"]] == ["Regel-A", "Neu", "Regel-B"]
    # Versionsstände: initial + nach dem Ausrollen
    snaps = client.get(f"/api/firewalls/{fw_id}/snapshots", headers=admin).json()
    assert [s["reason"] for s in snaps] == ["deploy", "initial"]
    cmp = client.get(f"/api/firewalls/{fw_id}/compare", headers=admin, params={"a": snaps[1]["id"]}).json()
    assert cmp["totals"]["added"] == 1

    log = client.get("/api/audit", headers=admin, params={"action": "change."}).json()["items"]
    assert {e["action"] for e in log} >= {"change.submitted", "change.approved", "change.deployed"}
    assert client.get("/api/audit/verify", headers=admin).json()["ok"] is True


def test_admin_cannot_approve_own_request(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    cid = submit_new_rule(client, fw_id, admin)
    r = client.post(f"/api/changes/{cid}/decision", headers=admin, json={"decision": "approve"})
    assert r.status_code == 403 and "Vier-Augen" in r.json()["detail"]


def test_two_approvals_required(client, admin, fake):
    client.put("/api/settings", headers=admin, json={"required_approvals": 2})
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    a1 = make_user(client, admin, "approver1", [("Approver", None)])
    a2 = make_user(client, admin, "approver2", [("Approver", None)])
    cid = submit_new_rule(client, fw_id, op)
    assert client.post(f"/api/changes/{cid}/decision", headers=a1, json={"decision": "approve"}).json()["status"] \
        == "pending"
    assert client.post(f"/api/changes/{cid}/decision", headers=a1, json={"decision": "approve"}).status_code == 409
    assert client.post(f"/api/changes/{cid}/decision", headers=a2, json={"decision": "approve"}).json()["status"] \
        == "approved"


def test_reject_needs_comment(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    ap = make_user(client, admin, "approver", [("Approver", None)])
    cid = submit_new_rule(client, fw_id, op)
    assert client.post(f"/api/changes/{cid}/decision", headers=ap, json={"decision": "reject"}).status_code == 400
    r = client.post(f"/api/changes/{cid}/decision", headers=ap, json={"decision": "reject", "comment": "zu offen"})
    assert r.json()["status"] == "rejected"


def test_drift_blocks_deploy(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    ap = make_user(client, admin, "approver", [("Approver", None)])
    r = client.post(f"/api/firewalls/{fw_id}/draft/operations", headers=op, json={
        "entity": "FirewallRule", "action": "update", "name": "Regel-B", "data": rule("Regel-B", "Drop")})
    assert r.status_code == 200, r.text
    cid = r.json()["draft"]["id"]
    client.post(f"/api/changes/{cid}/submit", headers=op, json={"title": "B sperren", "justification": "x"})
    client.post(f"/api/changes/{cid}/decision", headers=ap, json={"decision": "approve"})
    # Jemand ändert die Regel direkt an der Firewall
    fake.config["FirewallRule"][1]["Description"] = "manuell geändert"
    deploy_sync(cid)
    r = client.get(f"/api/changes/{cid}", headers=op).json()
    assert r["status"] == "conflict" and "Description" in r["error"]
    assert fake.applied == []


def test_failed_deploy_can_be_retried(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    cid = submit_new_rule(client, fw_id, op)
    client.post(f"/api/changes/{cid}/decision", headers=admin, json={"decision": "approve"})
    fake.fail = "Firewall antwortet nicht"
    deploy_sync(cid)
    assert client.get(f"/api/changes/{cid}", headers=op).json()["status"] == "failed"
    fake.fail = None
    with SessionLocal() as db:
        assert changes.claim_for_deploy(db, cid, ("approved", "failed"))
        changes.deploy(db, cid)
    assert client.get(f"/api/changes/{cid}", headers=op).json()["status"] == "deployed"


def test_group_scoped_permissions(client, admin, fake):
    g1 = client.post("/api/groups", headers=admin, json={"name": "Filialen"}).json()["id"]
    g2 = client.post("/api/groups", headers=admin, json={"name": "Zentrale"}).json()["id"]
    fw_filiale = setup_firewall(client, admin, g1)
    fw_zentrale = setup_firewall(client, admin, g2)
    u = make_user(client, admin, "filial-admin", [("Firewall-Administrator", g1), ("Betrachter", g2)])
    visible = {f["id"]: f for f in client.get("/api/firewalls", headers=u).json()}
    assert set(visible) == {fw_filiale, fw_zentrale}
    assert "change.create" in visible[fw_filiale]["permissions"]
    assert visible[fw_zentrale]["permissions"] == ["firewall.view"]
    r = client.post(f"/api/firewalls/{fw_zentrale}/draft/operations", headers=u, json={
        "entity": "IPHost", "action": "remove", "name": "Server"})
    assert r.status_code == 403
    # Ohne Zuweisung für eine Gruppe ist die Firewall unsichtbar
    other = make_user(client, admin, "nur-filiale", [("Betrachter", g1)])
    assert client.get(f"/api/firewalls/{fw_zentrale}", headers=other).status_code == 404
    assert client.get("/api/audit", headers=other).status_code == 403


def test_remove_in_use_object_rejected_and_revert(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    r = client.post(f"/api/firewalls/{fw_id}/draft/operations", headers=op, json={
        "entity": "Services", "action": "remove", "name": "HTTPS"})
    assert r.status_code == 409 and "Regel-A" in r.json()["detail"]
    cid = submit_new_rule(client, fw_id, op)
    client.post(f"/api/changes/{cid}/decision", headers=admin, json={"decision": "approve"})
    deploy_sync(cid)
    r = client.post(f"/api/changes/{cid}/revert", headers=op, json={"justification": "doch nicht"})
    assert r.status_code == 200, r.text
    rev = r.json()
    assert rev["status"] == "pending" and rev["reverts"]["id"] == cid
    assert [(o["action"], o["name"]) for o in rev["operations"]] == [("remove", "Neu")]


def test_approver_and_superadmin_can_revert(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    ap = make_user(client, admin, "approver", [("Approver", None)])
    viewer = make_user(client, admin, "viewer", [("Betrachter", None)])
    cid = submit_new_rule(client, fw_id, op)
    client.post(f"/api/changes/{cid}/decision", headers=ap, json={"decision": "approve"})
    deploy_sync(cid)
    detail = client.get(f"/api/changes/{cid}", headers=ap).json()
    assert detail["can"]["revert"] is True
    assert client.get(f"/api/changes/{cid}", headers=viewer).json()["can"]["revert"] is False
    assert client.post(f"/api/changes/{cid}/revert", headers=viewer, json={"justification": "x"}).status_code == 403
    assert client.post(f"/api/changes/{cid}/revert", headers=ap, json={"justification": " "}).status_code == 400
    # Approver (ohne change.create) stellt die Rücknahme …
    r = client.post(f"/api/changes/{cid}/revert", headers=ap, json={"justification": "Regel verursacht Störung"})
    assert r.status_code == 200, r.text
    rev = r.json()
    # … darf sie aber nicht selbst genehmigen (Vier-Augen-Prinzip)
    assert client.post(f"/api/changes/{rev['id']}/decision", headers=ap,
                       json={"decision": "approve"}).status_code == 403
    # doppelte Rücknahme wird verhindert
    assert client.post(f"/api/changes/{cid}/revert", headers=admin, json={"justification": "x"}).status_code == 409
    assert client.get(f"/api/changes/{cid}", headers=ap).json()["reverted_by"]["id"] == rev["id"]
    # Superadmin genehmigt, ausrollen stellt den alten Stand wieder her
    client.post(f"/api/changes/{rev['id']}/decision", headers=admin, json={"decision": "approve"})
    deploy_sync(rev["id"])
    assert client.get(f"/api/changes/{rev['id']}", headers=ap).json()["status"] == "deployed"
    assert [x["Name"] for x in fake.config["FirewallRule"]] == ["Regel-A", "Regel-B"]
    log = client.get("/api/audit", headers=admin, params={"action": "change.revert"}).json()["items"]
    assert log[0]["details"]["reverts"] == 1


def test_superadmin_can_revert_own_approved_change(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    cid = submit_new_rule(client, fw_id, op)
    client.post(f"/api/changes/{cid}/decision", headers=admin, json={"decision": "approve"})
    deploy_sync(cid)
    r = client.post(f"/api/changes/{cid}/revert", headers=admin, json={"justification": "Notfall"})
    assert r.status_code == 200 and r.json()["created_by"] == "admin"
    # Operator darf die Rücknahme des Superadmins nicht genehmigen (kein change.approve)
    assert client.post(f"/api/changes/{r.json()['id']}/decision", headers=op,
                       json={"decision": "approve"}).status_code == 403


def test_revert_blocked_when_config_changed(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    cid = submit_new_rule(client, fw_id, op)
    client.post(f"/api/changes/{cid}/decision", headers=admin, json={"decision": "approve"})
    deploy_sync(cid)
    # Regel wurde inzwischen an der Firewall gelöscht → Rücknahme (remove) nicht mehr möglich
    fake.config["FirewallRule"] = [r for r in fake.config["FirewallRule"] if r["Name"] != "Neu"]
    client.post(f"/api/firewalls/{fw_id}/sync", headers=admin)
    r = client.post(f"/api/changes/{cid}/revert", headers=admin, json={"justification": "x"})
    assert r.status_code == 409 and "geändert" in r.json()["detail"]


def test_removed_firewall_keeps_history(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    cid = submit_new_rule(client, fw_id, op)
    client.post(f"/api/changes/{cid}/decision", headers=admin, json={"decision": "approve"})
    deploy_sync(cid)
    assert client.delete(f"/api/firewalls/{fw_id}", headers=admin).status_code == 200
    assert client.get(f"/api/firewalls/{fw_id}", headers=admin).status_code == 404
    assert fw_id not in {f["id"] for f in client.get("/api/firewalls", headers=admin).json()}
    cr = client.get(f"/api/changes/{cid}", headers=admin).json()
    assert cr["status"] == "deployed" and cr["firewall_archived"] is True


def test_rest_connector_workflow(client, admin, monkeypatch):
    """Firewall per REST-API: Entwurf im REST-Format, Vier-Augen-Freigabe, Ausrollen."""
    from app.sophos import connector as conn
    from app import changes as ch
    state = {"zones": [{"name": "LAN", "type": "lan"}, {"name": "WAN", "type": "wan"}],
             "addressesIpv4": [], "firewallRulesIpv4": [{"name": "Alt", "ruleType": "firewall", "enabled": True,
                                                         "action": "accept", "sourceZones": {"any": True},
                                                         "destinationZones": {"any": True}}]}
    applied = []
    monkeypatch.setattr(conn, "fetch_config", lambda db, fw, log=None: (
        {e: [dict(o) for o in state.get(e, [])] for e in conn.entities.REST_NAMES}, "REST v1"))

    def apply(db, fw, ops, log):
        applied.append(ops)
        state.update(ch.effective_config(state, ops))
    monkeypatch.setattr(conn, "apply", apply)
    r = client.post("/api/firewalls", headers=admin, json={
        "name": "FW-REST", "connector": "rest", "api_url": "192.0.2.1", "api_password": "sfos_x",
        "api_key_expires_at": "2027-09-25"})
    assert r.status_code == 200, r.text
    fw = r.json()
    assert fw["capabilities"]["format"] == "rest" and fw["api_key_expires_at"].startswith("2027-09-25")
    client.post(f"/api/firewalls/{fw['id']}/sync", headers=admin)
    cfg = client.get(f"/api/firewalls/{fw['id']}/config", headers=admin).json()
    assert cfg["format"] == "rest" and cfg["entities"][0]["entity"] == "firewallRulesIpv4"
    # XML-Entität passt nicht zur REST-Anbindung
    bad = client.post(f"/api/firewalls/{fw['id']}/draft/operations", headers=admin, json={
        "entity": "IPHost", "action": "add", "name": "X", "data": {"Name": "X"}})
    assert bad.status_code == 400
    op = make_user(client, admin, "operator", [("Operator", None)])
    r = client.post(f"/api/firewalls/{fw['id']}/draft/operations", headers=op, json={
        "entity": "addressesIpv4", "action": "add", "name": "Srv",
        "data": {"name": "Srv", "type": "ipv4Address", "ipv4Address": "10.0.0.5", "id": "ignored"}})
    assert r.status_code == 200, r.text
    r = client.post(f"/api/firewalls/{fw['id']}/draft/operations", headers=op, json={
        "entity": "firewallRulesIpv4", "action": "add", "name": "Neu",
        "data": {"name": "Neu", "ruleType": "firewall", "enabled": True, "action": "accept",
                 "sourceZones": {"zones": [{"name": "LAN"}]}, "destinationZones": {"zones": [{"name": "WAN"}]},
                 "destinationNetworks": {"ipv4Addresses": [{"name": "Srv"}]}}, "position": {"type": "top"}})
    assert r.status_code == 200 and r.json()["warnings"] == []
    draft = r.json()["draft"]
    assert "id" not in draft["operations"][0]["data"]
    assert draft["operations"][1]["xml"].startswith("POST /api/firewall-config/v1/firewall/rules/ipv4")
    client.post(f"/api/changes/{draft['id']}/submit", headers=op, json={"title": "REST", "justification": "Test"})
    client.post(f"/api/changes/{draft['id']}/decision", headers=admin, json={"decision": "approve"})
    deploy_sync(draft["id"])
    assert client.get(f"/api/changes/{draft['id']}", headers=op).json()["status"] == "deployed"
    assert [r["name"] for r in state["firewallRulesIpv4"]] == ["Neu", "Alt"]


def test_connection_settings_superadmin_only(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    fwa = make_user(client, admin, "fwadmin", [("Firewall-Administrator", None)])

    # Firewall-Administrator sieht keine Verbindungsdaten …
    fw = client.get(f"/api/firewalls/{fw_id}", headers=fwa).json()
    assert fw["api_url"] is None and fw["api_username"] is None and fw["may_edit_connection"] is False
    assert client.get(f"/api/firewalls/{fw_id}", headers=admin).json()["api_url"] == "fw.test"
    # … darf Name/Gruppe ändern, aber nicht Adresse, Zugangsdaten oder Anbindung
    r = client.put(f"/api/firewalls/{fw_id}", headers=fwa, json={"name": "Umbenannt"})
    assert r.status_code == 200, r.text
    assert client.get(f"/api/firewalls/{fw_id}", headers=admin).json()["api_url"] == "fw.test"
    for change in ({"api_url": "evil.test"}, {"api_password": "neu"}, {"verify_tls": False}, {"connector": "rest"}):
        r = client.put(f"/api/firewalls/{fw_id}", headers=fwa, json={"name": "Umbenannt", **change})
        assert r.status_code == 403, change
    # Anlegen, Verbindungstest und Probelauf nur als Superadmin
    r = client.post("/api/firewalls", headers=fwa, json={"name": "X", "connector": "xmlapi", "api_url": "x.test",
                                                          "api_username": "a", "api_password": "b"})
    assert r.status_code == 403
    assert client.post(f"/api/firewalls/{fw_id}/test", headers=fwa).status_code == 403
    assert client.post(f"/api/firewalls/{fw_id}/diagnose", headers=fwa).status_code == 403


def test_central_and_audit_connection_data_superadmin_only(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    aud = make_user(client, admin, "auditor", [("Auditor", None)])
    r = client.post("/api/roles", headers=admin, json={"name": "Benutzerverwaltung", "permissions": ["admin", "firewall.view"]})
    assert r.status_code == 200, r.text
    adm = make_user(client, admin, "useradmin", [("Benutzerverwaltung", None)])

    # Central-Konten nur für Superadmins, auch nicht mit dem Recht „admin“
    assert client.get("/api/central-accounts", headers=adm).status_code == 403
    assert client.get("/api/central-accounts", headers=admin).status_code == 200

    # Audit-Log: API-Adresse geschwärzt und auch nicht über die Suche auffindbar
    entry = lambda h: next(e for e in client.get("/api/audit", headers=h).json()["items"] if e["action"] == "firewall.created")
    assert entry(admin)["details"]["api_url"] == "fw.test"
    assert entry(aud)["details"]["api_url"] == "•••"
    assert client.get("/api/audit", headers=aud, params={"q": "fw.test"}).json()["total"] == 0
    assert client.get("/api/audit", headers=admin, params={"q": "fw.test"}).json()["total"] >= 1
    csv_text = client.get("/api/audit/export.csv", headers=aud).text
    assert "fw.test" not in csv_text
