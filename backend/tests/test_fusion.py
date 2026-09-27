"""Sophos Central Firewall Management API: Inventar, Gruppen, MDR-Threat-Feed (Client, Workflow, Endpunkte)."""
import json

import httpx
import pytest

from app import changes, crypto
from app.db import SessionLocal
from app.models import CentralAccount, Firewall
from app.sophos import central, connector, mdr
from app.sophos.central import CentralClient, CentralError

from .conftest import login
from .test_workflow import deploy_sync, make_user, setup_firewall

REGION = "https://api-eu01.test"


def make_client(handler):
    central._CONFIG_PREFIX.clear()
    return CentralClient("https://id.test", "https://api.test", "cid", "secret", "tenant-1", REGION,
                         transport=httpx.MockTransport(handler))


def token(request):
    return httpx.Response(200, json={"access_token": "t", "expires_in": 3600})


# --- Client ------------------------------------------------------------------------------------------------

def test_client_group_and_firewall_calls():
    seen = []

    def handler(request: httpx.Request):
        if request.url.host == "id.test":
            return token(request)
        seen.append((request.method, request.url.path, json.loads(request.content) if request.content else None))
        return httpx.Response(200, json={"id": "g1"})

    c = make_client(handler)
    c.create_group("Filialen", ["fw1", "fw2"], parent_id="p1", import_from="fw1")
    c.update_group("g1", name="Filialen Nord", unassign=["fw2"])
    c.delete_group("g1")
    c.update_firewall("fw1", geo={"latitude": 53.5, "longitude": 10})
    c.delete_firewall("fw1")
    c.approve_management("fw1")
    assert seen[0] == ("POST", "/firewall/v1/firewall-groups", {
        "name": "Filialen", "assignFirewalls": ["fw1", "fw2"], "parentGroupId": "p1", "configImportSourceFirewallId": "fw1"})
    assert seen[1] == ("PATCH", "/firewall/v1/firewall-groups/g1", {"name": "Filialen Nord", "unassignFirewalls": ["fw2"]})
    assert seen[2][:2] == ("DELETE", "/firewall/v1/firewall-groups/g1")
    # Geokoordinaten verlangt die API als Strings
    assert seen[3] == ("PATCH", "/firewall/v1/firewalls/fw1", {"geoLocation": {"latitude": "53.5", "longitude": "10"}})
    assert seen[4][:2] == ("DELETE", "/firewall/v1/firewalls/fw1")
    assert seen[5] == ("POST", "/firewall/v1/firewalls/fw1/action", {"action": "approveManagement"})


def test_client_mdr_polls_firewall_transaction(monkeypatch):
    monkeypatch.setattr(central.config, "CENTRAL_POLL_SECONDS", 0)
    polls = []

    def handler(request: httpx.Request):
        if request.url.host == "id.test":
            return token(request)
        p = request.url.path
        if p == "/firewall/v1/firewall-config/firewalls/fw1/mdr-threat-feed/indicators":
            assert json.loads(request.content) == {"indicators": [{"type": "ipv4-addr", "value": "1.2.3.4"}]}
            return httpx.Response(202, json={"transactionId": "tx1"})
        if p == "/firewall/v1/firewall-config/firewalls/fw1/transactions/tx1":
            polls.append(request.url.params.get("fields"))
            status = "started" if len(polls) == 1 else "finished"
            return httpx.Response(200, json={"id": "tx1", "status": status, "result": "partialSuccess", "response": {
                "items": [], "errors": {"invalidMDRIndicators": {"items": [{"type": "ipv4-addr", "value": "1.2.3.4"}]}}}})
        return httpx.Response(404, json={"error": "notFound"})

    tx = make_client(handler).mdr_add("fw1", [{"type": "ipv4-addr", "value": "1.2.3.4"}])
    assert len(polls) == 2 and "response" in polls[0]
    with pytest.raises(CentralError):
        mdr._check_add(tx)


def test_client_mdr_error_result():
    def handler(request: httpx.Request):
        if request.url.host == "id.test":
            return token(request)
        if request.url.path.endswith("/mdr-threat-feed"):
            return httpx.Response(202, json={"transactionId": "tx"})
        return httpx.Response(200, json={"id": "tx", "status": "finished", "result": "error",
                                         "response": {"message": "Feature not licensed"}})

    with pytest.raises(CentralError, match="Feature not licensed"):
        make_client(handler).mdr_feed("fw1")


# --- MDR-Logik ---------------------------------------------------------------------------------------------

class FakeCentral:
    def __init__(self, indicators=None, search_format="items"):
        self.feed = {"enabled": "true", "action": "logAndDrop", "lastUpdatedAt": "2026-01-01T00:00:00Z"}
        self.indicators = dict(indicators or {})
        self.calls = []
        self.search_format = search_format
        self.fail_on = None

    def _call(self, name, *args):
        self.calls.append((name, *args))
        if self.fail_on == name:
            self.fail_on = None               # nur einmal – die Rücknahme darf denselben Aufruf nutzen
            raise CentralError(f"{name} kaputt")

    def mdr_feed(self, cid, log=None):
        self._call("feed")
        return self.feed

    def mdr_search(self, cid, values, log=None):
        self._call("search", tuple(values))
        if self.search_format != "items":
            return {"response": {"something": "else"}}
        return {"response": {"items": [{"type": self.indicators[v], "value": v} for v in values if v in self.indicators]}}

    def mdr_settings(self, cid, enabled=None, action=None, log=None):
        self._call("settings", enabled, action)

    def mdr_add(self, cid, items, log=None):
        self._call("add", tuple(i["value"] for i in items))
        for i in items:
            self.indicators[i["value"]] = i["type"]
        return {"response": {"items": items}}

    def mdr_delete(self, cid, items, log=None):
        self._call("delete", tuple(i["value"] for i in items))
        for i in items:
            self.indicators.pop(i["value"], None)

    def mdr_delete_all(self, cid, log=None):
        self._call("delete_all")
        self.indicators.clear()


def test_mdr_fetch_keeps_only_indicators_still_present():
    c = FakeCentral({"1.2.3.4": "ipv4-addr"})
    cached = [{"name": "1.2.3.4", "type": "ipv4-addr"}, {"name": "evil.example", "type": "domain-name"}]
    out = mdr.fetch(c, "fw1", cached)
    assert out["mdrThreatFeed"] == [{"name": "MDR-Threat-Feed", "enabled": True, "action": "logAndDrop"}]
    assert [o["name"] for o in out["mdrIndicators"]] == ["1.2.3.4"]
    # Unbekanntes Antwortformat der Suche: nichts als gelöscht betrachten
    out = mdr.fetch(FakeCentral(search_format="other"), "fw1", cached)
    assert len(out["mdrIndicators"]) == 2


def test_mdr_search_in_chunks_of_100():
    cached = [{"name": f"10.0.{i // 250}.{i % 250}", "type": "ipv4-addr"} for i in range(250)]
    c = FakeCentral({o["name"]: "ipv4-addr" for o in cached})
    assert len(mdr.fetch(c, "fw1", cached)["mdrIndicators"]) == 250
    assert [len(x[1]) for x in c.calls if x[0] == "search"] == [100, 100, 50]


def test_mdr_apply_order_and_rollback():
    c = FakeCentral({"old.example": "domain-name"})
    ops = [
        {"entity": "mdrIndicators", "action": "add", "name": "1.2.3.4", "data": {"name": "1.2.3.4", "type": "ipv4-addr"}},
        {"entity": "mdrIndicators", "action": "remove", "name": "old.example", "before": {"name": "old.example", "type": "domain-name"}},
        {"entity": "mdrThreatFeed", "action": "update", "name": "MDR-Threat-Feed",
         "data": {"name": "MDR-Threat-Feed", "enabled": True, "action": "logAndDrop"},
         "before": {"name": "MDR-Threat-Feed", "enabled": False, "action": "logOnly"}},
    ]
    undo = mdr.apply(c, "fw1", ops, lambda m: None)
    assert [x[0] for x in c.calls] == ["settings", "delete", "add"]
    assert c.indicators == {"1.2.3.4": "ipv4-addr"}
    undo()
    assert c.indicators == {"old.example": "domain-name"}
    assert c.calls[-1] == ("settings", False, "logOnly")

    # Fehler mitten im MDR-Teil: bereits Ausgeführtes wird zurückgenommen
    c = FakeCentral({"old.example": "domain-name"})
    c.fail_on = "add"
    with pytest.raises(CentralError):
        mdr.apply(c, "fw1", ops, lambda m: None)
    assert c.indicators == {"old.example": "domain-name"}


def test_mdr_clear_all():
    c = FakeCentral({"a.example": "domain-name", "b.example": "domain-name"})
    mdr.apply(c, "fw1", [{"entity": "mdrThreatFeed", "action": "update", "name": "MDR-Threat-Feed",
                          "data": {"name": "MDR-Threat-Feed", "enabled": True, "action": "logAndDrop", "clearIndicators": True},
                          "before": {"name": "MDR-Threat-Feed", "enabled": True, "action": "logAndDrop"}}], lambda m: None)
    assert c.indicators == {} and [x[0] for x in c.calls] == ["delete_all"]


def test_validate_indicator():
    assert mdr.validate_indicator("1.2.3.4", "ipv4-addr") is None
    assert mdr.validate_indicator("10.0.0.0/8", "ipv4-addr") is None
    assert mdr.validate_indicator("1.2.3", "ipv4-addr")
    assert mdr.validate_indicator("evil.example.com", "domain-name") is None
    assert mdr.validate_indicator("not a domain", "domain-name")
    assert mdr.validate_indicator("www.example.com/index.php", "url") is None
    assert mdr.validate_indicator("x", "md5")


def test_connector_rolls_back_mdr_when_config_part_fails(monkeypatch):
    undone = []
    monkeypatch.setattr(connector, "_central_for", lambda db, fw: (None, "fw1"))
    monkeypatch.setattr(mdr, "apply", lambda client, cid, ops, log: lambda: undone.append(True))

    def broken(db, fw, ops, log):
        raise connector.DeployError("Firewall sagt nein")
    monkeypatch.setattr(connector, "_apply_firewall", broken)
    ops = [{"entity": "mdrIndicators", "action": "add", "name": "1.2.3.4", "data": {"name": "1.2.3.4", "type": "ipv4-addr"}},
           {"entity": "IPHost", "action": "add", "name": "X", "data": {"Name": "X"}}]
    with pytest.raises(connector.DeployError):
        connector.apply(None, None, ops, lambda m: None)
    assert undone == [True]


# --- Workflow ----------------------------------------------------------------------------------------------

def link_central(fw_id):
    with SessionLocal() as db:
        acc = CentralAccount(name="Tenant", client_id="cid", id_url="https://id.test", api_url="https://api.test",
                             data_region=REGION, id_type="tenant", tenant_id="t1")
        acc.client_secret_enc = ""
        db.add(acc)
        db.flush()
        acc.client_secret_enc = crypto.encrypt("secret", f"central:{acc.id}")
        fw = db.get(Firewall, fw_id)
        fw.central_account_id, fw.central_id = acc.id, "c-fw1"
        db.commit()
        return acc.id


@pytest.fixture()
def mdr_fake(fake):
    fake.config["mdrThreatFeed"] = [{"name": "MDR-Threat-Feed", "enabled": False, "action": "logOnly"}]
    fake.config["mdrIndicators"] = [{"name": "bad.example", "type": "domain-name"}]
    return fake


def test_mdr_changes_need_central_link_and_four_eyes(client, admin, mdr_fake):
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    ap = make_user(client, admin, "approver", [("Approver", None)])
    ind = {"entity": "mdrIndicators", "action": "add", "name": "5.6.7.8", "data": {"name": "5.6.7.8", "type": "ipv4-addr"}}
    r = client.post(f"/api/firewalls/{fw_id}/draft/operations", headers=op, json=ind)
    assert r.status_code == 400 and "Sophos Central" in r.json()["detail"]
    # Ohne Central-Zuordnung auch nicht im Editor sichtbar
    cfg = client.get(f"/api/firewalls/{fw_id}/config", headers=op).json()
    assert "mdrIndicators" not in [e["entity"] for e in cfg["entities"]]

    link_central(fw_id)
    client.post(f"/api/firewalls/{fw_id}/sync", headers=admin)
    cfg = client.get(f"/api/firewalls/{fw_id}/config", headers=op).json()
    assert {"mdrThreatFeed", "mdrIndicators"} <= {e["entity"] for e in cfg["entities"]}

    bad = {**ind, "name": "1.2.3", "data": {"name": "1.2.3", "type": "ipv4-addr"}}
    assert client.post(f"/api/firewalls/{fw_id}/draft/operations", headers=op, json=bad).status_code == 400
    upd = {"entity": "mdrIndicators", "action": "update", "name": "bad.example", "data": {"name": "bad.example", "type": "url"}}
    assert client.post(f"/api/firewalls/{fw_id}/draft/operations", headers=op, json=upd).status_code == 400

    r = client.post(f"/api/firewalls/{fw_id}/draft/operations", headers=op, json=ind)
    assert r.status_code == 200, r.text
    assert "POST /firewall/v1/firewall-config/firewalls/c-fw1/mdr-threat-feed/indicators" in r.json()["draft"]["operations"][0]["xml"]
    feed = {"entity": "mdrThreatFeed", "action": "update", "name": "MDR-Threat-Feed",
            "data": {"name": "MDR-Threat-Feed", "enabled": True, "action": "logAndDrop"}}
    r = client.post(f"/api/firewalls/{fw_id}/draft/operations", headers=op, json=feed)
    assert r.status_code == 200, r.text
    assert "PATCH" in r.json()["draft"]["operations"][1]["xml"]
    draft_id = r.json()["draft"]["id"]
    client.post(f"/api/changes/{draft_id}/submit", headers=op, json={"title": "IoC", "justification": "MDR-Fall 7"})
    assert client.post(f"/api/changes/{draft_id}/decision", headers=op, json={"decision": "approve"}).status_code == 403
    assert client.post(f"/api/changes/{draft_id}/decision", headers=ap, json={"decision": "approve"}).status_code == 200
    deploy_sync(draft_id)
    assert client.get(f"/api/changes/{draft_id}", headers=op).json()["status"] == "deployed"
    assert {o["entity"] for o in mdr_fake.applied[0]} == {"mdrIndicators", "mdrThreatFeed"}
    assert [o["name"] for o in mdr_fake.config["mdrIndicators"]] == ["bad.example", "5.6.7.8"]


def test_mdr_clear_all_in_preview_and_not_revertable(client, admin, mdr_fake):
    fw_id = setup_firewall(client, admin)
    link_central(fw_id)
    client.post(f"/api/firewalls/{fw_id}/sync", headers=admin)
    op = make_user(client, admin, "operator", [("Firewall-Administrator", None)])
    ap = make_user(client, admin, "approver", [("Approver", None)])
    clear = {"entity": "mdrThreatFeed", "action": "update", "name": "MDR-Threat-Feed",
             "data": {"name": "MDR-Threat-Feed", "enabled": False, "action": "logOnly", "clearIndicators": True}}
    r = client.post(f"/api/firewalls/{fw_id}/draft/operations", headers=op, json=clear)
    assert r.status_code == 200, r.text
    assert "DELETE /firewall/v1/firewall-config/firewalls/c-fw1/mdr-threat-feed/indicators" in r.json()["draft"]["operations"][0]["xml"]
    cfg = client.get(f"/api/firewalls/{fw_id}/config", headers=op).json()
    assert cfg["preview"]["mdrIndicators"] == [] and cfg["objects"]["mdrIndicators"]
    cid = r.json()["draft"]["id"]
    client.post(f"/api/changes/{cid}/submit", headers=op, json={"title": "Feed leeren", "justification": "Neustart"})
    client.post(f"/api/changes/{cid}/decision", headers=ap, json={"decision": "approve"})
    deploy_sync(cid)
    r = client.post(f"/api/changes/{cid}/revert", headers=op, json={"justification": "doch nicht"})
    assert r.status_code == 409 and "nicht umkehren" in r.json()["detail"]


def test_mdr_search_endpoint(client, admin, fake, monkeypatch):
    fw_id = setup_firewall(client, admin)
    link_central(fw_id)
    fc = FakeCentral({"1.2.3.4": "ipv4-addr"})
    monkeypatch.setattr(connector, "central_client", lambda acc: fc)
    r = client.post(f"/api/firewalls/{fw_id}/mdr/search", headers=admin, json={"values": ["1.2.3.4", "9.9.9.9"]})
    assert r.status_code == 200, r.text
    assert r.json()["found"] == ["1.2.3.4"] and r.json()["missing"] == ["9.9.9.9"]


# --- Inventar-Endpunkte ------------------------------------------------------------------------------------

class FakeInventory(FakeCentral):
    def __init__(self):
        super().__init__()
        self.fws = [{"id": "c-fw1", "name": "FW-Test", "serialNumber": "S1", "status": {"managingStatus": "approvalPending"}}]
        self.grps = [{"id": "g1", "name": "Filialen"}]

    def firewalls(self, group_id=None, search=None):
        return self.fws

    def groups(self):
        return self.grps

    def create_group(self, name, assign, parent_id=None, import_from=None):
        self._call("create_group", name, tuple(assign), parent_id, import_from)
        return {"id": "g2", "name": name}

    def delete_firewall(self, cid):
        self._call("delete_firewall", cid)

    def delete_group(self, gid):
        self._call("delete_group", gid)


def test_inventory_endpoints_superadmin_only(client, admin, fake, monkeypatch):
    fw_id = setup_firewall(client, admin)
    acc_id = link_central(fw_id)
    inv = FakeInventory()
    monkeypatch.setattr(connector, "central_client", lambda acc: inv)
    monkeypatch.setattr("app.routers.central.sync.sync_central_inventory", lambda db, acc, actor: {})
    fa = make_user(client, admin, "fwadmin", [("Firewall-Administrator", None)])
    assert client.get(f"/api/central-accounts/{acc_id}/inventory", headers=fa).status_code == 403

    r = client.get(f"/api/central-accounts/{acc_id}/inventory", headers=admin)
    assert r.status_code == 200, r.text
    f = r.json()["firewalls"][0]
    assert f["local"]["id"] == fw_id and f["status"]["managing"] == "approvalPending"

    r = client.post(f"/api/central-accounts/{acc_id}/groups", headers=admin,
                    json={"name": "Neu", "assign": ["c-fw1"], "import_from": "c-fw1"})
    assert r.status_code == 200, r.text
    assert ("create_group", "Neu", ("c-fw1",), None, "c-fw1") in inv.calls

    # Löschen nur mit dem Namen als Bestätigung
    r = client.request("DELETE", f"/api/central-accounts/{acc_id}/firewalls/c-fw1", headers=admin, json={"confirm": "falsch"})
    assert r.status_code == 400 and ("delete_firewall", "c-fw1") not in inv.calls
    r = client.request("DELETE", f"/api/central-accounts/{acc_id}/firewalls/c-fw1", headers=admin, json={"confirm": "FW-Test"})
    assert r.status_code == 200, r.text
    # XML-API-Firewall bleibt verwaltet, nur ohne Central-Zuordnung
    fw = client.get(f"/api/firewalls/{fw_id}", headers=admin).json()
    assert fw["central_linked"] is False
    actions = [e["action"] for e in client.get("/api/audit", headers=admin).json()["items"]]
    assert "central.firewall_deleted" in actions and "central.group_created" in actions
