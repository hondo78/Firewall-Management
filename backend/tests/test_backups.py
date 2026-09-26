"""Sicherungen: Zeitplan, Aufbewahrung, Rechte, Download, Wiederherstellen über den Entwurf; SFOS-Sicherungszeitplan."""
import json
from datetime import datetime, timezone

import httpx

from app import backups, settings
from app.db import SessionLocal
from app.sophos import connector, entities, restapi
from app.sophos.restapi import RestApiClient

from .conftest import rule
from .test_workflow import make_user, setup_firewall


def test_schedule_slots():
    s = {"backup_frequency": "daily", "backup_time": "02:00", "backup_weekday": 0, "backup_monthday": 31}
    now = datetime(2026, 9, 26, 1, 0, tzinfo=timezone.utc)  # 03:00 in Berlin (Sommerzeit)
    slot = backups.last_slot(s, now)
    assert (slot.day, slot.hour) == (26, 2)
    assert backups.last_slot(s, datetime(2026, 9, 25, 23, 0, tzinfo=timezone.utc)).day == 25  # 01:00 → gestern
    weekly = {**s, "backup_frequency": "weekly", "backup_weekday": 0}
    assert backups.last_slot(weekly, now).weekday() == 0 and backups.last_slot(weekly, now) <= now
    monthly = {**s, "backup_frequency": "monthly"}
    # 31. im September gibt es nicht → letzter Tag des Monats; am 26.9. ist das noch nicht erreicht → 31.8.
    assert backups.last_slot(monthly, now).date().isoformat() == "2026-08-31"
    assert backups.next_slot(monthly, now).date().isoformat() == "2026-09-30"


def test_backup_create_retention_and_rights(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    viewer = make_user(client, admin, "viewer", [("Betrachter", None)])
    fwa = make_user(client, admin, "fwadmin", [("Firewall-Administrator", None)])
    assert client.put("/api/settings", headers=admin, json={"backup_keep": 2}).status_code == 200

    assert client.post(f"/api/firewalls/{fw_id}/backups", headers=viewer, json={}).status_code == 403
    ids = []
    for i in range(3):
        r = client.post(f"/api/firewalls/{fw_id}/backups", headers=fwa, json={"note": f"n{i}"})
        assert r.status_code == 200, r.text
        ids.append(r.json()["id"])
    listing = client.get(f"/api/firewalls/{fw_id}/backups", headers=viewer).json()
    # Aufbewahrung: nur die zwei neuesten
    assert [b["id"] for b in listing["items"]] == [ids[2], ids[1]]
    assert listing["items"][0]["unchanged"] is True and listing["items"][-1]["unchanged"] is None and listing["items"][0]["object_count"] == 6
    assert listing["schedule"]["frequency"] == "daily" and listing["schedule"]["next_run"]

    # Angeheftet → fällt nicht unter die Aufbewahrung
    assert client.patch(f"/api/firewalls/{fw_id}/backups/{ids[1]}", headers=fwa, json={"pinned": True}).status_code == 200
    client.post(f"/api/firewalls/{fw_id}/backups", headers=fwa, json={})
    client.post(f"/api/firewalls/{fw_id}/backups", headers=fwa, json={})
    kept = [b["id"] for b in client.get(f"/api/firewalls/{fw_id}/backups", headers=fwa).json()["items"]]
    assert ids[1] in kept and len(kept) == 3

    # Download (JSON und Entities.xml) auch für Betrachter; Löschen nur Superadmin
    doc = client.get(f"/api/firewalls/{fw_id}/backups/{ids[1]}/download", headers=viewer)
    assert doc.status_code == 200 and json.loads(doc.text)["config"]["FirewallRule"][0]["Name"] == "Regel-A"
    xml = client.get(f"/api/firewalls/{fw_id}/backups/{ids[1]}/download", headers=viewer, params={"format": "xml"})
    assert xml.status_code == 200 and "<FirewallRule" in xml.text
    assert client.delete(f"/api/firewalls/{fw_id}/backups/{ids[1]}", headers=fwa).status_code == 403
    assert client.delete(f"/api/firewalls/{fw_id}/backups/{ids[1]}", headers=admin).status_code == 200
    actions = {e["action"] for e in client.get("/api/audit", headers=admin).json()["items"]}
    assert {"backup.created", "backup.downloaded", "backup.deleted", "backup.updated"} <= actions


def test_scheduled_backup_due(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    with SessionLocal() as db:
        assert backups.due_firewalls(db) == [fw_id]
        from app.models import Firewall
        backups.create(db, db.get(Firewall, fw_id), trigger="scheduled")
        assert backups.due_firewalls(db) == []
        settings.set_many(db, {"backup_enabled": False})
        db.commit()
    client.post(f"/api/firewalls/{fw_id}/backups", headers=admin, json={})  # manuell zählt nicht als geplant
    with SessionLocal() as db:
        assert backups.due_firewalls(db) == []


def test_restore_via_draft(client, admin, fake):
    fw_id = setup_firewall(client, admin)
    bid = client.post(f"/api/firewalls/{fw_id}/backups", headers=admin, json={}).json()["id"]
    # Auf der Firewall ändert sich etwas: Regel-B gelöscht, Server geändert, neuer Host
    fake.config["FirewallRule"] = [rule("Regel-A", services=["HTTPS"])]
    fake.config["IPHost"] = [{"Name": "Server", "IPFamily": "IPv4", "HostType": "IP", "IPAddress": "10.0.0.9"},
                             {"Name": "Neu", "IPFamily": "IPv4", "HostType": "IP", "IPAddress": "10.0.0.5"}]
    assert client.post(f"/api/firewalls/{fw_id}/sync", headers=admin).status_code == 200

    r = client.post(f"/api/firewalls/{fw_id}/backups/{bid}/restore/review", headers=admin)
    assert r.status_code == 200, r.text
    rev = r.json()
    by = {(i["entity"], i["name"]): i for i in rev["items"]}
    assert by[("FirewallRule", "Regel-B")]["status"] == "new"
    assert by[("IPHost", "Server")]["status"] == "changed"
    assert by[("IPHost", "Neu")]["status"] == "removed"
    keys = [by[k]["key"] for k in (("FirewallRule", "Regel-B"), ("IPHost", "Server"), ("IPHost", "Neu"))]
    r = client.post(f"/api/firewalls/{fw_id}/backups/{bid}/restore/apply", headers=admin,
                    json={"token": rev["token"], "keys": keys})
    assert r.status_code == 200, r.text
    assert r.json()["added"] == 3 and not r.json()["skipped"]
    ops = {(o["entity"], o["name"]): o for o in r.json()["draft"]["operations"]}
    assert ops[("FirewallRule", "Regel-B")]["position"] == {"type": "after", "ref": "Regel-A"}
    assert ops[("IPHost", "Neu")]["action"] == "remove"
    assert ops[("IPHost", "Server")]["data"]["IPAddress"] == "10.0.0.1"
    # Vergleich Sicherung ↔ aktuell im Vergleichs-Tab
    cmp = client.get(f"/api/firewalls/{fw_id}/compare", headers=admin, params={"a": f"backup:{bid}", "b": "current"})
    assert cmp.status_code == 200


def test_rest_backup_settings_singleton():
    """SFOS-Sicherungszeitplan: GET/PATCH ohne Namen im Pfad, nur „update“, Rücknahme per PATCH."""
    calls = []
    state = {"backupStorage": "local", "schedule": {"frequency": "weekly", "dayOfWeek": "sunday", "hour": 2, "minute": 30},
             "updatedAt": "2026-01-01T00:00:00Z"}

    def handler(req: httpx.Request):
        calls.append((req.method, req.url.path, json.loads(req.content) if req.content else None))
        if req.url.path.endswith("/system/backup/settings"):
            if req.method == "PATCH":
                if json.loads(req.content).get("backupStorage") == "email":
                    return httpx.Response(400, json={"error": "badRequest", "message": "emailRecipients required"})
                state.update(json.loads(req.content))
            return httpx.Response(200, json=state)
        return httpx.Response(200, json={"items": [], "pages": {"current": 1, "total": 1, "size": 100}})

    restapi._PREFIX_BY_BASE.clear()
    c = RestApiClient("https://fw.test:4444", "k", transport=httpx.MockTransport(handler))
    item = {**c.get_singleton("/system/backup/settings"), "name": "Sicherungs-Zeitplan"}
    before = connector.strip_read_only(item)
    after = {**before, "schedule": {"frequency": "daily", "hour": 1, "minute": 0}}
    logs = []
    connector._rest_apply(c, [{"entity": "backupSettings", "action": "update", "name": "Sicherungs-Zeitplan",
                               "data": after, "before": before}], logs.append)
    method, path, body = calls[-1]
    assert (method, path) == ("PATCH", "/api/firewall-config/v1/system/backup/settings")
    assert body == {"schedule": {"frequency": "daily", "hour": 1, "minute": 0}}  # ohne name/updatedAt
    # Fehler → vorherige Änderung wird per PATCH zurückgenommen
    bad = {**after, "backupStorage": "email"}
    ops = [{"entity": "backupSettings", "action": "update", "name": "Sicherungs-Zeitplan", "data": after, "before": before},
           {"entity": "backupSettings", "action": "update", "name": "Sicherungs-Zeitplan", "data": bad, "before": after}]
    try:
        connector._rest_apply(c, ops, logs.append)
    except connector.DeployError:
        pass
    assert state["schedule"] == before["schedule"]
    assert "backupSettings" in entities.REST_SINGLETONS


def test_singleton_only_update(client, admin, monkeypatch):
    from app import changes
    from app.models import Firewall
    fw = Firewall(connector="rest")
    cfg = {"backupSettings": [{"name": "Sicherungs-Zeitplan", "backupStorage": "local"}]}
    import pytest
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as e:
        changes.validate_operation(fw, {"entity": "backupSettings", "action": "remove", "name": "Sicherungs-Zeitplan"}, cfg)
    assert e.value.status_code == 400
    with pytest.raises(HTTPException) as e:
        changes.validate_operation(fw, {"entity": "backupSettings", "action": "update", "name": "Sicherungs-Zeitplan",
                                        "data": {"name": "Sicherungs-Zeitplan", "backupStorage": "ftp",
                                                 "schedule": {"frequency": "daily"}}}, cfg)
    assert "Server und Benutzer" in e.value.detail
