"""Benachrichtigungen: Empfänger, Texte, Kanäle (Versand abgefangen) und Genehmigen per Telegram."""
import pytest

from app import notify
from app.notify import channels

from .test_workflow import deploy_sync, login, make_user, setup_firewall, submit_new_rule


@pytest.fixture()
def outbox(monkeypatch):
    box = {"mail": [], "telegram": [], "teams": [], "tg_calls": []}
    monkeypatch.setattr(channels, "send_mail", lambda cfg, to, s, b: box["mail"].append((sorted(to), s, b)))
    monkeypatch.setattr(channels, "send_telegram",
                        lambda cfg, chat, text, buttons=None: box["telegram"].append((chat, text, buttons)))
    monkeypatch.setattr(channels, "send_teams", lambda cfg, title, lines, url="": box["teams"].append(title))
    monkeypatch.setattr(channels, "tg_call", lambda cfg, method, http_timeout=15, **p: box["tg_calls"].append((method, p)) or {})
    return box


def enable_all(client, admin):
    r = client.put("/api/notifications/config", headers=admin, json={
        "public_url": "http://fwm.test",
        "email": {"enabled": True, "host": "smtp.test", "sender": "fwm@test", "password": "geheim"},
        "telegram": {"enabled": True, "bot_token": "123:abc", "bot_username": "fwm_bot"},
        "teams": {"enabled": True, "webhook_url": "https://teams.test/hook"}})
    assert r.status_code == 200
    cfg = r.json()
    assert cfg["email"]["password_set"] and "password" not in cfg["email"] and cfg["teams"]["webhook_url_set"]


def user_with_mail(client, admin, name, role):
    h = make_user(client, admin, name, [(role, None)])
    client.put("/api/auth/notifications", headers=h, json={"email": f"{name}@test"})
    return h


def test_approvers_get_notified_and_requester_gets_result(client, admin, fake, outbox):
    enable_all(client, admin)
    fw_id = setup_firewall(client, admin)
    op = user_with_mail(client, admin, "operator", "Operator")
    ap = user_with_mail(client, admin, "approver", "Approver")
    user_with_mail(client, admin, "leser", "Betrachter")
    cid = submit_new_rule(client, fw_id, op)
    to, subject, body = outbox["mail"][-1]
    assert to == ["approver@test"] and "Genehmigung benötigt" in subject and "http://fwm.test/changes/" in body
    assert outbox["teams"] and "Genehmigung benötigt" in outbox["teams"][-1]
    client.post(f"/api/changes/{cid}/decision", headers=ap, json={"decision": "approve"})
    assert outbox["mail"][-1][0] == ["operator@test"] and "genehmigt" in outbox["mail"][-1][1]
    deploy_sync(cid)
    assert sorted(outbox["mail"][-1][0]) == ["approver@test", "operator@test"]
    assert "ausgerollt" in outbox["mail"][-1][1]


def test_email_opt_out(client, admin, fake, outbox):
    enable_all(client, admin)
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    ap = user_with_mail(client, admin, "approver", "Approver")
    client.put("/api/auth/notifications", headers=ap, json={"notify_email": False})
    submit_new_rule(client, fw_id, op)
    assert all("approver@test" not in m[0] for m in outbox["mail"])


def test_telegram_link_and_approve_button(client, admin, fake, outbox):
    enable_all(client, admin)
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    ap = make_user(client, admin, "approver", [("Approver", None)])
    code = client.post("/api/auth/telegram-link", headers=ap).json()["code"]
    notify.handle_update({"message": {"text": f"/start {code}", "chat": {"id": 4711}}})
    assert client.get("/api/auth/me", headers=ap).json()["telegram_linked"] is True
    # Operator verknüpft ebenfalls – darf per Knopf aber nicht genehmigen
    code2 = client.post("/api/auth/telegram-link", headers=op).json()["code"]
    notify.handle_update({"message": {"text": f"/start {code2}", "chat": {"id": 815}}})
    cid = submit_new_rule(client, fw_id, op)
    chat, text, buttons = next(t for t in outbox["telegram"] if t[0] == "4711" and t[2])
    assert buttons[0][0]["callback_data"] == f"approve:{cid}"
    notify.handle_update({"callback_query": {"id": "q1", "data": f"approve:{cid}", "message": {"chat": {"id": 815}}}})
    assert client.get(f"/api/changes/{cid}", headers=op).json()["status"] == "pending"
    assert "Vier-Augen" in outbox["tg_calls"][-1][1]["text"] or "Berechtigung" in outbox["tg_calls"][-1][1]["text"]
    notify.handle_update({"callback_query": {"id": "q2", "data": f"approve:{cid}", "message": {"chat": {"id": 4711}}}})
    assert client.get(f"/api/changes/{cid}", headers=op).json()["status"] == "approved"
    entry = client.get("/api/audit", headers=admin, params={"action": "change.approved"}).json()["items"][0]
    assert entry["actor"] == "approver" and entry["details"]["via"] == "telegram"
    # ungültiger Code
    notify.handle_update({"message": {"text": "/start FALSCH", "chat": {"id": 1}}})
    assert "ungültig" in outbox["telegram"][-1][1]


def test_key_expiry_reminder_levels(client, admin, fake, outbox):
    from datetime import datetime, timedelta, timezone
    from app.db import SessionLocal
    from app.models import Firewall
    enable_all(client, admin)
    client.put("/api/auth/notifications", headers=admin, json={"email": "admin@test"})
    fw_id = setup_firewall(client, admin)
    with SessionLocal() as db:
        fw = db.get(Firewall, fw_id)
        fw.connector, fw.api_key_expires_at = "rest", datetime.now(timezone.utc) + timedelta(days=20, hours=1)
        db.commit()
    notify.check_reminders()
    notify.check_reminders()              # gleiche Stufe nicht doppelt
    assert len([m for m in outbox["mail"] if "API-Key" in m[1]]) == 1
    with SessionLocal() as db:
        db.get(Firewall, fw_id).api_key_expires_at = datetime.now(timezone.utc) + timedelta(days=3)
        db.commit()
    notify.check_reminders()
    assert len([m for m in outbox["mail"] if "API-Key" in m[1]]) == 2
