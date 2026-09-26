"""Benachrichtigungen per E-Mail, Microsoft Teams, Slack und Telegram.

change_event(change_id, kind): nach Workflow-Schritten (eingereicht, entschieden, ausgerollt …) – läuft im
Thread-Pool, damit langsame Mailserver/Webhooks die API nicht bremsen.
check_reminders(): vom Worker – Befristungen, die bald ablaufen, und ablaufende API-Keys.
Telegram: Approver erhalten einen Knopf „Genehmigen“; die Entscheidung läuft über changes.decide()
(gleiche Rechte- und Vier-Augen-Prüfung wie im Web). Ablehnen nur im Web (Begründung ist Pflicht).
"""
import logging
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from sqlalchemy import select

from .. import permissions
from ..audit import audit
from ..db import SessionLocal
from ..models import ChangeRequest, Firewall, User, utcnow
from . import channels, config as ncfg, texts

log = logging.getLogger("fwm.notify")
_pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="notify")
# Tests setzen das auf True: dann synchron statt im Thread-Pool
SYNC = False

KEY_WARN_DAYS = (30, 7, 1)


def change_event(change_id: str, kind: str) -> None:
    if SYNC:
        _safe(_change_event, change_id, kind)
    else:
        _pool.submit(_safe, _change_event, change_id, kind)


def _safe(fn, *args) -> None:
    try:
        fn(*args)
    except Exception:
        log.exception("Benachrichtigung fehlgeschlagen")


def _active_users(db) -> list[User]:
    return db.execute(select(User).where(User.active.is_(True))).scalars().all()


def approvers(db, fw: Firewall, exclude: str | None) -> list[User]:
    return [u for u in _active_users(db) if u.id != exclude and permissions.can(db, u, "change.approve", fw)]


def managers(db, fw: Firewall) -> list[User]:
    return [u for u in _active_users(db) if permissions.can(db, u, "firewall.manage", fw)]


def _recipients(db, cr: ChangeRequest, kind: str) -> list[User]:
    if kind == "pending":
        return approvers(db, cr.firewall, cr.created_by)
    people = {cr.creator.id: cr.creator} if cr.creator else {}
    if kind in ("deployed", "failed", "conflict", "expiry_failed"):
        for e in cr.events:
            if e.kind == "approved" and e.user_id:
                u = db.get(User, e.user_id)
                if u:
                    people[u.id] = u
        if kind != "deployed" or not people:
            # Fehler auch an die Verwalter der Firewall (oder System-Rücknahme ohne Antragsteller)
            for u in managers(db, cr.firewall):
                people[u.id] = u
    return [u for u in people.values() if u.active]


def deliver(db, cfg: dict, users: list[User], subject: str, body: str, buttons=None, teams: tuple | None = None,
            urgent: bool = False):
    """An Benutzer (Mail + Telegram) und optional an die Kanäle (Teams, Slack) senden; Fehler je Kanal protokollieren.

    teams = (Titel, Zeilen[, Link]) – die Kanal-Nachricht für Teams und Slack; urgent → Slack-Erwähnung (@here).
    """
    errors = []
    if cfg["email"]["enabled"] and cfg["email"]["host"]:
        to = [u.email for u in users if u.email and u.notify_email]
        try:
            channels.send_mail(cfg, to, subject, body)
        except Exception as e:
            errors.append(f"E-Mail: {e}")
    if cfg["telegram"]["enabled"] and cfg["telegram"]["bot_token"]:
        for u in users:
            if u.telegram_chat_id:
                try:
                    channels.send_telegram(cfg, u.telegram_chat_id, f"{subject}\n\n{body}", buttons)
                except Exception as e:
                    errors.append(f"Telegram ({u.username}): {e}")
    if teams and cfg["teams"]["enabled"] and cfg["teams"]["webhook_url"]:
        try:
            channels.send_teams(cfg, *teams)
        except Exception as e:
            errors.append(f"Teams: {e}")
    if teams and cfg["slack"]["enabled"] and cfg["slack"]["webhook_url"]:
        try:
            channels.send_slack(cfg, *teams, urgent=urgent)
        except Exception as e:
            errors.append(f"Slack: {e}")
    for err in errors:
        log.warning("Benachrichtigung: %s", err)
    return errors


def _change_event(change_id: str, kind: str) -> None:
    with SessionLocal() as db:
        cr = db.get(ChangeRequest, change_id)
        if not cr:
            return
        cfg = ncfg.load(db)
        users = _recipients(db, cr, kind)
        subject, body = texts.change_message(cr, kind, cfg["public_url"])
        buttons = None
        if kind == "pending" and cfg["telegram"].get("allow_approve"):
            buttons = [[{"text": "✅ Genehmigen", "callback_data": f"approve:{cr.id}"}]]
        url = texts.link(cfg["public_url"], cr)
        teams = (subject, texts.change_lines(cr, kind), url) if kind in (
            "pending", "deployed", "failed", "conflict", "expiry_failed") else None
        deliver(db, cfg, users, subject, body, buttons, teams, urgent=kind == "pending")


def check_reminders() -> None:
    """Vom Worker regelmäßig aufgerufen."""
    with SessionLocal() as db:
        cfg = ncfg.load(db)
        now = utcnow()
        # Befristungen, die in den nächsten 24 h ablaufen
        for cr in db.execute(select(ChangeRequest).where(
                ChangeRequest.status == "deployed", ChangeRequest.expires_at.is_not(None),
                ChangeRequest.expires_at <= now + timedelta(hours=24), ChangeRequest.expires_at > now,
                ChangeRequest.expiry_warned.is_(False))).scalars():
            subject, body = texts.change_message(cr, "expiry_soon", cfg["public_url"])
            deliver(db, cfg, _recipients(db, cr, "expiry_soon"), subject, body)
            cr.expiry_warned = True
            db.commit()
        # API-Keys: Warnung 30, 7 und 1 Tag vor Ablauf (jede Stufe einmal)
        for fw in db.execute(select(Firewall).where(
                Firewall.archived.is_(False), Firewall.connector == "rest",
                Firewall.api_key_expires_at.is_not(None))).scalars():
            days = (fw.api_key_expires_at - now).days
            level = next((d for d in reversed(KEY_WARN_DAYS) if days < d), None)
            if level is None or (fw.api_key_warned_days and fw.api_key_warned_days <= level):
                continue
            text = (f"Der API-Key der Firewall „{fw.name}“ läuft am {fw.api_key_expires_at:%d.%m.%Y} ab "
                    f"({'abgelaufen' if days < 0 else f'in {days} Tagen'}). Bitte auf der Firewall unter "
                    "Administration › API access einen neuen Key erzeugen und in den Einstellungen eintragen.")
            if cfg["public_url"]:
                text += f"\n\n{cfg['public_url']}/firewalls/{fw.id}/settings"
            subject = f"[Firewall] API-Key läuft ab: {fw.name}"
            deliver(db, cfg, managers(db, fw), subject, text, teams=(subject, [text]))
            fw.api_key_warned_days = level
            db.commit()


def drift_detected(firewall_id: str, summary: dict) -> None:
    def run():
        with SessionLocal() as db:
            fw = db.get(Firewall, firewall_id)
            cfg = ncfg.load(db)
            parts = [f"{e}: +{s['added']} −{s['removed']} ~{s['modified']}" for e, s in summary.items()]
            text = (f"An der Firewall „{fw.name}“ wurde die Konfiguration außerhalb dieses Tools geändert:\n"
                    + "\n".join(parts))
            if cfg["public_url"]:
                text += f"\n\nVergleich: {cfg['public_url']}/firewalls/{fw.id}/compare"
            subject = f"[Firewall] Änderung außerhalb des Tools: {fw.name}"
            deliver(db, cfg, managers(db, fw), subject, text, teams=(subject, text.split("\n")))
    if SYNC:
        _safe(run)
    else:
        _pool.submit(_safe, run)


def backup_failed(firewall_id: str, error: str) -> None:
    def run():
        with SessionLocal() as db:
            fw = db.get(Firewall, firewall_id)
            cfg = ncfg.load(db)
            text = f"Die automatische Sicherung der Firewall „{fw.name}“ ist fehlgeschlagen:\n{error}"
            if cfg["public_url"]:
                text += f"\n\nSicherungen: {cfg['public_url']}/firewalls/{fw.id}/backups"
            subject = f"[Firewall] Sicherung fehlgeschlagen: {fw.name}"
            deliver(db, cfg, managers(db, fw), subject, text, teams=(subject, text.split("\n")))
    if SYNC:
        _safe(run)
    else:
        _pool.submit(_safe, run)


# --- Telegram: Verknüpfung und Genehmigen per Knopf ----------------------------------------------------------

_link_codes: dict[str, tuple[str, float]] = {}   # code → (user_id, gültig bis)


def create_link_code(user: User) -> str:
    code = secrets.token_hex(4).upper()
    _link_codes[code] = (user.id, time.time() + 600)
    return code


def handle_update(update: dict) -> None:
    with SessionLocal() as db:
        cfg = ncfg.load(db)
        msg = update.get("message") or {}
        text = (msg.get("text") or "").strip()
        chat_id = str((msg.get("chat") or {}).get("id") or "")
        if text.startswith("/start"):
            code = text.split(maxsplit=1)[1].strip().upper() if " " in text else ""
            entry = _link_codes.pop(code, None)
            if not entry or entry[1] < time.time():
                channels.send_telegram(cfg, chat_id, "Code ungültig oder abgelaufen – im Profil einen neuen erzeugen.")
                return
            user = db.get(User, entry[0])
            user.telegram_chat_id = chat_id
            audit(db, "user.telegram_linked", actor=user, target_type="user", target_id=user.id)
            channels.send_telegram(cfg, chat_id, f"Verknüpft mit {user.username}. Sie erhalten jetzt Benachrichtigungen.")
            return
        cb = update.get("callback_query")
        if not cb:
            return
        chat_id = str(((cb.get("message") or {}).get("chat") or {}).get("id") or "")
        data = cb.get("data") or ""
        answer = "Unbekannte Aktion"
        user = db.execute(select(User).where(User.telegram_chat_id == chat_id, User.active.is_(True))).scalar()
        if data.startswith("approve:") and user and cfg["telegram"].get("allow_approve"):
            from fastapi import HTTPException
            from .. import changes
            cr = db.get(ChangeRequest, data.split(":", 1)[1])
            try:
                if not cr:
                    raise HTTPException(404, "Antrag nicht gefunden")
                changes.decide(db, user, cr, "approve", "per Telegram", ip="telegram")
                answer = f"{texts.cr_no(cr)} genehmigt" + (" – wird ausgerollt" if cr.status == "approved" else "")
            except HTTPException as e:
                answer = str(e.detail)
        elif not user:
            answer = "Dieser Chat ist mit keinem Benutzer verknüpft"
        try:
            channels.tg_call(cfg, "answerCallbackQuery", callback_query_id=cb.get("id"), text=answer[:190],
                             show_alert=True)
        except Exception:
            log.warning("Telegram answerCallbackQuery fehlgeschlagen")


def run_telegram_forever(stop: threading.Event) -> None:
    """Long Polling (kein öffentlicher Endpunkt nötig); Konfiguration wird bei jedem Durchlauf neu gelesen."""
    offset = 0
    while not stop.is_set():
        with SessionLocal() as db:
            cfg = ncfg.load(db)
        if not (cfg["telegram"]["enabled"] and cfg["telegram"]["bot_token"]):
            stop.wait(15)
            continue
        try:
            # Telegram hält die Anfrage bis zu 30 s offen (Long Polling), HTTP-Timeout etwas länger
            updates = channels.tg_call(cfg, "getUpdates", http_timeout=40, offset=offset, timeout=30,
                                       allowed_updates=["message", "callback_query"])
            for u in updates:
                offset = u["update_id"] + 1
                _safe(handle_update, u)
        except Exception as e:
            log.warning("Telegram-Polling: %s", e)
            stop.wait(10)
