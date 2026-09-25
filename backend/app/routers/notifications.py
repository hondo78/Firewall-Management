"""Benachrichtigungen: Kanal-Konfiguration (Admin), Testversand, persönliche Einstellungen."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session as DbSession

from .. import notify
from ..audit import audit
from ..db import get_db
from ..models import User
from ..notify import channels, config as ncfg
from ..permissions import require_global
from ..security import client_ip, get_current_user

router = APIRouter(prefix="/api", tags=["notifications"])
admin_only = require_global("admin")


@router.get("/notifications/config")
def get_config(_: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    return ncfg.public_view(ncfg.load(db))


@router.put("/notifications/config")
def put_config(body: dict, request: Request, actor: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    try:
        result = ncfg.save(db, body)
    except (TypeError, ValueError):
        raise HTTPException(400, "Ungültiger Wert")
    if result["changed"]:
        audit(db, "notifications.updated", actor=actor, ip=client_ip(request), details=result)
    else:
        db.commit()
    return ncfg.public_view(ncfg.load(db))


class TestIn(BaseModel):
    channel: str


@router.post("/notifications/test")
def send_test(body: TestIn, actor: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    """Testnachricht an den eigenen Benutzer (Mail/Telegram) bzw. den Teams-Kanal."""
    cfg = ncfg.load(db)
    subject, text = "[Firewall] Testnachricht", f"Test der Benachrichtigungen, ausgelöst von {actor.username}."
    try:
        if body.channel == "email":
            if not actor.email:
                raise HTTPException(400, "Für Ihren Benutzer ist keine E-Mail-Adresse hinterlegt")
            channels.send_mail(cfg, [actor.email], subject, text)
        elif body.channel == "telegram":
            if not actor.telegram_chat_id:
                raise HTTPException(400, "Ihr Benutzer ist nicht mit Telegram verknüpft (Profil)")
            me = channels.tg_call(cfg, "getMe")
            channels.send_telegram(cfg, actor.telegram_chat_id, f"{subject}\n\n{text}")
            return {"ok": True, "message": f"Gesendet über @{me.get('username')}"}
        elif body.channel == "teams":
            channels.send_teams(cfg, subject, [text], cfg["public_url"])
        else:
            raise HTTPException(400, "Unbekannter Kanal")
    except HTTPException:
        raise
    except Exception as e:
        return {"ok": False, "message": str(e)}
    return {"ok": True, "message": "Gesendet"}


class PrefsIn(BaseModel):
    notify_email: bool | None = None
    email: str | None = None


@router.put("/auth/notifications")
def my_prefs(body: PrefsIn, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    if body.notify_email is not None:
        user.notify_email = body.notify_email
    if body.email is not None:
        user.email = body.email.strip()
    audit(db, "user.notification_prefs", actor=user, target_type="user", target_id=user.id,
          details={"notify_email": user.notify_email, "email": user.email})
    return {"notify_email": user.notify_email, "email": user.email, "telegram_linked": bool(user.telegram_chat_id)}


@router.post("/auth/telegram-link")
def telegram_link(user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    cfg = ncfg.load(db)
    if not (cfg["telegram"]["enabled"] and cfg["telegram"]["bot_token"]):
        raise HTTPException(400, "Telegram ist nicht eingerichtet")
    code = notify.create_link_code(user)
    bot = cfg["telegram"].get("bot_username") or ""
    return {"code": code, "bot": bot, "url": f"https://t.me/{bot}?start={code}" if bot else "",
            "expires_in": 600}


@router.delete("/auth/telegram-link")
def telegram_unlink(user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    user.telegram_chat_id = ""
    audit(db, "user.telegram_unlinked", actor=user, target_type="user", target_id=user.id)
    return {"ok": True}
