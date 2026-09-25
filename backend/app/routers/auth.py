from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .. import config, permissions
from ..audit import audit
from ..db import get_db
from ..models import User, utcnow
from ..security import client_ip, create_token, get_current_user, hash_password, verify_password
from ..serializers import user_out

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Fehlversuche je Benutzername: (Anzahl, gesperrt_bis)
_failures: dict[str, tuple[int, object]] = {}


class LoginIn(BaseModel):
    username: str
    password: str


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10)


def me_out(db: DbSession, user: User) -> dict:
    return {**user_out(user), "permissions": permissions.effective(db, user)}


@router.post("/login")
def login(body: LoginIn, request: Request, db: DbSession = Depends(get_db)):
    ip = client_ip(request)
    name = body.username.strip().lower()
    count, locked_until = _failures.get(name, (0, None))
    if locked_until and locked_until > utcnow():
        raise HTTPException(429, "Zu viele Fehlversuche – bitte später erneut versuchen")
    user = db.execute(select(User).where(User.username == name)).scalar_one_or_none()
    if not user or not user.active or not verify_password(body.password, user.password_hash):
        count += 1
        lock = utcnow() + timedelta(minutes=config.LOGIN_LOCK_MINUTES) if count >= config.LOGIN_MAX_FAILURES else None
        _failures[name] = (0 if lock else count, lock)
        audit(db, "auth.login_failed", actor_name=name, ip=ip, details={"locked": bool(lock)})
        raise HTTPException(401, "Benutzername oder Passwort falsch")
    _failures.pop(name, None)
    user.last_login_at = utcnow()
    audit(db, "auth.login", actor=user, ip=ip)
    return {"token": create_token(user), "user": me_out(db, user)}


@router.get("/me")
def me(user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    return me_out(db, user)


@router.post("/password")
def change_password(body: PasswordChangeIn, request: Request, user: User = Depends(get_current_user),
                    db: DbSession = Depends(get_db)):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "Aktuelles Passwort ist falsch")
    user.password_hash = hash_password(body.new_password)
    audit(db, "auth.password_changed", actor=user, target_type="user", target_id=user.id, ip=client_ip(request))
    return {"ok": True}
