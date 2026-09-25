from datetime import timedelta

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session as DbSession

from . import config
from .db import get_db
from .models import User, utcnow

_bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


def create_token(user: User) -> str:
    payload = {"sub": user.id, "exp": utcnow() + timedelta(hours=config.JWT_HOURS)}
    return jwt.encode(payload, config.JWT_SECRET, algorithm="HS256")


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: DbSession = Depends(get_db),
) -> User:
    if not creds:
        raise HTTPException(401, "Nicht angemeldet")
    try:
        payload = jwt.decode(creds.credentials, config.JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "Sitzung abgelaufen – bitte neu anmelden")
    user = db.get(User, payload.get("sub"))
    if not user or not user.active:
        raise HTTPException(401, "Benutzer unbekannt oder deaktiviert")
    return user


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""
