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


def create_token(user: User, *, mfa: bool = False, source: str = "local") -> str:
    """iat = Zeitpunkt der Anmeldung (für „vor dem Genehmigen neu anmelden“), mfa = zweiter Faktor erfolgt."""
    now = utcnow()
    payload = {"sub": user.id, "iat": int(now.timestamp()), "exp": now + timedelta(hours=config.JWT_HOURS),
               "mfa": mfa, "src": source}
    return jwt.encode(payload, config.JWT_SECRET, algorithm="HS256")


def create_purpose_token(user: User, purpose: str, minutes: int = 5) -> str:
    """Kurzlebiges Token für Zwischenschritte (z. B. Passwort ok, TOTP-Code noch offen)."""
    payload = {"sub": user.id, "purpose": purpose, "exp": utcnow() + timedelta(minutes=minutes)}
    return jwt.encode(payload, config.JWT_SECRET, algorithm="HS256")


def read_purpose_token(token: str, purpose: str) -> str:
    try:
        payload = jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "Anmeldung abgelaufen – bitte erneut anmelden")
    if payload.get("purpose") != purpose:
        raise HTTPException(401, "Ungültiges Token")
    return payload["sub"]


# Solange der Pflicht-zweite-Faktor fehlt, sind nur diese Pfade erreichbar
_MFA_SETUP_PATHS = ("/api/auth/me", "/api/auth/totp/", "/api/auth/password")


def mfa_satisfied(db: DbSession, claims: dict) -> bool:
    from . import settings
    return bool(claims.get("mfa")) or (claims.get("src") == "oidc" and settings.get(db, "oidc_counts_as_mfa"))


def get_current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: DbSession = Depends(get_db),
) -> User:
    if not creds:
        raise HTTPException(401, "Nicht angemeldet")
    try:
        payload = jwt.decode(creds.credentials, config.JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "Sitzung abgelaufen – bitte neu anmelden")
    if payload.get("purpose"):
        raise HTTPException(401, "Ungültiges Token")
    user = db.get(User, payload.get("sub"))
    if not user or not user.active:
        raise HTTPException(401, "Benutzer unbekannt oder deaktiviert")
    request.state.claims = payload
    from . import mfa  # spät importieren (mfa → permissions → security)
    if (mfa.required(db, user) and not mfa_satisfied(db, payload)
            and not request.url.path.startswith(_MFA_SETUP_PATHS)):
        raise HTTPException(403, {"code": "mfa_setup_required",
                                  "message": "Bitte zuerst die Zwei-Faktor-Anmeldung einrichten (Profil)"})
    return user


def require_recent_auth(request: Request, db: DbSession) -> None:
    """Vor sensiblen Aktionen (Genehmigen): Anmeldung darf nicht länger als reauth_minutes zurückliegen."""
    from . import settings
    minutes = int(settings.get(db, "reauth_minutes"))
    claims = getattr(request.state, "claims", {}) or {}
    if minutes and utcnow().timestamp() - int(claims.get("iat") or 0) > minutes * 60:
        raise HTTPException(403, {"code": "reauth_required",
                                  "message": f"Bitte erneut anmelden – die Anmeldung liegt mehr als {minutes} Minuten zurück"})


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""
