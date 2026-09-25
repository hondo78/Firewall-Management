from datetime import timedelta

import segno
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .. import config, crypto, mfa, oidc, permissions
from ..audit import audit
from ..db import get_db
from ..models import User, utcnow
from ..notify import config as ncfg
from ..permissions import require_global
from ..security import (client_ip, create_purpose_token, create_token, get_current_user, hash_password,
                        mfa_satisfied, read_purpose_token, verify_password)
from ..serializers import user_out

router = APIRouter(prefix="/api/auth", tags=["auth"])
admin_only = require_global("admin")

# Fehlversuche je Benutzername: (Anzahl, gesperrt_bis)
_failures: dict[str, tuple[int, object]] = {}


class LoginIn(BaseModel):
    username: str
    password: str


class TotpLoginIn(BaseModel):
    mfa_token: str
    code: str


class CodeIn(BaseModel):
    code: str


class ReauthIn(BaseModel):
    password: str
    code: str = ""


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10)


def me_out(db: DbSession, user: User, claims: dict | None = None) -> dict:
    required = mfa.required(db, user)
    return {**user_out(user), "permissions": permissions.effective(db, user),
            "totp_enabled": user.totp_enabled, "auth_source": user.auth_source, "mfa_required": required,
            "mfa_setup_required": required and not user.totp_enabled and not mfa_satisfied(db, claims or {})}


def _locked(name: str) -> None:
    _count, locked_until = _failures.get(name, (0, None))
    if locked_until and locked_until > utcnow():
        raise HTTPException(429, "Zu viele Fehlversuche – bitte später erneut versuchen")


def _fail(db: DbSession, name: str, ip: str, reason: str) -> None:
    count, _ = _failures.get(name, (0, None))
    count += 1
    lock = utcnow() + timedelta(minutes=config.LOGIN_LOCK_MINUTES) if count >= config.LOGIN_MAX_FAILURES else None
    _failures[name] = (0 if lock else count, lock)
    audit(db, "auth.login_failed", actor_name=name, ip=ip, details={"locked": bool(lock), "reason": reason})


def _success(db: DbSession, user: User, ip: str, *, mfa_ok: bool, source: str) -> dict:
    _failures.pop(user.username, None)
    user.last_login_at = utcnow()
    audit(db, "auth.login", actor=user, ip=ip, details={"mfa": mfa_ok, "source": source})
    claims = {"mfa": mfa_ok, "src": source}
    return {"token": create_token(user, mfa=mfa_ok, source=source), "user": me_out(db, user, claims)}


@router.post("/login")
def login(body: LoginIn, request: Request, db: DbSession = Depends(get_db)):
    ip = client_ip(request)
    name = body.username.strip().lower()
    _locked(name)
    user = db.execute(select(User).where(User.username == name)).scalar_one_or_none()
    if (not user or not user.active or user.auth_source != "local"
            or not verify_password(body.password, user.password_hash)):
        _fail(db, name, ip, "password")
        raise HTTPException(401, "Benutzername oder Passwort falsch")
    if user.totp_enabled:
        # Passwort stimmt – zweiter Schritt: Code aus der Authenticator-App
        return {"mfa_required": True, "mfa_token": create_purpose_token(user, "login_totp")}
    return _success(db, user, ip, mfa_ok=False, source="local")


@router.post("/login/totp")
def login_totp(body: TotpLoginIn, request: Request, db: DbSession = Depends(get_db)):
    ip = client_ip(request)
    user = db.get(User, read_purpose_token(body.mfa_token, "login_totp"))
    if not user or not user.active:
        raise HTTPException(401, "Benutzer unbekannt oder deaktiviert")
    _locked(user.username)
    if not mfa.check_user_code(user, body.code):
        _fail(db, user.username, ip, "totp")
        raise HTTPException(401, "Code falsch oder abgelaufen")
    return _success(db, user, ip, mfa_ok=True, source="local")


@router.get("/me")
def me(request: Request, user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    return me_out(db, user, getattr(request.state, "claims", {}))


@router.post("/password")
def change_password(body: PasswordChangeIn, request: Request, user: User = Depends(get_current_user),
                    db: DbSession = Depends(get_db)):
    if user.auth_source != "local":
        raise HTTPException(400, "SSO-Benutzer ändern ihr Passwort beim Identity Provider")
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "Aktuelles Passwort ist falsch")
    user.password_hash = hash_password(body.new_password)
    audit(db, "auth.password_changed", actor=user, target_type="user", target_id=user.id, ip=client_ip(request))
    return {"ok": True}


@router.post("/reauth")
def reauth(body: ReauthIn, request: Request, user: User = Depends(get_current_user),
           db: DbSession = Depends(get_db)):
    """Erneute Anmeldung (vor dem Genehmigen) – liefert ein neues Token mit aktueller Anmeldezeit."""
    ip = client_ip(request)
    if user.auth_source != "local":
        raise HTTPException(400, "Bitte über SSO neu anmelden")
    _locked(user.username)
    if not verify_password(body.password, user.password_hash):
        _fail(db, user.username, ip, "reauth_password")
        raise HTTPException(400, "Passwort falsch")
    if user.totp_enabled and not mfa.check_user_code(user, body.code):
        _fail(db, user.username, ip, "reauth_totp")
        raise HTTPException(400, "Code falsch oder abgelaufen")
    audit(db, "auth.reauth", actor=user, ip=ip)
    return {"token": create_token(user, mfa=user.totp_enabled, source="local")}


# --- Zwei-Faktor (TOTP) --------------------------------------------------------------------------------------

@router.post("/totp/setup")
def totp_setup(user: User = Depends(get_current_user), db: DbSession = Depends(get_db)):
    """Neues Geheimnis erzeugen (noch nicht aktiv) – QR-Code für die Authenticator-App."""
    if user.auth_source != "local":
        raise HTTPException(400, "SSO-Benutzer nutzen den zweiten Faktor ihres Identity Providers")
    secret = mfa.new_secret()
    user.totp_pending_enc = crypto.encrypt(secret, f"totp-pending:{user.id}")
    db.commit()
    uri = mfa.provisioning_uri(secret, user.username)
    return {"secret": secret, "uri": uri, "qr_svg": segno.make(uri, error="m").svg_inline(scale=5, border=2)}


@router.post("/totp/enable")
def totp_enable(body: CodeIn, request: Request, user: User = Depends(get_current_user),
                db: DbSession = Depends(get_db)):
    if not user.totp_pending_enc:
        raise HTTPException(400, "Bitte zuerst die Einrichtung starten")
    secret = crypto.decrypt(user.totp_pending_enc, f"totp-pending:{user.id}")
    if not mfa.verify(secret, body.code):
        raise HTTPException(400, "Code falsch – Uhrzeit des Telefons prüfen und erneut versuchen")
    user.totp_secret_enc = crypto.encrypt(secret, f"totp:{user.id}")
    user.totp_pending_enc = ""
    user.totp_enabled = True
    audit(db, "auth.totp_enabled", actor=user, target_type="user", target_id=user.id, ip=client_ip(request))
    return {"token": create_token(user, mfa=True, source="local"), "user": me_out(db, user, {"mfa": True})}


@router.post("/totp/disable")
def totp_disable(body: ReauthIn, request: Request, user: User = Depends(get_current_user),
                 db: DbSession = Depends(get_db)):
    if mfa.required(db, user):
        raise HTTPException(409, "Zwei-Faktor ist für Ihre Rolle verpflichtend")
    if not verify_password(body.password, user.password_hash) or not mfa.check_user_code(user, body.code):
        raise HTTPException(400, "Passwort oder Code falsch")
    user.totp_enabled, user.totp_secret_enc = False, ""
    audit(db, "auth.totp_disabled", actor=user, target_type="user", target_id=user.id, ip=client_ip(request))
    return {"ok": True}


@router.post("/users/{user_id}/totp/reset")
def totp_reset(user_id: str, request: Request, actor: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    """Admin: zweiten Faktor zurücksetzen (z. B. Telefon verloren) – der Benutzer richtet ihn neu ein."""
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "Benutzer nicht gefunden")
    u.totp_enabled, u.totp_secret_enc, u.totp_pending_enc = False, "", ""
    audit(db, "auth.totp_reset", actor=actor, target_type="user", target_id=u.id, ip=client_ip(request),
          details={"username": u.username})
    return {"ok": True}


# --- Single Sign-On (OIDC) -----------------------------------------------------------------------------------

def _redirect_uri(db: DbSession) -> tuple[str, str]:
    base = ncfg.load(db)["public_url"]
    if not base:
        raise HTTPException(400, "Für SSO bitte unter Administration › Benachrichtigungen die Adresse der Oberfläche eintragen")
    return base, f"{base}/api/auth/oidc/callback"


@router.get("/oidc/info")
def oidc_info(db: DbSession = Depends(get_db)):
    """Für die Login-Seite (ohne Anmeldung)."""
    cfg = oidc.load(db)
    return {"enabled": bool(cfg["enabled"] and cfg["issuer"] and cfg["client_id"]), "label": cfg["button_label"]}


@router.get("/oidc/login")
def oidc_login(db: DbSession = Depends(get_db)):
    _, redirect_uri = _redirect_uri(db)
    return RedirectResponse(oidc.start(oidc.load(db), redirect_uri), status_code=302)


@router.get("/oidc/callback")
def oidc_callback(request: Request, code: str = "", state: str = "", error: str = "",
                  error_description: str = "", db: DbSession = Depends(get_db)):
    base, redirect_uri = _redirect_uri(db)
    from urllib.parse import quote
    if error:
        return RedirectResponse(f"{base}/login?oidc_error={quote(error_description or error)}", status_code=302)
    try:
        cfg = oidc.load(db)
        claims = oidc.finish(cfg, code, state, redirect_uri)
        user, info = oidc.map_user(db, cfg, claims)
        audit(db, "auth.login", actor=user, ip=client_ip(request),
              details={"source": "oidc", "created": info["created"], "roles_changed": info["roles_changed"],
                       "roles": info["roles"]})
        user.last_login_at = utcnow()
        db.commit()
        return RedirectResponse(f"{base}/login?oidc={oidc.issue_exchange_code(user)}", status_code=302)
    except HTTPException as e:
        db.rollback()
        audit(db, "auth.login_failed", actor_name="oidc", ip=client_ip(request),
              details={"source": "oidc", "reason": str(e.detail)})
        return RedirectResponse(f"{base}/login?oidc_error={quote(str(e.detail))}", status_code=302)


class ExchangeIn(BaseModel):
    code: str


@router.post("/oidc/exchange")
def oidc_exchange(body: ExchangeIn, db: DbSession = Depends(get_db)):
    user = db.get(User, oidc.redeem_exchange_code(body.code))
    if not user or not user.active:
        raise HTTPException(401, "Benutzer unbekannt oder deaktiviert")
    claims = {"mfa": False, "src": "oidc"}
    return {"token": create_token(user, mfa=False, source="oidc"), "user": me_out(db, user, claims)}


@router.get("/oidc/config")
def get_oidc_config(_: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    base = ncfg.load(db)["public_url"]
    return {**oidc.public_view(oidc.load(db)),
            "redirect_uri": f"{base}/api/auth/oidc/callback" if base else ""}


@router.put("/oidc/config")
def put_oidc_config(body: dict, request: Request, actor: User = Depends(admin_only), db: DbSession = Depends(get_db)):
    changed = oidc.save(db, body)
    if changed:
        audit(db, "oidc.updated", actor=actor, ip=client_ip(request), details={"changed": changed})
    else:
        db.commit()
    return get_oidc_config(actor, db)
