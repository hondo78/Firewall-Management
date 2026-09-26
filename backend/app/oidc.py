"""Single Sign-On per OpenID Connect (Authorization Code Flow mit PKCE).

Ablauf: /api/auth/oidc/login → Identity Provider → /api/auth/oidc/callback (Code gegen Tokens tauschen, ID-Token
per JWKS prüfen) → Benutzer zuordnen/anlegen, Rollen aus Gruppen-Claims → Einmal-Code → Frontend tauscht ihn
gegen das eigene Token (/api/auth/oidc/exchange). So landet kein Token in einer URL.
Konfiguration in settings["oidc"], Client-Secret verschlüsselt.
"""
import base64
import copy
import hashlib
import secrets
import time
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from . import crypto
from .models import FirewallGroup, Role, RoleAssignment, Setting, User
from .security import hash_password
from .i18n import tr

KEY = "oidc"
DEFAULTS = {
    "enabled": False, "issuer": "", "client_id": "", "client_secret": "", "scopes": "openid profile email",
    "button_label": "Mit SSO anmelden", "username_claim": "preferred_username", "groups_claim": "groups",
    # Unbekannte Benutzer beim ersten SSO-Login anlegen (sonst nur vorhandene zuordnen)
    "auto_create": True,
    # Rollen bei jedem Login aus den Gruppen-Claims übernehmen (ersetzt vorhandene Zuweisungen)
    "sync_roles": True,
    # [{"claim": "fw-approver", "role_id": "…", "group_id": null | "…"}]
    "mappings": [],
}
_http = httpx.Client(timeout=15)
_discovery: dict[str, tuple[dict, float]] = {}
_pending: dict[str, dict] = {}                    # state → {nonce, verifier, created}
_exchange: dict[str, tuple[str, str, float]] = {}  # Einmal-Code → (user_id, source, gültig bis)


# --- Konfiguration -------------------------------------------------------------------------------------------

def load(db: DbSession) -> dict:
    row = db.get(Setting, KEY)
    cfg = copy.deepcopy(DEFAULTS)
    cfg.update(row.value if row else {})
    enc = cfg.pop("client_secret_enc", "")
    cfg["client_secret"] = crypto.decrypt(enc, "oidc:client_secret") if enc else ""
    cfg["issuer"] = (cfg.get("issuer") or "").rstrip("/")
    return cfg


def public_view(cfg: dict) -> dict:
    out = copy.deepcopy(cfg)
    out["client_secret_set"] = bool(out.pop("client_secret", ""))
    return out


def save(db: DbSession, incoming: dict) -> list[str]:
    row = db.get(Setting, KEY)
    stored = copy.deepcopy(DEFAULTS)
    stored.update(row.value if row else {})
    changed = []
    for k, v in incoming.items():
        if k == "client_secret":
            if v:
                stored["client_secret_enc"] = crypto.encrypt(str(v), "oidc:client_secret")
                changed.append(k)
            continue
        if k == "clear_client_secret" and v:
            stored.pop("client_secret_enc", None)
            changed.append("client_secret")
            continue
        if k in DEFAULTS and stored.get(k) != v:
            if k == "mappings":
                v = [{"claim": str(m.get("claim", "")).strip(), "role_id": m.get("role_id"),
                      "group_id": m.get("group_id") or None} for m in v if m.get("claim") and m.get("role_id")]
            stored[k] = v
            changed.append(k)
    stored.pop("client_secret", None)
    if row is None:
        db.add(Setting(key=KEY, value=stored))
    else:
        row.value = stored
    return changed


# --- Protokoll -----------------------------------------------------------------------------------------------

def discovery(issuer: str) -> dict:
    cached = _discovery.get(issuer)
    if cached and cached[1] > time.time():
        return cached[0]
    try:
        r = _http.get(f"{issuer}/.well-known/openid-configuration")
        r.raise_for_status()
        doc = r.json()
    except (httpx.HTTPError, ValueError) as e:
        raise HTTPException(502, tr('OIDC-Discovery fehlgeschlagen: {0}', e))
    _discovery[issuer] = (doc, time.time() + 3600)
    return doc


def start(cfg: dict, redirect_uri: str) -> str:
    if not (cfg["enabled"] and cfg["issuer"] and cfg["client_id"]):
        raise HTTPException(400, tr('SSO ist nicht eingerichtet'))
    doc = discovery(cfg["issuer"])
    now = time.time()
    for k in [k for k, v in _pending.items() if v["created"] < now - 600]:
        _pending.pop(k, None)
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    _pending[state] = {"nonce": nonce, "verifier": verifier, "created": now}
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return doc["authorization_endpoint"] + "?" + urlencode({
        "response_type": "code", "client_id": cfg["client_id"], "redirect_uri": redirect_uri,
        "scope": cfg["scopes"] or "openid", "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256"})


def finish(cfg: dict, code: str, state: str, redirect_uri: str) -> dict:
    """Code gegen Tokens tauschen, ID-Token prüfen; liefert die Claims (inkl. userinfo)."""
    pending = _pending.pop(state or "", None)
    if not pending or pending["created"] < time.time() - 600:
        raise HTTPException(400, tr('Anmeldung abgelaufen oder ungültig – bitte erneut versuchen'))
    doc = discovery(cfg["issuer"])
    try:
        r = _http.post(doc["token_endpoint"], data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
            "client_id": cfg["client_id"], "client_secret": cfg["client_secret"],
            "code_verifier": pending["verifier"]})
    except httpx.HTTPError as e:
        raise HTTPException(502, tr('Token-Abruf beim Identity Provider fehlgeschlagen: {0}', e))
    if r.status_code != 200:
        raise HTTPException(502, tr('Token-Abruf abgelehnt (HTTP {0}): {1}', r.status_code, r.text[:200]))
    tokens = r.json()
    claims = verify_id_token(cfg, doc, tokens.get("id_token", ""), pending["nonce"])
    if doc.get("userinfo_endpoint") and tokens.get("access_token"):
        try:
            u = _http.get(doc["userinfo_endpoint"], headers={"Authorization": f"Bearer {tokens['access_token']}"})
            if u.status_code == 200 and u.json().get("sub") == claims["sub"]:
                claims = {**u.json(), **claims}
        except (httpx.HTTPError, ValueError):
            pass
    return claims


def verify_id_token(cfg: dict, doc: dict, id_token: str, nonce: str) -> dict:
    if not id_token:
        raise HTTPException(502, tr('Identity Provider hat kein ID-Token geliefert'))
    try:
        header = jwt.get_unverified_header(id_token)
        jwks = _http.get(doc["jwks_uri"]).json()
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
        if key is None and len(jwks.get("keys", [])) == 1:
            key = jwks["keys"][0]
        if key is None:
            raise HTTPException(502, tr('Signaturschlüssel des ID-Tokens nicht gefunden'))
        alg = header.get("alg", "RS256")
        if alg == "none" or alg.startswith("HS"):
            raise HTTPException(502, tr('Unsicherer Signaturalgorithmus im ID-Token'))
        claims = jwt.decode(id_token, jwt.PyJWK.from_dict(key).key, algorithms=[alg], audience=cfg["client_id"],
                            issuer=doc.get("issuer", cfg["issuer"]), leeway=60)
    except (jwt.PyJWTError, httpx.HTTPError, ValueError) as e:
        raise HTTPException(401, tr('ID-Token ungültig: {0}', e))
    if claims.get("nonce") != nonce:
        raise HTTPException(401, tr('ID-Token ungültig: nonce passt nicht'))
    return claims


# --- Benutzer & Rollen ---------------------------------------------------------------------------------------

def _claim_list(claims: dict, name: str) -> list[str]:
    v = claims.get(name) or []
    return [str(x) for x in (v if isinstance(v, list) else [v])]


def map_user(db: DbSession, cfg: dict, claims: dict) -> tuple[User, dict]:
    sub = str(claims.get("sub") or "")
    username = str(claims.get(cfg["username_claim"]) or claims.get("email") or sub).strip().lower()
    if not sub or not username:
        raise HTTPException(401, tr('ID-Token ohne Benutzerkennung'))
    user = db.execute(select(User).where(User.oidc_subject == sub)).scalar()
    created = False
    if user is None:
        user = db.execute(select(User).where(User.username == username)).scalar()
        if user is not None and user.is_superadmin and user.auth_source == "local":
            # Lokaler Notfall-Superadmin wird nie automatisch an ein SSO-Konto gebunden
            raise HTTPException(403, tr('Dieser Benutzername ist dem lokalen Administrator vorbehalten'))
        if user is None:
            if not cfg["auto_create"]:
                raise HTTPException(403, tr('Benutzer „{0}“ ist nicht freigeschaltet', username))
            # Defaults der Spalten greifen erst beim flush → active ausdrücklich setzen
            user = User(username=username, password_hash=hash_password(secrets.token_urlsafe(32)),
                        auth_source="oidc", active=True, is_superadmin=False)
            db.add(user)
            created = True
        user.oidc_subject = sub
    if not user.active:
        raise HTTPException(403, tr('Benutzer ist deaktiviert'))
    user.display_name = str(claims.get("name") or user.display_name or "")
    if claims.get("email"):
        user.email = str(claims["email"])
    db.flush()
    roles_before = sorted(f"{a.role_id}:{a.group_id}" for a in user.assignments)
    if cfg["sync_roles"] and cfg["mappings"]:
        groups = set(_claim_list(claims, cfg["groups_claim"]))
        wanted = {(m["role_id"], m.get("group_id")) for m in cfg["mappings"] if m["claim"] in groups}
        valid_roles = {r.id for r in db.execute(select(Role)).scalars()}
        valid_groups = {g.id for g in db.execute(select(FirewallGroup)).scalars()}
        user.assignments.clear()
        db.flush()
        for role_id, group_id in wanted:
            if role_id in valid_roles and (group_id is None or group_id in valid_groups):
                user.assignments.append(RoleAssignment(role_id=role_id, group_id=group_id))
        db.flush()
    roles_after = sorted(f"{a.role_id}:{a.group_id}" for a in user.assignments)
    return user, {"created": created, "roles_changed": roles_before != roles_after,
                  "roles": [a.role.name if a.role else a.role_id for a in user.assignments]}


def issue_exchange_code(user: User) -> str:
    code = secrets.token_urlsafe(24)
    _exchange[code] = (user.id, "oidc", time.time() + 60)
    return code


def redeem_exchange_code(code: str) -> str:
    entry = _exchange.pop(code or "", None)
    if not entry or entry[2] < time.time():
        raise HTTPException(401, tr('SSO-Anmeldung abgelaufen – bitte erneut versuchen'))
    return entry[0]
