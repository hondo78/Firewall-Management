"""Zwei-Faktor (TOTP), Pflicht je Rolle, Neu-Anmeldung vor Genehmigung und SSO (OIDC mit Attrappe)."""
import base64
import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app import mfa, oidc

from .test_workflow import deploy_sync, login, make_user, setup_firewall, submit_new_rule


def totp_now(secret: str) -> str:
    return mfa._code(secret, int(time.time() // 30))


def enable_totp(client, headers) -> str:
    setup = client.post("/api/auth/totp/setup", headers=headers).json()
    assert setup["uri"].startswith("otpauth://totp/") and "<svg" in setup["qr_svg"]
    assert client.post("/api/auth/totp/enable", headers=headers, json={"code": "000000"}).status_code == 400
    r = client.post("/api/auth/totp/enable", headers=headers, json={"code": totp_now(setup["secret"])})
    assert r.status_code == 200
    return setup["secret"]


def test_totp_rfc6238_vector():
    # RFC 6238 Anhang B (SHA-1, Geheimnis „12345678901234567890“) – letzte 6 Stellen
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert mfa._code(secret, 59 // 30) == "287082"
    assert mfa._code(secret, 1111111109 // 30) == "081804"


def test_totp_login_flow(client, admin):
    op = make_user(client, admin, "operator", [("Operator", None)])
    secret = enable_totp(client, op)
    r = client.post("/api/auth/login", json={"username": "operator", "password": "secret-password-1"})
    assert r.json()["mfa_required"] is True and "token" not in r.json()
    tok = r.json()["mfa_token"]
    assert client.post("/api/auth/login/totp", json={"mfa_token": tok, "code": "123456"}).status_code == 401
    # das Zwischen-Token taugt nicht als Sitzung
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    r = client.post("/api/auth/login/totp", json={"mfa_token": tok, "code": totp_now(secret)})
    assert r.status_code == 200 and r.json()["user"]["totp_enabled"]


def test_mfa_required_for_privileged_blocks_until_setup(client, admin):
    ap = make_user(client, admin, "approver", [("Approver", None)])
    viewer = make_user(client, admin, "viewer", [("Betrachter", None)])
    client.put("/api/settings", headers=admin, json={"require_mfa": "privileged"})
    # auch der Superadmin ist ab jetzt gesperrt, bis er TOTP eingerichtet hat
    assert client.get("/api/firewalls", headers=admin).status_code == 403
    assert client.get("/api/firewalls", headers=viewer).status_code == 200        # nicht privilegiert
    r = client.get("/api/firewalls", headers=ap)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "mfa_setup_required"
    assert client.get("/api/auth/me", headers=ap).json()["mfa_setup_required"] is True
    setup = client.post("/api/auth/totp/setup", headers=ap).json()
    new = client.post("/api/auth/totp/enable", headers=ap, json={"code": totp_now(setup["secret"])}).json()
    assert client.get("/api/firewalls", headers={"Authorization": f"Bearer {new['token']}"}).status_code == 200
    # Admin (nach eigener Einrichtung) setzt zurück → wieder gesperrt bis zur Neueinrichtung
    admin_token = client.post("/api/auth/totp/enable", headers=admin, json={
        "code": totp_now(client.post("/api/auth/totp/setup", headers=admin).json()["secret"])}).json()["token"]
    uid = client.get("/api/auth/me", headers=ap).json()["id"]
    assert client.post(f"/api/auth/users/{uid}/totp/reset",
                       headers={"Authorization": f"Bearer {admin_token}"}).status_code == 200
    r = client.post("/api/auth/login", json={"username": "approver", "password": "secret-password-1"})
    assert "token" in r.json() and r.json()["user"]["mfa_setup_required"] is True


def test_reauth_before_approval(client, admin, fake, monkeypatch):
    client.put("/api/settings", headers=admin, json={"reauth_minutes": 5})
    fw_id = setup_firewall(client, admin)
    op = make_user(client, admin, "operator", [("Operator", None)])
    ap = make_user(client, admin, "approver", [("Approver", None)])
    cid = submit_new_rule(client, fw_id, op)
    # Sitzung des Approvers ist 10 Minuten alt
    claims = jwt.decode(ap["Authorization"].split()[1], "test", algorithms=["HS256"])
    old = jwt.encode({**claims, "iat": int(time.time()) - 600}, "test", algorithm="HS256")
    ap = {"Authorization": f"Bearer {old}"}
    r = client.post(f"/api/changes/{cid}/decision", headers=ap, json={"decision": "approve"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "reauth_required"
    assert client.post("/api/auth/reauth", headers=ap, json={"password": "falsch"}).status_code == 400
    new = client.post("/api/auth/reauth", headers=ap, json={"password": "secret-password-1"}).json()["token"]
    r = client.post(f"/api/changes/{cid}/decision", headers={"Authorization": f"Bearer {new}"},
                    json={"decision": "approve"})
    assert r.status_code == 200 and r.json()["status"] == "approved"


# --- OIDC mit Attrappe ---------------------------------------------------------------------------------------

ISSUER = "https://idp.test"


@pytest.fixture()
def idp(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="k1", use="sig", alg="RS256")
    state = {"claims": {}, "codes": {}}

    def handler(req: httpx.Request):
        if req.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/auth",
                                             "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/jwks"})
        if req.url.path == "/jwks":
            return httpx.Response(200, json={"keys": [jwk]})
        if req.url.path == "/token":
            form = parse_qs(req.content.decode())
            nonce = state["codes"].pop(form["code"][0])
            claims = {"iss": ISSUER, "aud": "fwm", "exp": int(time.time()) + 300, "iat": int(time.time()),
                      "nonce": nonce, **state["claims"]}
            token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})
            return httpx.Response(200, json={"id_token": token, "access_token": "at"})
        return httpx.Response(404)
    monkeypatch.setattr(oidc, "_http", httpx.Client(transport=httpx.MockTransport(handler)))
    oidc._discovery.clear()
    return state


def sso_login(client, idp, claims):
    """Browser-Ablauf nachstellen: /login → IdP (Code) → /callback → Einmal-Code → Token."""
    idp["claims"] = claims
    r = client.get("/api/auth/oidc/login", follow_redirects=False)
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["code_challenge_method"] == ["S256"]
    idp["codes"]["c1"] = q["nonce"][0]
    r = client.get("/api/auth/oidc/callback", params={"code": "c1", "state": q["state"][0]}, follow_redirects=False)
    loc = parse_qs(urlparse(r.headers["location"]).query)
    return loc


def test_oidc_login_with_role_mapping(client, admin, idp):
    roles = {r["name"]: r["id"] for r in client.get("/api/roles", headers=admin).json()}
    client.put("/api/notifications/config", headers=admin, json={"public_url": "http://fwm.test"})
    cfg = client.put("/api/auth/oidc/config", headers=admin, json={
        "enabled": True, "issuer": ISSUER, "client_id": "fwm", "client_secret": "s3cret",
        "mappings": [{"claim": "fw-approver", "role_id": roles["Approver"]}]}).json()
    assert cfg["client_secret_set"] and cfg["redirect_uri"] == "http://fwm.test/api/auth/oidc/callback"
    assert client.get("/api/auth/oidc/info").json()["enabled"] is True
    loc = sso_login(client, idp, {"sub": "u-1", "preferred_username": "Erika", "email": "erika@test",
                                  "groups": ["fw-approver", "andere"]})
    assert "oidc" in loc, loc
    r = client.post("/api/auth/oidc/exchange", json={"code": loc["oidc"][0]})
    assert r.status_code == 200
    user = r.json()["user"]
    assert user["username"] == "erika" and user["auth_source"] == "oidc"
    assert [a["role"] for a in user["assignments"]] == ["Approver"]
    # Einmal-Code nur einmal verwendbar, Passwort-Login für SSO-Benutzer gesperrt
    assert client.post("/api/auth/oidc/exchange", json={"code": loc["oidc"][0]}).status_code == 401
    # Gruppe entzogen → Rolle beim nächsten Login weg
    loc = sso_login(client, idp, {"sub": "u-1", "preferred_username": "erika", "groups": []})
    user = client.post("/api/auth/oidc/exchange", json={"code": loc["oidc"][0]}).json()["user"]
    assert user["assignments"] == []


def test_oidc_rejects_bad_nonce_and_local_admin_takeover(client, admin, idp):
    client.put("/api/notifications/config", headers=admin, json={"public_url": "http://fwm.test"})
    client.put("/api/auth/oidc/config", headers=admin, json={"enabled": True, "issuer": ISSUER, "client_id": "fwm"})
    # IdP liefert Konto „admin“ → darf den lokalen Superadmin nicht übernehmen
    loc = sso_login(client, idp, {"sub": "evil", "preferred_username": "admin"})
    assert "oidc_error" in loc and "vorbehalten" in loc["oidc_error"][0]
    # manipulierter Ablauf: falscher state
    r = client.get("/api/auth/oidc/callback", params={"code": "x", "state": "falsch"}, follow_redirects=False)
    assert "oidc_error" in r.headers["location"]
