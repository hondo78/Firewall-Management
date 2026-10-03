"""Demo-Daten für die Aufnahme: fiktive Benutzer/Firewalls auf der Sophos-Attrappe, 2 Genehmigungen, etwas Historie.

Aufruf im Demo-Backend-Container (frische SQLite-Datenbank):  python seed_demo.py --lang en|de
Bricht mit klarer Meldung ab, wenn die Datenbank schon befüllt ist oder die Attrappe nicht antwortet.
"""
import argparse
import sys
import time

import httpx
from fastapi.testclient import TestClient

from app.main import app

TEXT = {
    "de": {"ntp_desc": "Zeitserver RZ", "t1": "Zeitserver im RZ anlegen", "j1": "Neuer NTP-Server für die Filialen.",
           "c1": "Passt, IP geprüft.", "t2": "Testnetz für Dienstleister", "j2": "Kurzfristiger Zugang.",
           "reject": "0.0.0.0/0 ist zu weit gefasst – bitte konkretes Netz beantragen."},
    "en": {"ntp_desc": "Time server data centre", "t1": "Add time server in data centre", "j1": "New NTP server for the branch offices.",
           "c1": "Looks good, IP verified.", "t2": "Test network for contractor", "j2": "Short-term access.",
           "reject": "0.0.0.0/0 is far too broad – please request a specific network."},
}
PW = "Demo-Passwort-2026"
MOCK = "http://sophos-mock:8000"

lang = argparse.ArgumentParser()
lang.add_argument("--lang", choices=sorted(TEXT), default="en")
LANG = lang.parse_args().lang
T = TEXT[LANG]


def fail(msg: str):
    sys.exit(f"seed_demo: {msg}")


# Die Attrappe braucht nach dem Start ein paar Sekunden
for _ in range(30):
    try:
        httpx.post(f"{MOCK}/mock/reset", timeout=3).raise_for_status()
        break
    except httpx.HTTPError:
        time.sleep(1)
else:
    fail("Sophos-Attrappe nicht erreichbar – COMPOSE_PROFILES=mock docker compose up -d sophos-mock")

with TestClient(app) as c:
    def call(method, path, headers, ok=(200, 201), **kw):
        r = c.request(method, path, headers=headers, **kw)
        if r.status_code not in ok:
            fail(f"{method} {path} → HTTP {r.status_code}: {r.text[:300]}")
        return r.json() if r.content else None

    def login(u, p=PW):
        return {"Authorization": "Bearer " + call("POST", "/api/auth/login", {}, json={"username": u, "password": p})["token"]}

    A = login("admin", "admin-password-123")
    if any(u["username"] == "m.berger" for u in call("GET", "/api/users", A)):
        fail("Datenbank ist schon befüllt – Demo-Container neu anlegen (frische SQLite-Datenbank)")
    roles = {r["name"]: r["id"] for r in call("GET", "/api/roles", A)}
    for u, dn, role in [("m.berger", "Martina Berger", "Firewall-Administrator"), ("s.keller", "Stefan Keller", "Approver"),
                        ("t.nguyen", "Thu Nguyen", "Approver"), ("a.wolf", "Andrea Wolf", "Auditor")]:
        call("POST", "/api/users", A, json={"username": u, "display_name": dn, "email": f"{u}@example.com", "password": PW,
                                            "assignments": [{"role_id": roles[role]}]})
    call("PUT", "/api/settings", A, json={"required_approvals": 2, "auto_deploy": False, "require_ticket": True, "language": LANG})
    fws = {}
    for name, serial in [("FW-Zentrale", "X21002ZENTRALE1"), ("FW-Hamburg", "X11600HAMBURG01")]:
        fw = call("POST", "/api/firewalls", A, json={"name": name, "connector": "rest", "api_url": f"{MOCK}/fw/{serial}",
                                                      "api_password": "sfos_mock_key", "verify_tls": False})
        call("POST", f"/api/firewalls/{fw['id']}/sync", A)
        fws[name] = fw["id"]
    M, K, N = login("m.berger"), login("s.keller"), login("t.nguyen")
    fid = fws["FW-Zentrale"]

    # 1) ausgerollter Antrag (CR-0001)
    op = {"entity": "addressesIpv4", "action": "add", "name": "NTP-Server",
          "data": {"name": "NTP-Server", "description": T["ntp_desc"], "type": "ipv4Address", "ipv4Address": "10.10.5.20"}}
    cid = call("POST", f"/api/firewalls/{fid}/draft/operations", M, json=op)["draft"]["id"]
    call("POST", f"/api/changes/{cid}/submit", M, json={"title": T["t1"], "justification": T["j1"], "ticket_ref": "CHG-4711"})
    for H, comment in [(K, T["c1"]), (N, "")]:
        call("POST", f"/api/changes/{cid}/decision", H, json={"decision": "approve", "comment": comment})
    call("POST", f"/api/changes/{cid}/deploy", M)
    for _ in range(60):
        status = call("GET", f"/api/changes/{cid}", M)["status"]
        if status not in ("approved", "deploying"):
            break
        time.sleep(0.5)
    if status != "deployed":
        fail(f"CR-0001 nicht ausgerollt (Status {status})")

    # 2) abgelehnter Antrag (CR-0002)
    op = {"entity": "addressesIpv4", "action": "add", "name": "Any-Temp",
          "data": {"name": "Any-Temp", "description": "", "type": "ipv4Network", "ipv4NetworkAddress": "0.0.0.0", "cidr": 0}}
    cid = call("POST", f"/api/firewalls/{fid}/draft/operations", M, json=op)["draft"]["id"]
    call("POST", f"/api/changes/{cid}/submit", M, json={"title": T["t2"], "justification": T["j2"], "ticket_ref": "CHG-4720"})
    call("POST", f"/api/changes/{cid}/decision", K, json={"decision": "reject", "comment": T["reject"]})
    print(f"seed_demo ({LANG}): fertig – Firewalls {fws}")
