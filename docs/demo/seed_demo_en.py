"""Demo-Daten: fiktive Benutzer/Firewalls auf der Sophos-Attrappe, 2 Genehmigungen, etwas Historie."""
import time, httpx
from fastapi.testclient import TestClient
from app.main import app
httpx.post("http://sophos-mock:8000/mock/reset")
PW = "Demo-Passwort-2026"
with TestClient(app) as c:
    def login(u, p=PW):
        return {"Authorization": "Bearer " + c.post("/api/auth/login", json={"username": u, "password": p}).json()["token"]}
    A = login("admin", "admin-password-123")
    roles = {r["name"]: r["id"] for r in c.get("/api/roles", headers=A).json()}
    for u, dn, role in [("m.berger", "Martina Berger", "Firewall-Administrator"), ("s.keller", "Stefan Keller", "Approver"),
                        ("t.nguyen", "Thu Nguyen", "Approver"), ("a.wolf", "Andrea Wolf", "Auditor")]:
        r = c.post("/api/users", headers=A, json={"username": u, "display_name": dn, "email": f"{u}@example.com", "password": PW,
                                                   "assignments": [{"role_id": roles[role]}]})
        assert r.status_code in (200, 201), r.text
    c.put("/api/settings", headers=A, json={"required_approvals": 2, "auto_deploy": False, "require_ticket": True, "language": "en"})
    fws = {}
    for name, serial in [("FW-Zentrale", "X21002ZENTRALE1"), ("FW-Hamburg", "X11600HAMBURG01")]:
        fw = c.post("/api/firewalls", headers=A, json={"name": name, "connector": "rest", "api_url": f"http://sophos-mock:8000/fw/{serial}",
                                                         "api_password": "sfos_mock_key", "verify_tls": False}).json()
        c.post(f"/api/firewalls/{fw['id']}/sync", headers=A)
        fws[name] = fw["id"]
    M, K, N = login("m.berger"), login("s.keller"), login("t.nguyen")
    fid = fws["FW-Zentrale"]
    # 1) ausgerollter Antrag
    op = {"entity": "addressesIpv4", "action": "add", "name": "NTP-Server",
          "data": {"name": "NTP-Server", "description": "Time server data centre", "type": "ipv4Address", "ipv4Address": "10.10.5.20"}}
    d = c.post(f"/api/firewalls/{fid}/draft/operations", headers=M, json=op).json()
    cid = d["draft"]["id"]
    print(c.post(f"/api/changes/{cid}/submit", headers=M, json={"title": "Add time server in data centre", "justification": "New NTP server for the branch offices.", "ticket_ref": "CHG-4711"}).status_code)
    for H, cm in [(K, "Looks good, IP verified."), (N, "")]:
        print(c.post(f"/api/changes/{cid}/decision", headers=H, json={"decision": "approve", "comment": cm}).status_code)
    print(c.post(f"/api/changes/{cid}/deploy", headers=M).status_code)
    for _ in range(30):
        st = c.get(f"/api/changes/{cid}", headers=M).json()["status"]
        if st not in ("approved", "deploying"): break
        time.sleep(0.5)
    print("deploy", st)
    # 2) abgelehnter Antrag
    op = {"entity": "addressesIpv4", "action": "add", "name": "Any-Temp",
          "data": {"name": "Any-Temp", "description": "", "type": "ipv4Network", "ipv4NetworkAddress": "0.0.0.0", "cidr": 0}}
    d = c.post(f"/api/firewalls/{fid}/draft/operations", headers=M, json=op).json()
    cid = d["draft"]["id"]
    c.post(f"/api/changes/{cid}/submit", headers=M, json={"title": "Test network for contractor", "justification": "Short-term access.", "ticket_ref": "CHG-4720"})
    print(c.post(f"/api/changes/{cid}/decision", headers=K, json={"decision": "reject", "comment": "0.0.0.0/0 is far too broad – please request a specific network."}).status_code)
    print(fws)
