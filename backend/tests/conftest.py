"""Tests laufen gegen SQLite im Speicher; die Firewall wird durch FakeFirewall ersetzt (kein Netzwerk)."""
import base64
import copy
import os

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["FWM_MASTER_KEY"] = base64.b64encode(b"k" * 32).decode()
os.environ["ADMIN_PASSWORD"] = "admin-password-123"
os.environ["DISABLE_WORKER"] = "1"
os.environ["JWT_SECRET"] = "test"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.sophos import connector  # noqa: E402


def rule(name, action="Accept", status="Enable", src="LAN", dst="WAN", services=None):
    pol = {"Action": action, "SourceZones": {"Zone": [src]}, "DestinationZones": {"Zone": [dst]},
           "Schedule": "All The Time"}
    if services:
        pol["Services"] = {"Service": services}
    return {"Name": name, "Description": "", "IPFamily": "IPv4", "Status": status, "PolicyType": "Network",
            "NetworkPolicy": pol}


class FakeFirewall:
    def __init__(self):
        self.config = {
            "Zone": [{"Name": "LAN", "Type": "LAN"}, {"Name": "WAN", "Type": "WAN"}],
            "Services": [{"Name": "HTTPS", "Type": "TCPorUDP"}],
            "IPHost": [{"Name": "Server", "IPFamily": "IPv4", "HostType": "IP", "IPAddress": "10.0.0.1"}],
            "FirewallRule": [rule("Regel-A", services=["HTTPS"]), rule("Regel-B")],
        }
        self.applied: list[list[dict]] = []
        self.fail = None

    def fetch(self, db, fw, log=None):
        return copy.deepcopy(self.config), "2100.1"

    def apply(self, db, fw, ops, log):
        if self.fail:
            raise connector.DeployError(self.fail)
        from app import changes
        self.applied.append(ops)
        self.config = changes.effective_config(self.config, ops)
        log("fake applied")


@pytest.fixture()
def fake(monkeypatch):
    f = FakeFirewall()
    monkeypatch.setattr(connector, "fetch_config", f.fetch)
    monkeypatch.setattr(connector, "apply", f.apply)
    return f


@pytest.fixture()
def client():
    Base.metadata.drop_all(engine)
    with TestClient(app) as c:
        yield c


def login(client, username, password):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


@pytest.fixture()
def admin(client):
    return login(client, "admin", "admin-password-123")
