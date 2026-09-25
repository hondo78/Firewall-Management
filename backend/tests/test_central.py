"""Central-Client gegen httpx.MockTransport: Pfade laut Spezifikation, Rückfall auf den Leitfaden, S3-Upload."""
import io
import json
import tarfile

import httpx

from app.sophos import central
from app.sophos.central import CentralClient, normalize_status

REGION = "https://api-eu01.test"


def tar_with(xml: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo("Entities.xml")
        info.size = len(xml)
        t.addfile(info, io.BytesIO(xml))
    return buf.getvalue()


def make_client(handler, region=REGION):
    central._CONFIG_PREFIX.clear()
    return CentralClient("https://id.test", "https://api.test", "cid", "secret", "tenant-1", region,
                         transport=httpx.MockTransport(handler))


def token_ok(request):
    return httpx.Response(200, json={"access_token": "t", "expires_in": 3600})


def test_export_uses_spec_path():
    seen = []

    def handler(request: httpx.Request):
        seen.append((request.method, request.url.path))
        if request.url.host == "id.test":
            return token_ok(request)
        assert request.url.host != "s3.test" or "authorization" not in request.headers
        if request.url.path == "/firewall/v1/firewall-config/firewalls/fw1/export":
            return httpx.Response(202, json={"transactionId": "tx1"})
        if request.url.path == "/firewall/v1/firewall-config/firewalls/transactions/tx1":
            return httpx.Response(200, json={"id": "tx1", "status": "finished", "result": "success",
                                             "response": {"url": "https://s3.test/export.tar"}})
        if request.url.host == "s3.test":
            return httpx.Response(200, content=tar_with(b"<Configuration/>"))
        return httpx.Response(404, json={"error": "notFound"})

    data = make_client(handler).export_config("fw1", ["Zone"])
    assert data.startswith(b"Entities.xml")
    assert ("POST", "/firewall/v1/firewall-config/firewalls/fw1/export") in seen


def test_falls_back_to_guide_path_and_remembers():
    calls = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        if request.url.host == "id.test":
            return token_ok(request)
        if request.url.path == "/firewall/v1/firewalls/import":
            return httpx.Response(201, json={"transactionId": "tx", "url": "https://s3.test/up", "method": "PUT"})
        if request.url.host == "s3.test":
            # Pre-signed S3-PUT: weder Central-Header noch eigener Content-Type
            assert "authorization" not in request.headers
            assert "content-type" not in request.headers
            return httpx.Response(200)
        if request.url.path == "/firewall/v1/firewalls/import/tx/upload-complete":
            body = json.loads(request.content)
            assert body["firewallIds"] == ["fw1"] and body["performPartialImport"] is False
            return httpx.Response(202, json={"id": "tx", "status": "started"})
        if request.url.path == "/firewall/v1/firewalls/transactions/tx":
            return httpx.Response(200, json={"id": "tx", "status": "finished", "result": "success",
                                             "response": {"items": [{"firewallId": "fw1", "result": "success"}]}})
        return httpx.Response(404, json={"error": "notFound", "message": "No route"})

    client = make_client(handler, "https://api-legacy.test")
    tx = client.import_config(["fw1"], b"archive")
    assert tx["result"] == "success"
    # Spezifikation zuerst probiert, danach nur noch die funktionierende Variante
    assert calls.count("/firewall/v1/firewall-config/firewalls/import") == 1
    assert "/firewall/v1/firewall-config/firewalls/transactions/tx" not in calls
    assert central._CONFIG_PREFIX["https://api-legacy.test"] == ""


def test_real_404_is_not_masked():
    def handler(request):
        if request.url.host == "id.test":
            return token_ok(request)
        return httpx.Response(404, json={"error": "notFound", "message": "Firewall not found"})

    try:
        make_client(handler).export_config("unknown", ["Zone"])
    except central.CentralError as e:
        assert e.status == 404 and "firewall-config" in str(e)
    else:
        raise AssertionError("CentralError erwartet")


def test_normalize_status():
    assert normalize_status({"managingStatus": "approvedByCustomer", "connected": True})["managing"] == "approvedByCustomer"
    assert normalize_status({"managing": "approved"}) == {"managing": "approved"}
