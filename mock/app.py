"""Attrappe für Sophos Central (Firewall Management API v1) und die lokale Firewall-XML-API.

Nur für Entwicklung und Tests: Zustand liegt im Speicher und wird bei jedem Start neu erzeugt.

Sophos ID      POST /api/v2/oauth2/token
Central        GET  /whoami/v1, /firewall/v1/... (Firewalls, Gruppen, Firmware, Import/Export unter
               /firewall/v1/firewall-config/… wie in der OpenAPI-Spezifikation 1.5.0),
               /licenses/v1/licenses/firewalls, /common/v1/alerts
Pre-signed     GET/PUT /presigned/{token}
XML-API        POST /fw/{serial}/webconsole/APIController   (Formularfeld reqxml)
Test-Helfer    POST /mock/fw/{serial}/tamper   (Änderung „an der Firewall vorbei“ → Drift)
               POST /mock/reset
"""
import copy
import hashlib
import io
import os
import secrets
import tarfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, Response

import seed

PUBLIC_URL = os.environ.get("MOCK_PUBLIC_URL", "http://sophos-mock:8000").rstrip("/")
CLIENT_ID = os.environ.get("MOCK_CLIENT_ID", "mock-client")
CLIENT_SECRET = os.environ.get("MOCK_CLIENT_SECRET", "mock-secret")
FW_USER = os.environ.get("MOCK_FW_USER", "apiadmin")
FW_PASSWORD = os.environ.get("MOCK_FW_PASSWORD", "mock-password")
# Verzögerung asynchroner Transaktionen (Sekunden)
TX_DELAY = float(os.environ.get("MOCK_TX_DELAY", "1.5"))
API_VERSION = "2100.1"
TENANT_ID = "3e382b8e-49fd-4cd9-8360-a364371d7650"

app = FastAPI(title="Sophos-Attrappe")
lock = threading.RLock()
state: dict = {}


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def to_el(tag, value) -> ET.Element:
    el = ET.Element(tag)
    if isinstance(value, dict):
        for k, v in value.items():
            for item in (v if isinstance(v, list) else [v]):
                el.append(to_el(k, item))
    elif value is not None:
        el.text = str(value)
    return el


def reset() -> None:
    with lock:
        state.clear()
        state["tokens"] = {}
        state["transactions"] = {}
        state["presigned"] = {}
        state["groups"] = {}
        state["firewalls"] = {}
        state["firmware_jobs"] = {}
        for name in sorted({f["group"] for f in seed.FIREWALLS if f.get("group")}):
            gid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"group-{name}"))
            state["groups"][gid] = {"id": gid, "name": name, "parent": None}
        # Untergruppe (Central erlaubt verschachtelte Gruppen)
        parent = str(uuid.uuid5(uuid.NAMESPACE_DNS, "group-Filialen"))
        sub = str(uuid.uuid5(uuid.NAMESPACE_DNS, "group-Filialen-Sued"))
        state["groups"][sub] = {"id": sub, "name": "Süd", "parent": parent}
        for f in seed.FIREWALLS:
            fid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f["serial"]))
            objs: dict[str, list[ET.Element]] = {}
            for tag, data in f["objects"]:
                objs.setdefault(tag, []).append(to_el(tag, data))
            gid = next((g for g, v in state["groups"].items() if v["name"] == f.get("group")), None)
            if f["serial"] == "X11600MUENCHEN1":
                gid = str(uuid.uuid5(uuid.NAMESPACE_DNS, "group-Filialen-Sued"))
            state["firewalls"][f["serial"]] = {
                "id": fid, "serial": f["serial"], "name": f["name"], "hostname": f["hostname"],
                "model": f["model"], "firmware": f["firmware"], "ips": f["ips"], "group_id": gid,
                "central": f.get("central", True), "objects": objs,
            }


reset()


def by_id(fid: str) -> dict:
    fw = next((f for f in state["firewalls"].values() if f["id"] == fid and f["central"]), None)
    if not fw:
        raise HTTPException(404, {"error": "notFound", "message": "Firewall not found"})
    return fw


# --- Sophos ID / Central-Grundlagen -------------------------------------------------------------------------

@app.post("/api/v2/oauth2/token")
def token(grant_type: str = Form(...), client_id: str = Form(...), client_secret: str = Form(...),
          scope: str = Form("token")):
    if client_id != CLIENT_ID or client_secret != CLIENT_SECRET:
        return JSONResponse({"errorCode": "customer.validation", "message": "Invalid client credentials",
                             "error": "invalid_client"}, status_code=401)
    tok = secrets.token_urlsafe(32)
    state["tokens"][tok] = time.time() + 3600
    return {"access_token": tok, "token_type": "bearer", "expires_in": 3600, "errorCode": "success"}


def auth(request: Request, tenant: bool = True) -> None:
    h = request.headers.get("authorization", "")
    tok = h.removeprefix("Bearer ").strip()
    if state["tokens"].get(tok, 0) < time.time():
        raise HTTPException(401, {"error": "unauthorized", "message": "Invalid or expired token"})
    if tenant and request.headers.get("x-tenant-id") != TENANT_ID:
        raise HTTPException(403, {"error": "forbidden", "message": "Unknown tenant"})


@app.get("/whoami/v1")
def whoami(request: Request):
    auth(request, tenant=False)
    return {"id": TENANT_ID, "idType": "tenant", "apiHosts": {"global": PUBLIC_URL, "dataRegion": PUBLIC_URL}}


def fw_out(f: dict) -> dict:
    g = state["groups"].get(f["group_id"]) if f["group_id"] else None
    return {
        "id": f["id"], "tenant": {"id": TENANT_ID}, "serialNumber": f["serial"],
        **({"group": {"id": g["id"], "name": g["name"]}} if g else {}),
        "hostname": f["hostname"], "name": f["name"], "externalIpv4Addresses": f["ips"],
        "firmwareVersion": f["firmware"], "model": f["model"],
        "status": {"managingStatus": "approvedByCustomer", "reportingStatus": "approvedByCustomer",
                   "connected": True, "suspended": False},
        "stateChangedAt": now(), "capabilities": ["sdwanGroup"], "geoLocation": {"latitude": "53.55", "longitude": "9.99"},
    }


def page(items: list) -> dict:
    return {"items": items, "pages": {"current": 1, "total": 1, "size": 100, "maxSize": 1000, "items": len(items)}}


@app.get("/firewall/v1/firewalls")
def list_firewalls(request: Request, groupId: str | None = None, search: str | None = None):
    auth(request)
    items = [f for f in state["firewalls"].values() if f["central"]]
    if groupId:
        items = [f for f in items if f["group_id"] == groupId]
    if search:
        items = [f for f in items if search.lower() in f"{f['name']} {f['hostname']} {f['serial']}".lower()]
    return page([fw_out(f) for f in items])


@app.patch("/firewall/v1/firewalls/{fid}")
async def patch_firewall(fid: str, request: Request):
    auth(request)
    fw = by_id(fid)
    body = await request.json()
    if body.get("name"):
        fw["name"] = body["name"]
    return fw_out(fw)


@app.post("/firewall/v1/firewalls/{fid}/action")
async def fw_action(fid: str, request: Request):
    auth(request)
    by_id(fid)
    return {"status": "succeeded", "action": (await request.json()).get("action")}


@app.get("/firewall/v1/firewall-groups")
def list_groups(request: Request):
    auth(request)
    items = []
    for g in state["groups"].values():
        members = [{"id": f["id"]} for f in state["firewalls"].values() if f["group_id"] == g["id"]]
        parent = state["groups"].get(g["parent"]) if g["parent"] else None
        items.append({"id": g["id"], "name": g["name"], "tenant": {"id": TENANT_ID}, "lockedByManagingAccount": False,
                      **({"parentGroup": {"id": parent["id"], "name": parent["name"]}} if parent else {}),
                      "firewalls": {"total": len(members), "itemsCount": len(members), "items": members}})
    return page(items)


@app.get("/firewall/v1/firewall-groups/{gid}/firewalls/sync-status")
def sync_status(gid: str, request: Request):
    auth(request)
    return page([{"firewall": {"id": f["id"]}, "status": "inSync", "lastUpdatedAt": now()}
                 for f in state["firewalls"].values() if f["group_id"] == gid])


# --- Lizenzen & Alerts --------------------------------------------------------------------------------------

@app.get("/licenses/v1/licenses/firewalls")
def licenses(request: Request):
    auth(request)
    items = []
    for f in state["firewalls"].values():
        if not f["central"]:
            continue
        items.append({"serialNumber": f["serial"], "tenant": {"id": TENANT_ID}, "model": f["model"].split("_")[0],
                      "modelType": "hardware", "lastSeenAt": now(), "licenses": [
                          {"id": str(uuid.uuid5(uuid.NAMESPACE_DNS, f["serial"] + p)), "licenseIdentifier": p,
                           "product": {"code": p, "name": name, "genericCode": p}, "startDate": "2025-01-01",
                           "endDate": end, "perpetual": False, "type": "term", "quantity": 1, "unlimited": False}
                          for p, name, end in (("XGSBASE", "Base License", "2099-12-31"),
                                               ("XGSXSTREAM", "Xstream Protection", "2026-12-31"))]})
    return page(items)


@app.get("/common/v1/alerts")
def alerts(request: Request, product: str | None = None):
    auth(request)
    hh = state["firewalls"]["X11600HAMBURG01"]
    items = [{"id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "alert-hh")), "allowedActions": ["acknowledge"],
              "category": "connectivity", "description": "Gateway WAN-2 ist nicht erreichbar",
              "groupKey": "gw", "managedAgent": {"id": hh["id"], "type": "xgFirewall", "name": hh["name"]},
              "product": "firewall", "raisedAt": now(), "severity": "medium", "tenant": {"id": TENANT_ID},
              "type": "Event::Firewall::GatewayDown"}]
    if product and product != "firewall":
        items = []
    return {"items": items, "pages": {"size": len(items), "total": 1, "items": len(items), "maxSize": 1000}}


# --- Firmware ------------------------------------------------------------------------------------------------

UPGRADES = {"SF01V_SO01_20.0.2.378": ["21.0.1.272", "21.5.0.171"], "SF01V_SO01_21.0.1.272": ["21.5.0.171"]}


@app.post("/firewall/v1/firewalls/actions/firmware-upgrade-check")
async def firmware_check(request: Request):
    auth(request)
    ids = (await request.json()).get("firewalls", [])
    fws = [by_id(i) for i in ids]
    versions = sorted({v for f in fws for v in UPGRADES.get(f["firmware"], [])})
    return {
        "firewalls": [{"id": f["id"], "serialNumber": f["serial"], "firmwareVersion": f["firmware"],
                       "upgradeToVersion": UPGRADES.get(f["firmware"], [])} for f in fws],
        "firmwareVersions": [{"version": v, "bugs": ["NC-0000 Beispiel-Fehlerbehebung"],
                              "news": ["Maintenance Release"], "size": "400 MB"} for v in versions],
    }


@app.post("/firewall/v1/firewalls/actions/firmware-upgrade")
async def firmware_upgrade(request: Request):
    auth(request)
    out = []
    for item in (await request.json()).get("firewalls", []):
        f = by_id(item["id"])
        if item["upgradeToVersion"] not in UPGRADES.get(f["firmware"], []):
            raise HTTPException(400, {"error": "badRequest", "message": "Version not available for this firewall"})
        state["firmware_jobs"][f["id"]] = item
        out.append({"id": f["id"], "upgradeToVersion": item["upgradeToVersion"], "status": "success",
                    "upgradedAt": item.get("upgradeAt") or now()})
    return {"firewalls": out}


@app.delete("/firewall/v1/firewalls/actions/firmware-upgrade")
def firmware_cancel(ids: str, request: Request):
    auth(request)
    for i in ids.split(","):
        state["firmware_jobs"].pop(i, None)
    return {"deleted": True}


# --- Import / Export -----------------------------------------------------------------------------------------

def entities_xml(fw: dict, entities: list[str] | None) -> bytes:
    root = ET.Element("Configuration", {"APIVersion": API_VERSION, "IPS_CAT_VER": "1"})
    for tag, els in fw["objects"].items():
        if entities and tag not in entities:
            continue
        for el in els:
            c = copy.deepcopy(el)
            c.set("transactionid", "")
            root.append(c)
    ET.indent(root, "  ")
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8")


def make_tar(xml: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("Entities.xml")
        info.size = len(xml)
        tar.addfile(info, io.BytesIO(xml))
    return buf.getvalue()


def new_tx(request_path: str, method: str = "POST") -> dict:
    tid = str(uuid.uuid4())
    tx = {"id": tid, "status": "started", "result": "notAvailable", "createdAt": now(), "finishedAt": None,
          "expiryAt": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(), "response": {},
          "request": {"method": method, "path": request_path}, "_ready_at": time.time() + TX_DELAY}
    state["transactions"][tid] = tx
    return tx


@app.post("/firewall/v1/firewall-config/firewalls/{fid}/export")
async def export(fid: str, request: Request):
    auth(request)
    fw = by_id(fid)
    body = await request.json()
    if body.get("fullExport") is True and ("exportEntities" in body or "includeDependency" in body):
        raise HTTPException(400, {"error": "badRequest", "message": "exportEntities not allowed with fullExport"})
    if body.get("fullExport") is False and not body.get("exportEntities"):
        raise HTTPException(400, {"error": "badRequest", "message": "exportEntities required"})
    tx = new_tx("firewalls/{firewallId}/export")
    token = secrets.token_urlsafe(16)
    state["presigned"][token] = {"method": "GET", "data": make_tar(entities_xml(fw, body.get("exportEntities")))}
    tx["_on_finish"] = {"result": "success", "response": {
        "url": f"{PUBLIC_URL}/presigned/{token}", "method": "GET",
        "expiresAt": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(), "firewallId": fid}}
    return JSONResponse({"transactionId": tx["id"]}, status_code=202)


@app.post("/firewall/v1/firewall-config/firewalls/import")
def import_init(request: Request):
    auth(request)
    tx = new_tx("firewalls/import")
    tx["status"] = "pending"
    tx["response"] = {"uploadStatus": "pending", "items": []}
    token = secrets.token_urlsafe(16)
    state["presigned"][token] = {"method": "PUT", "data": None, "tx": tx["id"]}
    return JSONResponse({"transactionId": tx["id"], "url": f"{PUBLIC_URL}/presigned/{token}", "method": "PUT",
                         "expiresAt": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
                         "description": "Upload the configuration archive to this URL using an HTTP PUT."},
                        status_code=202)


@app.get("/presigned/{token}")
def presigned_get(token: str):
    p = state["presigned"].get(token)
    if not p or p["method"] != "GET":
        raise HTTPException(403, "AccessDenied")
    return Response(p["data"], media_type="application/x-tar")


@app.put("/presigned/{token}")
async def presigned_put(token: str, request: Request):
    p = state["presigned"].get(token)
    if not p or p["method"] != "PUT":
        raise HTTPException(403, "AccessDenied")
    p["data"] = await request.body()
    return Response(status_code=200)


@app.post("/firewall/v1/firewall-config/firewalls/import/{tid}/upload-complete")
async def import_complete(tid: str, request: Request):
    auth(request)
    tx = state["transactions"].get(tid)
    if not tx:
        raise HTTPException(404, {"error": "notFound", "message": "Transaction not found"})
    if tx["status"] != "pending":
        raise HTTPException(409, {"error": "conflict", "message": "Transaction does not accept upload completion"})
    body = await request.json()
    p = next((v for v in state["presigned"].values() if v.get("tx") == tid), None)
    data = (p or {}).get("data")
    if not body.get("firewallIds"):
        raise HTTPException(400, {"error": "badRequest", "message": "firewallIds required"})
    if not data or hashlib.md5(data).hexdigest() != body.get("checksumMd5") or len(data) != body.get("fileSizeBytes"):
        raise HTTPException(400, {"error": "badRequest", "message": "Invalid checksumMd5 or fileSizeBytes"})
    items = []
    for fid in body["firewallIds"]:
        fw = by_id(fid)
        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                xml = tar.extractfile("Entities.xml").read()
            root = ET.fromstring(xml)
            with lock:
                work = copy.deepcopy(fw["objects"])
                for el in root:
                    code, _ = apply_set(work, el, "import")
                    if code != "200":
                        raise ValueError(f"{el.tag}: {_}")
                fw["objects"] = work
            items.append({"firewallId": fid, "status": "started", "result": "notAvailable", "_final": "success"})
        except (KeyError, ValueError, ET.ParseError, tarfile.TarError) as e:
            items.append({"firewallId": fid, "status": "started", "result": "notAvailable", "_final": "error",
                          "_error": str(e)})
    tx["status"] = "started"
    tx["response"] = {"uploadStatus": "success", "items": items}
    tx["_ready_at"] = time.time() + TX_DELAY
    ok = all(i["_final"] == "success" for i in items)
    tx["_on_finish"] = {"result": "success" if ok else ("error" if not any(i["_final"] == "success" for i in items)
                                                         else "partialSuccess")}
    return JSONResponse(public_tx(tx), status_code=200)


def public_tx(tx: dict) -> dict:
    out = {k: v for k, v in tx.items() if not k.startswith("_")}
    if "items" in (out.get("response") or {}):
        out["response"] = {**out["response"], "items": [
            {k: v for k, v in i.items() if not k.startswith("_") or k == "_error"} for i in out["response"]["items"]]}
    return out


@app.get("/firewall/v1/firewall-config/firewalls/transactions/{tid}")
def get_tx(tid: str, request: Request):
    auth(request)
    tx = state["transactions"].get(tid)
    if not tx:
        raise HTTPException(404, {"error": "notFound", "message": "Transaction not found"})
    if tx["status"] == "started" and time.time() >= tx["_ready_at"]:
        fin = tx.get("_on_finish") or {}
        tx["status"], tx["finishedAt"] = "finished", now()
        tx["result"] = fin.get("result", "success")
        if "response" in fin:
            tx["response"] = fin["response"]
        for i in (tx.get("response") or {}).get("items", []):
            i["status"], i["result"] = "finished", i.get("_final", "success")
    return public_tx(tx)


# --- Lokale XML-API ------------------------------------------------------------------------------------------

BUILTIN = {"Any", "All The Time"}
REFS = {"Zone": ["Zone"], "Network": ["IPHost", "IPHostGroup", "FQDNHost", "FQDNHostGroup", "MACHost"],
        "Service": ["Services", "ServiceGroup"]}


def names(objs: dict, tags: list[str]) -> set[str]:
    return {el.findtext("Name") for t in tags for el in objs.get(t, [])}


def rule_refs(el: ET.Element) -> list[tuple[str, str]]:
    out = []
    for kind in ("Zone", "Network", "Service"):
        out += [(kind, (x.text or "").strip()) for x in el.iter(kind)]
    return out


def check_refs(objs: dict, el: ET.Element) -> str | None:
    if el.tag == "FirewallRule":
        for kind, name in rule_refs(el):
            if name not in BUILTIN and name not in names(objs, REFS[kind]):
                return f"Operation failed. Invalid {kind.lower()} reference: {name}"
    if el.tag == "IPHostGroup":
        for h in el.iter("Host"):
            if h.text not in names(objs, ["IPHost"]):
                return f"Operation failed. Unknown host: {h.text}"
    if el.tag == "ServiceGroup":
        for s in el.iter("Service"):
            if s.text not in names(objs, ["Services"]):
                return f"Operation failed. Unknown service: {s.text}"
    return None


def in_use(objs: dict, tag: str, name: str) -> bool:
    kind = next((k for k, tags in REFS.items() if tag in tags), None)
    if kind is None:
        return False
    for r in objs.get("FirewallRule", []):
        if (kind, name) in rule_refs(r):
            return True
    for g in objs.get("IPHostGroup", []):
        if tag == "IPHost" and name in [h.text for h in g.iter("Host")]:
            return True
    for g in objs.get("ServiceGroup", []):
        if tag == "Services" and name in [s.text for s in g.iter("Service")]:
            return True
    return False


def apply_set(objs: dict, el: ET.Element, operation: str) -> tuple[str, str]:
    """operation: add | update | import (= add oder update)."""
    name = el.findtext("Name")
    if not name:
        return "500", "Operation failed. Name is required."
    el = copy.deepcopy(el)
    el.attrib.pop("transactionid", None)
    pos, ref = el.findtext("Position"), el.findtext("After/Name") or el.findtext("Before/Name")
    for t in ("Position", "After", "Before"):
        for x in el.findall(t):
            el.remove(x)
    lst = objs.setdefault(el.tag, [])
    idx = next((i for i, x in enumerate(lst) if x.findtext("Name") == name), None)
    if operation == "add" and idx is not None:
        return "502", "Operation failed. Entity having same name already exists."
    if operation == "update" and idx is None:
        return "541", "Operation failed. Entity not found."
    err = check_refs(objs, el)
    if err:
        return "500", err
    if idx is not None:
        lst.pop(idx)
    if el.tag == "FirewallRule" and pos:
        rnames = [x.findtext("Name") for x in lst]
        if pos == "Top":
            new_idx = 0
        elif pos in ("After", "Before") and ref in rnames:
            new_idx = rnames.index(ref) + (1 if pos == "After" else 0)
        elif pos in ("After", "Before"):
            return "500", f"Operation failed. Reference rule not found: {ref}"
        else:
            new_idx = len(lst)
    else:
        new_idx = len(lst) if idx is None else idx
    lst.insert(new_idx, el)
    return "200", "Configuration applied successfully."


def xml_response(children: list[ET.Element], login_ok: bool = True) -> Response:
    root = ET.Element("Response", {"APIVersion": API_VERSION, "IPS_CAT_VER": "1"})
    login = ET.SubElement(root, "Login")
    ET.SubElement(login, "status").text = "Authentication Successful" if login_ok else "Authentication Failure"
    for c in children:
        root.append(c)
    return Response(ET.tostring(root, encoding="utf-8"), media_type="application/xml")


def status_el(tag: str, code: str, text: str) -> ET.Element:
    el = ET.Element(tag, {"transactionid": ""})
    st = ET.SubElement(el, "Status", {"code": code})
    st.text = text
    return el


@app.api_route("/fw/{serial}/webconsole/APIController", methods=["GET", "POST"])
async def xml_api(serial: str, request: Request):
    fw = state["firewalls"].get(serial)
    if not fw:
        raise HTTPException(404, "Not Found")
    reqxml = request.query_params.get("reqxml")
    if reqxml is None:
        form = await request.form()
        reqxml = form.get("reqxml")
    try:
        req = ET.fromstring(reqxml or "")
    except ET.ParseError:
        root = ET.Element("Response")
        ET.SubElement(root, "Status", {"code": "529"}).text = "Input request file is Invalid"
        return Response(ET.tostring(root), media_type="application/xml")
    if req.findtext("Login/Username") != FW_USER or req.findtext("Login/Password") != FW_PASSWORD:
        return xml_response([], login_ok=False)
    out: list[ET.Element] = []
    with lock:
        objs = fw["objects"]
        for op in req:
            if op.tag == "Get":
                for ent in op:
                    items = objs.get(ent.tag, [])
                    if not items:
                        out.append(status_el(ent.tag, "526", "No. of records Zero."))
                    for el in items:
                        c = copy.deepcopy(el)
                        c.set("transactionid", "")
                        out.append(c)
            elif op.tag == "Set":
                operation = op.get("operation", "add")
                for el in op:
                    code, text = apply_set(objs, el, operation)
                    out.append(status_el(el.tag, code, text))
            elif op.tag == "Remove":
                for el in op:
                    name = el.findtext("Name")
                    lst = objs.get(el.tag, [])
                    idx = next((i for i, x in enumerate(lst) if x.findtext("Name") == name), None)
                    if idx is None:
                        out.append(status_el(el.tag, "541", "Operation failed. Entity not found."))
                    elif in_use(objs, el.tag, name):
                        out.append(status_el(el.tag, "500", "Operation failed. Entity is in use."))
                    else:
                        lst.pop(idx)
                        out.append(status_el(el.tag, "200", "Configuration applied successfully."))
    return xml_response(out)


# --- Test-Helfer ---------------------------------------------------------------------------------------------

@app.post("/mock/reset")
def mock_reset():
    reset()
    return {"ok": True}


@app.post("/mock/fw/{serial}/tamper")
def tamper(serial: str):
    """Simuliert eine Änderung direkt an der Firewall: Beschreibung der ersten Regel ändern."""
    fw = state["firewalls"].get(serial)
    if not fw or not fw["objects"].get("FirewallRule"):
        raise HTTPException(404, "Nichts zu ändern")
    rule = fw["objects"]["FirewallRule"][0]
    rule.find("Description").text = f"Direkt an der Firewall geändert {now()}"
    return {"ok": True, "rule": rule.findtext("Name")}


@app.get("/mock/state")
def mock_state():
    return {s: {"id": f["id"], "name": f["name"], "central": f["central"],
                "objects": {t: [e.findtext("Name") for e in els] for t, els in f["objects"].items()}}
            for s, f in state["firewalls"].items()}
