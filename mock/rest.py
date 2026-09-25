"""SFOS-REST-API-Attrappe: https://<fw>/api/firewall-config/v1/… mit Bearer-Key (nur die verwalteten Ressourcen).

Zustand je Firewall in JSON (aus seed.py umgerechnet); unabhängig vom XML-Zustand der Attrappe.
"""
import copy
import ipaddress
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

import seed

API_KEY = os.environ.get("MOCK_API_KEY", "sfos_mock_key")
PREFIX = "/api/firewall-config/v1"

RESOURCES = {
    "/firewall/rules/ipv4": "firewallRulesIpv4", "/firewall/rules/ipv6": "firewallRulesIpv6",
    "/nat/rules/ipv4": "natRulesIpv4", "/network/addresses/ipv4": "addressesIpv4",
    "/network/address-groups/ipv4": "addressGroupsIpv4", "/network/addresses/ipv6": "addressesIpv6",
    "/network/address-groups/ipv6": "addressGroupsIpv6", "/network/addresses/fqdn": "addressesFqdn",
    "/network/address-groups/fqdn": "addressGroupsFqdn", "/network/addresses/mac": "addressesMac",
    "/network/address-groups/country": "countryGroups", "/network/services": "services",
    "/network/service-groups": "serviceGroups", "/network/zones": "zones", "/administration/schedules": "schedules",
}
RULES = {"firewallRulesIpv4", "firewallRulesIpv6", "natRulesIpv4"}
REF_TARGETS = {"zone": ["zones"], "network": ["addressesIpv4", "addressGroupsIpv4", "addressesFqdn", "addressGroupsFqdn",
                                            "addressesMac", "countryGroups"],
               "service": ["services", "serviceGroups"], "schedule": ["schedules"]}
NET_KEYS = ("ipv4Addresses", "ipv4Groups", "fqdnAddresses", "fqdnGroups", "macAddresses", "countryGroups")

router = APIRouter()
state: dict[str, dict[str, list[dict]]] = {}


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def meta(obj: dict) -> dict:
    return {"id": str(uuid.uuid4()), **obj, "createdAt": now(), "updatedAt": now()}


# --- Seed (XML-Struktur aus seed.py → REST-Struktur) ---------------------------------------------------------

def _refs(names):
    return [{"name": n} for n in names]


def convert(objects: list[tuple[str, dict]]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {v: [] for v in RESOURCES.values()}
    for tag, d in objects:
        if tag == "Zone":
            t = d["Type"].lower()
            out["zones"].append(meta({"name": d["Name"], "type": t if t in ("lan", "wan", "dmz", "vpn") else "lan",
                                      "description": d.get("Description", "")}))
        elif tag == "Schedule":
            out["schedules"].append(meta({"name": d["Name"], "description": d.get("Description", ""), "type": "recurring",
                                          "timeSlots": [{"dayOfWeek": "weekdays" if "Work" in d["Name"] else "allDays",
                                                         "startTime": "08:00" if "Work" in d["Name"] else "00:00",
                                                         "endTime": "18:00" if "Work" in d["Name"] else "23:59"}]}))
        elif tag == "Services":
            det = d["ServiceDetails"]["ServiceDetail"][0]
            p = int(det["DestinationPort"])
            out["services"].append(meta({"name": d["Name"], "description": d.get("Description", ""), "type": "tcpOrUdp",
                                         "services": [{"protocol": det["Protocol"].lower(),
                                                       "sourcePort": {"from": 1, "to": 65535},
                                                       "destinationPort": {"from": p, "to": p}}]}))
        elif tag == "ServiceGroup":
            out["serviceGroups"].append(meta({"name": d["Name"], "description": d.get("Description", ""),
                                              "services": _refs(d["ServiceList"]["Service"])}))
        elif tag == "FQDNHost":
            out["addressesFqdn"].append(meta({"name": d["Name"], "description": d.get("Description", ""), "fqdn": d["FQDN"]}))
        elif tag == "IPHost":
            base = {"name": d["Name"], "description": d.get("Description", "")}
            if d["HostType"] == "Network":
                cidr = ipaddress.IPv4Network(f"0.0.0.0/{d['Subnet']}").prefixlen
                base.update(type="ipv4Network", ipv4NetworkAddress=d["IPAddress"], cidr=cidr)
            elif d["HostType"] == "IPRange":
                base.update(type="ipv4Range", ipv4AddressStart=d["StartIPAddress"], ipv4AddressEnd=d["EndIPAddress"])
            else:
                base.update(type="ipv4Address", ipv4Address=d["IPAddress"])
            out["addressesIpv4"].append(meta(base))
        elif tag == "IPHostGroup":
            out["addressGroupsIpv4"].append(meta({"name": d["Name"], "description": d.get("Description", ""),
                                                  "ipv4Addresses": _refs(d["HostList"]["Host"])}))
        elif tag == "FirewallRule":
            pol = d["NetworkPolicy"]
            groups = {x["name"] for x in out["addressGroupsIpv4"]}

            def nets(key):
                names = (pol.get(key) or {}).get("Network") or []
                if not names:
                    return {"any": True}
                res = {}
                for n in names:
                    res.setdefault("ipv4Groups" if n in groups else "ipv4Addresses", []).append({"name": n})
                return res
            svc = (pol.get("Services") or {}).get("Service") or []
            sgroups = {x["name"] for x in out["serviceGroups"]}
            svc_val = {"any": True} if not svc else {k: v for k, v in {
                "services": _refs([s for s in svc if s not in sgroups]),
                "serviceGroups": _refs([s for s in svc if s in sgroups])}.items() if v}
            rule = {"name": d["Name"], "description": d.get("Description", ""), "ruleType": "firewall",
                    "enabled": d["Status"] == "Enable", "action": pol["Action"].lower(),
                    "sourceZones": {"zones": _refs(pol["SourceZones"]["Zone"])},
                    "destinationZones": {"zones": _refs(pol["DestinationZones"]["Zone"])},
                    "sourceNetworks": nets("SourceNetworks"), "destinationNetworks": nets("DestinationNetworks"),
                    "servicesOrGroups": svc_val, "logTraffic": pol.get("LogTraffic") == "Enable"}
            if pol.get("Schedule") and pol["Schedule"] != "All The Time":
                rule["schedule"] = {"name": pol["Schedule"]}
            out["firewallRulesIpv4"].append(meta(rule))
    return out


def reset() -> None:
    state.clear()
    for f in seed.FIREWALLS:
        state[f["serial"]] = convert(f["objects"])


reset()


# --- Hilfen --------------------------------------------------------------------------------------------------

def err(status: int, error: str, message: str) -> JSONResponse:
    return JSONResponse({"error": error, "message": message}, status_code=status)


def names_in(fw: dict, kind: str) -> set[str]:
    return {o["name"] for e in REF_TARGETS[kind] for o in fw.get(e, [])}


def references(entity: str, obj: dict) -> list[tuple[str, str]]:
    refs = []
    if entity in ("firewallRulesIpv4", "firewallRulesIpv6"):
        for k in ("sourceZones", "destinationZones"):
            refs += [("zone", z["name"]) for z in (obj.get(k) or {}).get("zones", [])]
        for k in ("sourceNetworks", "destinationNetworks"):
            for nk in NET_KEYS:
                refs += [("network", n["name"]) for n in (obj.get(k) or {}).get(nk, [])]
        svc = obj.get("servicesOrGroups") or {}
        refs += [("service", s["name"]) for s in svc.get("services", []) + svc.get("serviceGroups", [])]
        if (obj.get("schedule") or {}).get("name"):
            refs.append(("schedule", obj["schedule"]["name"]))
    elif entity == "addressGroupsIpv4":
        refs += [("network", n["name"]) for n in obj.get("ipv4Addresses", [])]
    elif entity == "addressGroupsFqdn":
        refs += [("network", n["name"]) for n in obj.get("fqdns", [])]
    elif entity == "serviceGroups":
        refs += [("service", n["name"]) for n in obj.get("services", [])]
    return refs


def check_refs(fw: dict, entity: str, obj: dict):
    for kind, name in references(entity, obj):
        if name not in names_in(fw, kind):
            return err(400, "invalidRequest", f"Referenced {kind} '{name}' does not exist")
    return None


def in_use(fw: dict, entity: str, name: str) -> bool:
    kind = next((k for k, ents in REF_TARGETS.items() if entity in ents), None)
    return kind is not None and any((kind, name) in references(e, o) for e, objs in fw.items() for o in objs)


def find(lst: list[dict], ref: str) -> int | None:
    return next((i for i, o in enumerate(lst) if o["name"] == ref or o["id"] == ref), None)


def place(lst: list[dict], obj: dict, body: dict):
    pos = body.get("position")
    ref = (body.get("referenceItem") or {}).get("name")
    if pos not in ("top", "bottom", "after", "before"):
        return err(400, "invalidRequest", "position is required")
    if pos == "top":
        lst.insert(0, obj)
    elif pos == "bottom":
        lst.append(obj)
    else:
        i = find(lst, ref or "")
        if i is None:
            return err(400, "invalidRequest", f"referenceItem '{ref}' not found")
        lst.insert(i + (1 if pos == "after" else 0), obj)
    return None


def resolve(path: str) -> tuple[str | None, str]:
    """→ (entity, Rest-Pfad nach der Ressource)"""
    for base in sorted(RESOURCES, key=len, reverse=True):
        if path == base or path.startswith(base + "/"):
            return RESOURCES[base], path[len(base):].lstrip("/")
    return None, ""


# --- Routen --------------------------------------------------------------------------------------------------

@router.api_route("/fw/{serial}/firewall-config/v1/{path:path}", methods=["GET", "POST", "PATCH", "DELETE"])
def wrong_prefix(serial: str, path: str):
    # wie die echte Firewall: ohne /api gibt es eine HTML-Fehlerseite
    return HTMLResponse("<html><body><h3>Error:404 Page not found</h3></body></html>", status_code=404)


@router.api_route("/fw/{serial}" + PREFIX + "/{path:path}", methods=["GET", "POST", "PATCH", "DELETE"])
async def rest_api(serial: str, path: str, request: Request):
    if request.headers.get("authorization", "") != f"Bearer {API_KEY}":
        return err(401, "unauthenticated", "Token missing or invalid.")
    fw = state.get(serial)
    if fw is None:
        return err(404, "notFound", "Unknown firewall")
    path = "/" + path
    if path == "/administration/api-settings":
        return {"enabled": True, "allowedIpHosts": [{"name": "Admin-Host"}]}
    entity, rest = resolve(path)
    if entity is None:
        return err(404, "notFound", "Resource not found")
    lst = fw[entity]
    body = await request.json() if request.method in ("POST", "PATCH") and await request.body() else {}
    method = request.method

    if not rest and method == "GET":
        page, size = int(request.query_params.get("page", 1)), int(request.query_params.get("pageSize", 50))
        chunk = lst[(page - 1) * size: page * size]
        total = max(1, -(-len(lst) // size))
        return {"items": copy.deepcopy(chunk), "pages": {"current": page, "total": total, "items": len(lst),
                                                         "size": size, "maxSize": 1000}}
    if not rest and method == "POST":
        if not body.get("name"):
            return err(400, "invalidRequest", "name is required")
        if find(lst, body["name"]) is not None:
            return err(409, "conflict", f"Object '{body['name']}' already exists")
        obj = meta({k: v for k, v in body.items() if k not in ("position", "referenceItem", "id", "createdAt", "updatedAt")})
        problem = check_refs(fw, entity, obj)
        if problem:
            return problem
        if entity in RULES:
            problem = place(lst, obj, body)
            if problem:
                return problem
        else:
            lst.append(obj)
        return JSONResponse(obj, status_code=201)
    if rest == "move" and method == "POST" and entity in RULES:
        i = find(lst, body.get("name", ""))
        if i is None:
            return err(404, "notFound", "Rule not found")
        obj = lst.pop(i)
        problem = place(lst, obj, body)
        if problem:
            lst.insert(i, obj)
            return problem
        return {}
    if rest == "delete" and method == "POST":
        results = []
        for item in body.get("items", []):
            i = find(lst, item.get("name") or item.get("id") or "")
            if i is not None and not in_use(fw, entity, lst[i]["name"]):
                lst.pop(i)
                results.append({"item": item})
            else:
                results.append({"item": item, "error": {"error": "notDeleted"}})
        return {"items": results}
    if rest and "/" not in rest:
        i = find(lst, rest)
        if i is None:
            return err(404, "notFound", f"Object '{rest}' not found")
        if method == "GET":
            return lst[i]
        if method == "DELETE":
            if in_use(fw, entity, lst[i]["name"]):
                return err(409, "conflict", f"Object '{lst[i]['name']}' is in use")
            lst.pop(i)
            return {}
        if method == "PATCH":
            if "name" in body and body["name"] != lst[i]["name"]:
                return err(400, "invalidRequest", "Renaming is not supported by the mock")
            updated = {**lst[i], **{k: v for k, v in body.items() if k not in ("id", "createdAt", "updatedAt")},
                       "updatedAt": now()}
            problem = check_refs(fw, entity, updated)
            if problem:
                return problem
            lst[i] = updated
            return updated
    return err(405, "methodNotAllowed", "Method not allowed")


def tamper(serial: str) -> str | None:
    fw = state.get(serial)
    if not fw or not fw["firewallRulesIpv4"]:
        return None
    rule = fw["firewallRulesIpv4"][0]
    rule["description"] = f"Direkt an der Firewall geändert {now()}"
    rule["updatedAt"] = now()
    return rule["name"]
