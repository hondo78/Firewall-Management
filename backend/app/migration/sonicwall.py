"""SonicWall (SonicOS) – unverschlüsselter Settings-Export (.exp) → Zwischenmodell.

Die .exp-Datei ist Base64-kodiert und enthält URL-kodierte Paare „schlüssel=wert&…“ mit durchnummerierten Schlüsseln,
z. B. addrObjId_0, addrObjType_0 (1 Host, 2 Bereich, 4 Netz, 8 Gruppe), addro_atomToGrp_0/addro_grpToGrp_0,
svcObjId_0, svcObjIpType_0 (6 TCP, 17 UDP, 1 ICMP), svcObjPort1_0/svcObjPort2_0, policySrcZone_0, policyAction_0
(0 verweigern, 1 verwerfen, 2 zulassen). Das Format ist nicht offiziell dokumentiert – ausgewertet werden die bekannten
Schlüssel; was fehlt, steht im Bericht.
"""
import base64
import binascii
import re
from collections import defaultdict
from urllib.parse import unquote_plus

from ..i18n import tr
from . import model

ANY = {"", "any", "Any", "ANY"}
_KEY = re.compile(r"^(.+?)_(\d+)$")


def decode(data: bytes) -> dict[str, str]:
    raw = data.strip()
    text = None
    try:
        dec = base64.b64decode(raw, validate=False)
        if b"=" in dec[:2000] and b"&" in dec[:2000]:
            text = dec.decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        pass
    if text is None:
        text = raw.decode("utf-8", errors="replace")
    pairs = {}
    for part in text.replace("\r", "").replace("\n", "&").split("&"):
        if "=" in part:
            k, _, v = part.partition("=")
            pairs[unquote_plus(k)] = unquote_plus(v)
    return pairs


def table(pairs: dict[str, str], prefix: str) -> list[dict[str, str]]:
    """Alle Schlüssel prefix*_N zu Zeilen N zusammenfassen: [{feld: wert}] in Nummernfolge."""
    rows: dict[int, dict] = defaultdict(dict)
    for k, v in pairs.items():
        if k.startswith(prefix):
            mt = _KEY.match(k)
            if mt:
                rows[int(mt.group(2))][mt.group(1)[len(prefix):]] = v
    return [rows[i] for i in sorted(rows)]


def _mask_to_prefix(mask: str) -> int:
    return sum(bin(int(x)).count("1") for x in mask.split("."))


def parse(data: bytes) -> dict:
    p = decode(data)
    if not any(k.startswith(("addrObjId_", "policyAction_", "svcObjId_")) for k in p):
        raise ValueError(tr('Keine SonicWall-Einstellungen erkannt (unverschlüsselte .exp-Datei erwartet)'))
    m = model.new("sonicwall")
    m["source"] = {"firmware": p.get("buildNum", "") or p.get("firmwareVersion", ""), "model": p.get("shortProdName", "")}

    for i in table(p, "iface_"):
        name = i.get("name") or i.get("ifaceName")
        if name:
            model.add_interface(m, name, i.get("zone", ""), i.get("lan_ip") or i.get("static_ip", ""), "interface")
    for z in table(p, "zoneObj"):
        if z.get("Id"):
            model.add_interface(m, z["Id"], z["Id"], kind="zone")

    # Adressen
    groups: dict[str, list[str]] = defaultdict(list)
    for a in table(p, "addrObj"):
        n, t = a.get("Id"), a.get("Type", "")
        if not n:
            continue
        ip1, ip2 = a.get("Ip1", ""), a.get("Ip2", "")
        if t == "1":
            m["addresses"].append({"name": n, "type": "host", "value": ip1})
        elif t == "2":
            m["addresses"].append({"name": n, "type": "range", "start": ip1, "end": ip2})
        elif t == "4":
            m["addresses"].append({"name": n, "type": "network", "value": f"{ip1}/{_mask_to_prefix(ip2) if '.' in ip2 else ip2}"})
        elif t == "8":
            groups.setdefault(n, [])
        else:
            m["addresses"].append({"name": n, "type": "unsupported", "note": tr('Adresstyp {0} nicht unterstützt', t)})
    for f in table(p, "addrObjFqdn"):
        if f.get("Id"):
            m["addresses"].append({"name": f["Id"], "type": "fqdn", "value": f.get("") or f.get("Fqdn", "")})
    for g in table(p, "addro_"):
        if g.get("grpToGrp") and g.get("atomToGrp"):
            groups[g["grpToGrp"]].append(g["atomToGrp"])
    for n, members in groups.items():
        m["address_groups"].append({"name": n, "members": [x for x in members if x not in ANY]})

    # Dienste
    sgroups: dict[str, list[str]] = defaultdict(list)
    for s in table(p, "svcObj"):
        n = s.get("Id")
        if not n:
            continue
        if s.get("Type") == "2":
            sgroups.setdefault(n, [])
            continue
        proto = {"6": "TCP", "17": "UDP", "1": "ICMP", "58": "ICMPV6"}.get(s.get("IpType", ""), "")
        p1, p2 = s.get("Port1", ""), s.get("Port2", "")
        if proto in ("TCP", "UDP"):
            items = [{"proto": proto, "dst": p1 if not p2 or p1 == p2 else f"{p1}:{p2}"}]
        elif proto.startswith("ICMP"):
            items = [{"proto": proto, "icmp_type": p1}]
        elif s.get("IpType"):
            items = [{"proto": "IP", "ip_proto": s.get("IpType")}]
        else:
            items = []
        m["services"].append({"name": n, "items": items})
    for g in table(p, "so_"):
        if g.get("grpToGrp") and g.get("atomToGrp"):
            sgroups[g["grpToGrp"]].append(g["atomToGrp"])
    for n, members in sgroups.items():
        m["service_groups"].append({"name": n, "members": members})

    # Access Rules
    sec = []
    for i, r in enumerate(table(p, "policy")):
        if r.get("Action") is None and r.get("SrcZone") is None:
            continue
        name = r.get("Name") or f"{r.get('SrcZone', 'Any')}→{r.get('DstZone', 'Any')} #{i}"
        notes = []
        if any(r.get(k) not in (None, "", "0") for k in ("AppControl", "Ips", "Gav", "Cfs")):
            notes.append(tr('Sicherheitsdienste (CFS/GAV/IPS/App) nicht übernommen'))
            sec.append(name)
        m["rules"].append({
            "name": name, "enabled": r.get("Enabled", "1") != "0",
            "action": {"2": "accept", "1": "drop", "0": "reject"}.get(r.get("Action", "0"), "drop"),
            "src_zones": [r["SrcZone"]] if r.get("SrcZone") not in ANY else [],
            "dst_zones": [r["DstZone"]] if r.get("DstZone") not in ANY else [],
            "src": [r["SrcNet"]] if r.get("SrcNet") not in ANY else [],
            "dst": [r["DstNet"]] if r.get("DstNet") not in ANY else [],
            "services": [r["DstSvc"]] if r.get("DstSvc") not in ANY else [],
            "log": r.get("Log", "1") != "0", "schedule": r.get("Schedule", ""), "comment": r.get("Comment", ""),
            "notes": notes})
        for z in (r.get("SrcZone"), r.get("DstZone")):
            if z not in ANY and z is not None:
                model.add_interface(m, z, z, kind="zone")
    for n in table(p, "natPolicy"):
        if n.get("OrigSrc") is not None or n.get("TransDst") is not None:
            m["nat"].append({"name": n.get("Comment") or tr('NAT-Regel'),
                             "summary": f"{n.get('OrigSrc', 'Any')} → {n.get('OrigDst', 'Any')} ⇒ {n.get('TransSrc', 'Original')} / {n.get('TransDst', 'Original')}"})

    R = model.report
    R(m, "concepts", tr('Zonen'), "supported", len(m["interfaces"]), tr('SonicWall-Zonen werden im nächsten Schritt Sophos-Zonen zugeordnet.'))
    R(m, "objects", tr('Adressobjekte (Host, Bereich, Netz, FQDN)'), "supported", sum(1 for a in m["addresses"] if a["type"] != "unsupported"))
    R(m, "objects", tr('Adressgruppen'), "supported", len(m["address_groups"]))
    R(m, "objects", tr('Dienste und Dienstgruppen'), "supported", len(m["services"]) + len(m["service_groups"]))
    R(m, "interfaces", tr('Interfaces, VLANs, Routen, DHCP'), "manual", 0, tr('Werden von diesem Tool nicht verwaltet.'))
    R(m, "rules", tr('Access Rules'), "supported", len(m["rules"]))
    if sec:
        R(m, "rules", tr('Sicherheitsdienste auf Regeln'), "manual", len(sec), "", sec)
    if m["nat"]:
        R(m, "rules", tr('NAT-Richtlinien'), "manual", len(m["nat"]), tr('Als NAT-Regeln auf Sophos nachbauen.'),
          [f"{n['name']}: {n['summary']}" for n in m["nat"]])
    R(m, "advanced", tr('VPN, SSL-VPN, HA, Wireless'), "manual", 0, tr('Bewusst nicht übernommen.'))
    m["warnings"].append(tr('Das SonicWall-Exportformat ist nicht offiziell dokumentiert – Ergebnis besonders sorgfältig prüfen.'))
    return m
