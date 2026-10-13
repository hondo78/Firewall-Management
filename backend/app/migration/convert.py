"""Zwischenmodell → Sophos-Objekte im XML-Format (Entities.xml), abhängig von Zonen-Zuordnung und Präfix.

Grundsatz wie im Config Studio – der Bericht bleibt ehrlich: Eine Regel, die nicht vollständig übernommen werden kann
(unbekanntes oder nicht übertragbares Objekt, z. B. Länder- oder dynamische Adresse), wird deaktiviert übernommen
und im Bericht als „Aktion nötig“ markiert. Sie wird nie stillschweigend weiter gefasst als im Original.
"""
import ipaddress
import re

from ..i18n import tr

MAX_NAME = 60
_BAD = re.compile(r"[,\x00-\x1f]")


class Names:
    """Quellname → gültiger, eindeutiger Sophos-Name (mit optionalem Präfix)."""

    def __init__(self, prefix: str):
        self.prefix = prefix
        self.map: dict[tuple[str, str], str] = {}
        self.used: set[str] = set()

    def get(self, kind: str, name: str) -> str:
        key = (kind, name)
        if key in self.map:
            return self.map[key]
        base = _BAD.sub("_", f"{self.prefix}{name}").lstrip("#").strip() or "Objekt"
        base = base[:MAX_NAME]
        out, i = base, 2
        while out.lower() in self.used:
            suffix = f"_{i}"
            out, i = base[:MAX_NAME - len(suffix)] + suffix, i + 1
        self.used.add(out.lower())
        self.map[key] = out
        return out


def _mask(prefix: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def _ports(p: str) -> str:
    p = (p or "").strip().replace("-", ":")
    return p or "1:65535"


def convert(m: dict, zone_map: dict[str, str], prefix: str = "") -> tuple[dict[str, list[dict]], list[dict]]:
    """Ergebnis: ({XML-Entität: [Objekte]}, Hinweise [{kind, name, status, note}]).
    zone_map: Quell-Interface/-Zone → Sophos-Zone ("" = beliebig)."""
    names = Names(prefix)
    notes: list[dict] = []
    out: dict[str, list[dict]] = {"IPHost": [], "FQDNHost": [], "MACHost": [], "IPHostGroup": [], "FQDNHostGroup": [],
                                  "Services": [], "ServiceGroup": [], "FirewallRule": []}

    def note(kind, name, status, text):
        notes.append({"kind": kind, "name": name, "status": status, "note": text})

    # --- Adressen ----------------------------------------------------------------------------------------------
    addr_kind: dict[str, str] = {}               # Quellname → ip | fqdn | mac | bad
    addr_name: dict[str, str] = {}               # Quellname → Sophos-Name
    for a in m["addresses"]:
        t, n = a["type"], a["name"]
        desc = (a.get("comment") or "")[:255]
        try:
            if t in ("host", "network", "host6", "network6"):
                net = ipaddress.ip_network(a["value"], strict=False)
                sn = names.get("addr", n)
                fam = "IPv4" if net.version == 4 else "IPv6"
                if net.num_addresses == 1 and t in ("host", "host6"):
                    obj = {"Name": sn, "Description": desc, "IPFamily": fam, "HostType": "IP", "IPAddress": str(net.network_address)}
                elif net.num_addresses == 1:
                    obj = {"Name": sn, "Description": desc, "IPFamily": fam, "HostType": "IP", "IPAddress": str(net.network_address)}
                else:
                    obj = {"Name": sn, "Description": desc, "IPFamily": fam, "HostType": "Network",
                           "IPAddress": str(net.network_address),
                           "Subnet": _mask(net.prefixlen) if net.version == 4 else str(net.prefixlen)}
                out["IPHost"].append(obj)
                addr_kind[n], addr_name[n] = "ip", sn
            elif t == "range":
                ipaddress.ip_address(a["start"]), ipaddress.ip_address(a["end"])
                sn = names.get("addr", n)
                fam = "IPv6" if ":" in a["start"] else "IPv4"
                out["IPHost"].append({"Name": sn, "Description": desc, "IPFamily": fam, "HostType": "IPRange",
                                      "StartIPAddress": a["start"], "EndIPAddress": a["end"]})
                addr_kind[n], addr_name[n] = "ip", sn
            elif t == "fqdn":
                sn = names.get("addr", n)
                out["FQDNHost"].append({"Name": sn, "Description": desc, "FQDN": a["value"]})
                addr_kind[n], addr_name[n] = "fqdn", sn
            elif t == "mac":
                sn = names.get("addr", n)
                out["MACHost"].append({"Name": sn, "Description": desc, "Type": "MACAddress",
                                       "MACAddress": a["value"].upper().replace("-", ":")})
                addr_kind[n], addr_name[n] = "mac", sn
            else:
                addr_kind[n] = "bad"
                note("address", n, "manual", a.get("note") or tr('Adresstyp „{0}“ wird nicht übernommen – auf Sophos nachbauen (z. B. Ländergruppe)', t))
        except (ValueError, KeyError) as e:
            addr_kind[n] = "bad"
            note("address", n, "manual", tr('Adresse nicht lesbar: {0}', e))

    # --- Gruppen (verschachtelt → flach; IP- und FQDN-Mitglieder getrennt) ------------------------------------------
    groups = {g["name"]: g for g in m["address_groups"]}

    def flatten(name, seen=None):
        seen = seen or set()
        if name in seen:
            return []
        seen.add(name)
        if name in groups:
            res = []
            for mem in groups[name]["members"]:
                res += flatten(mem, seen)
            return res
        return [name]

    group_refs: dict[str, list[str]] = {}       # Quell-Gruppenname → Sophos-Namen (IP-Gruppe und/oder FQDN-Gruppe)
    for g in m["address_groups"]:
        members = list(dict.fromkeys(flatten(g["name"])))
        ip = [addr_name[x] for x in members if addr_kind.get(x) == "ip"]
        fq = [addr_name[x] for x in members if addr_kind.get(x) == "fqdn"]
        missing = [x for x in members if addr_kind.get(x) not in ("ip", "fqdn")]
        refs = []
        if ip:
            sn = names.get("grp", g["name"])
            out["IPHostGroup"].append({"Name": sn, "Description": (g.get("comment") or "")[:255], "IPFamily": "IPv4",
                                       "HostList": {"Host": ip}})
            refs.append(sn)
        if fq:
            sn = names.get("grp-fqdn", g["name"] + ("_FQDN" if ip else ""))
            out["FQDNHostGroup"].append({"Name": sn, "Description": (g.get("comment") or "")[:255],
                                         "FQDNHostList": {"FQDNHost": fq}})
            refs.append(sn)
        if ip and fq:
            note("group", g["name"], "partial", tr('IP- und FQDN-Mitglieder getrennt: {0}', ", ".join(refs)))
        if missing:
            note("group", g["name"], "manual", tr('Mitglieder nicht übernommen: {0}', ", ".join(missing[:20])))
            refs.append(None)                     # Gruppe unvollständig → Regeln damit deaktivieren
        group_refs[g["name"]] = refs

    # --- Dienste -------------------------------------------------------------------------------------------------
    svc_name: dict[str, str | None] = {}
    for s in m["services"]:
        items = s["items"]
        tcpudp = [i for i in items if i["proto"] in ("TCP", "UDP")]
        others = [i for i in items if i["proto"] not in ("TCP", "UDP")]
        sn = names.get("svc", s["name"])
        if tcpudp and not others:
            out["Services"].append({"Name": sn, "Description": (s.get("comment") or "")[:255], "Type": "TCPorUDP",
                                    "ServiceDetails": {"ServiceDetail": [
                                        {"SourcePort": _ports(i.get("src")), "DestinationPort": _ports(i.get("dst")),
                                         "Protocol": i["proto"]} for i in tcpudp]}})
            svc_name[s["name"]] = sn
        elif others and not tcpudp and all(i["proto"] in ("ICMP", "ICMPV6") for i in others):
            out["Services"].append({"Name": sn, "Description": (s.get("comment") or "")[:255],
                                    "Type": "ICMPv6" if others[0]["proto"] == "ICMPV6" else "ICMP",
                                    "ServiceDetails": {"ServiceDetail": [{"ICMPType": "Any Type", "ICMPCode": "Any Code"}]}})
            svc_name[s["name"]] = sn
            if any(i.get("icmp_type") not in (None, "", "any") for i in others):
                note("service", s["name"], "partial", tr('ICMP-Typ als „Any Type“ übernommen – bei Bedarf einschränken'))
        elif others and not tcpudp and all(i["proto"] == "IP" for i in others):
            out["Services"].append({"Name": sn, "Description": (s.get("comment") or "")[:255], "Type": "IP",
                                    "ServiceDetails": {"ServiceDetail": [{"ProtocolName": str(i.get("ip_proto") or "")} for i in others]}})
            svc_name[s["name"]] = sn
        else:
            svc_name[s["name"]] = None
            note("service", s["name"], "manual", tr('Dienst mit gemischten Protokollen bzw. ohne Ports – auf Sophos nachbauen'))
    svc_groups = {g["name"]: g for g in m["service_groups"]}

    def flatten_svc(name, seen=None):
        seen = seen or set()
        if name in seen:
            return []
        seen.add(name)
        if name in svc_groups:
            res = []
            for mem in svc_groups[name]["members"]:
                res += flatten_svc(mem, seen)
            return res
        return [name]
    sgroup_ref: dict[str, str | None] = {}
    for g in m["service_groups"]:
        members = list(dict.fromkeys(flatten_svc(g["name"])))
        ok = [svc_name[x] for x in members if svc_name.get(x)]
        missing = [x for x in members if not svc_name.get(x)]
        if missing:
            note("service_group", g["name"], "manual", tr('Mitglieder nicht übernommen: {0}', ", ".join(missing[:20])))
        if ok:
            sn = names.get("svcgrp", g["name"])
            out["ServiceGroup"].append({"Name": sn, "Description": (g.get("comment") or "")[:255], "ServiceList": {"Service": ok}})
        sgroup_ref[g["name"]] = None if (missing or not ok) else names.get("svcgrp", g["name"])

    # --- Regeln --------------------------------------------------------------------------------------------------
    def addr_refs(ref_names, rule_name, side, problems):
        res = []
        for r in ref_names:
            if r in group_refs:
                refs = group_refs[r]
                if None in refs:
                    problems.append(tr('{0}: Gruppe „{1}“ unvollständig', side, r))
                res += [x for x in refs if x]
            elif addr_kind.get(r) in ("ip", "fqdn", "mac"):
                res.append(addr_name[r])
            else:
                # Inline-Adresse in der Regel (z. B. Palo Alto) → eigenes Host-Objekt
                try:
                    net = ipaddress.ip_network(r, strict=False)
                    sn = names.get("addr", r.replace("/", "_"))
                    if not any(o["Name"] == sn for o in out["IPHost"]):
                        out["IPHost"].append({"Name": sn, "Description": tr('Aus Regel „{0}“', rule_name),
                                              "IPFamily": "IPv4" if net.version == 4 else "IPv6",
                                              **({"HostType": "IP", "IPAddress": str(net.network_address)} if net.num_addresses == 1
                                                 else {"HostType": "Network", "IPAddress": str(net.network_address),
                                                       "Subnet": _mask(net.prefixlen) if net.version == 4 else str(net.prefixlen)})})
                    res.append(sn)
                except ValueError:
                    problems.append(tr('{0}: Objekt „{1}“ nicht übertragbar', side, r))
        return list(dict.fromkeys(res))

    for r in m["rules"]:
        problems = list(r.get("notes") or [])
        hard = []
        src = addr_refs(r["src"], r["name"], tr('Quelle'), hard)
        dst = addr_refs(r["dst"], r["name"], tr('Ziel'), hard)
        svcs = []
        for s in r["services"]:
            if s in sgroup_ref:
                if sgroup_ref[s]:
                    svcs.append(sgroup_ref[s])
                else:
                    hard.append(tr('Dienstgruppe „{0}“ unvollständig', s))
            elif svc_name.get(s):
                svcs.append(svc_name[s])
            else:
                hard.append(tr('Dienst „{0}“ nicht übertragbar', s))
        zones = lambda lst: list(dict.fromkeys(z for z in (zone_map.get(x, "") for x in lst) if z))  # noqa: E731
        sz, dz = zones(r["src_zones"]), zones(r["dst_zones"])
        if r.get("schedule") and r["schedule"].lower() not in ("always", "", "none", "all the time"):
            problems.append(tr('Zeitplan „{0}“ nicht übernommen – Regel gilt immer', r["schedule"]))
        enabled = r.get("enabled", True) and not hard
        pol = {"Action": {"accept": "Accept", "drop": "Drop", "reject": "Reject"}.get(r["action"], "Drop"),
               "LogTraffic": "Enable" if r.get("log") else "Disable", "SkipLocalDestined": "Disable",
               "Schedule": "All The Time"}
        if sz:
            pol["SourceZones"] = {"Zone": sz}
        if dz:
            pol["DestinationZones"] = {"Zone": dz}
        if src:
            pol["SourceNetworks"] = {"Network": src}
        if dst:
            pol["DestinationNetworks"] = {"Network": dst}
        if svcs:
            pol["Services"] = {"Service": svcs}
        sn = names.get("rule", r["name"])
        out["FirewallRule"].append({"Name": sn, "Description": (r.get("comment") or "")[:255], "IPFamily": "IPv4",
                                    "Status": "Enable" if enabled else "Disable", "PolicyType": "Network",
                                    "NetworkPolicy": pol})
        if hard:
            note("rule", r["name"], "manual", tr('Deaktiviert übernommen – {0}', "; ".join(hard)))
        if problems:
            note("rule", r["name"], "partial", "; ".join(problems))
    return {k: v for k, v in out.items() if v}, notes
