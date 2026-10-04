"""Verbindungsanalyse: Syslog-Parser, Sammeln/Schreiben, Netzwerkplan-Abfrage, Einstufung, Regel-Vorlagen."""
from datetime import datetime, timedelta, timezone

from app import template_plan
from app.db import SessionLocal
from app.flows import analysis, receiver
from app.models import ChangeTemplate, Firewall, FlowBucket, SyslogSender

from .test_workflow import make_user, setup_firewall

V19 = ('<30>device_name="SFW" timestamp="2026-10-04T10:00:00+0200" device_serial_id="S-TEST-1" log_type="Firewall" '
       'log_component="Firewall Rule" log_subtype="{sub}" fw_rule_id="5" fw_rule_name="LAN nach Internet" '
       'src_zone="LAN" dst_zone="WAN" src_ip="{src}" dst_ip="{dst}" protocol="{proto}" src_port=51515 dst_port={port} '
       'bytes_sent=100 bytes_received=900')
OLD = ('device="SFW" date=2026-10-04 time=10:00:00 device_id=S-TEST-1 log_id=010101600001 log_type="Firewall" '
       'log_component="Firewall Rule" log_subtype="Denied" status="Deny" fw_rule_id=0 src_ip=198.51.100.7 '
       'dst_ip=10.0.0.1 protocol="TCP" src_port=40000 dst_port=22 sent_bytes=0 recv_bytes=0 src_zone="WAN" dst_zone="DMZ"')


def line(src="192.168.10.20", dst="8.8.8.8", proto="UDP", port=53, sub="Allowed"):
    return V19.format(src=src, dst=dst, proto=proto, port=port, sub=sub)


def test_parse_both_formats():
    f = receiver.flow_of(receiver.parse(line()))
    assert f["src_ip"] == "192.168.10.20" and f["dst_port"] == 53 and f["protocol"] == "UDP"
    assert f["action"] == "allow" and f["bytes"] == 1000 and f["rule_name"] == "LAN nach Internet"
    old = receiver.flow_of(receiver.parse(OLD))
    assert old["action"] == "deny" and old["dst_zone"] == "DMZ" and old["dst_port"] == 22
    # ICMP ohne Port, andere Logtypen ignorieren
    assert receiver.flow_of(receiver.parse(line(proto="ICMP", port=0)))["dst_port"] == 0
    assert receiver.flow_of(receiver.parse('log_type="Content Filtering" src_ip="1.1.1.1" dst_ip="2.2.2.2"')) is None
    # TCP-Octet-Counting und mehrere Zeilen
    assert receiver._lines(b"12 <30>a=1\n<30>b=2\r\n") == ["<30>a=1", "<30>b=2"]


def _firewall(client, admin):
    fw_id = setup_firewall(client, admin)
    with SessionLocal() as db:
        db.get(Firewall, fw_id).serial = "S-TEST-1"
        db.commit()
    receiver.collector._map_loaded = 0
    return fw_id


def _feed(lines, sender="10.99.0.1", when=None):
    for ln in lines:
        receiver.collector.feed(sender, ln, when)
    receiver.collector.flush()


def test_collector_assigns_by_serial_and_aggregates(client, admin, fake):
    fw_id = _firewall(client, admin)
    now = datetime.now(timezone.utc)
    _feed([line()] * 3 + [line(dst="1.1.1.1", proto="TCP", port=443)] + [OLD], when=now)
    _feed(['log_type="Firewall" src_ip="1.1.1.1" dst_ip="2.2.2.2" protocol="TCP" dst_port=1'], sender="10.99.0.9")
    with SessionLocal() as db:
        rows = db.query(FlowBucket).filter(FlowBucket.firewall_id == fw_id).all()
        dns = next(r for r in rows if r.dst_ip == "8.8.8.8")
        assert dns.count == 3 and dns.bytes == 3000
        assert len(rows) == 3
        known = db.get(SyslogSender, "10.99.0.1")
        assert known.firewall_id == fw_id and known.messages == 5 and known.serial == "S-TEST-1"
        unknown = db.get(SyslogSender, "10.99.0.9")
        assert unknown.firewall_id is None and unknown.ignored == 1 and unknown.sample
    # Zweiter Schwung in derselben Stunde: Zählung wird addiert
    _feed([line()], when=now)
    with SessionLocal() as db:
        assert db.query(FlowBucket).filter(FlowBucket.dst_ip == "8.8.8.8").one().count == 4


def test_flows_api_decisions_and_template(client, admin, fake):
    fw_id = _firewall(client, admin)
    _feed([line(src="192.168.10.20"), line(src="192.168.10.21"), line(dst="10.0.0.1", proto="TCP", port=443),
           line(src="192.168.10.55", dst="203.0.113.66", proto="TCP", port=4444), OLD])
    end = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
    start = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    params = {"start": start, "end": end}
    r = client.get(f"/api/firewalls/{fw_id}/flows", headers=admin, params=params)
    assert r.status_code == 200, r.text
    flows = r.json()
    assert flows["counts"]["open"] == len(flows["edges"]) == 5
    srv = next(e for e in flows["edges"] if e["dst"] == "10.0.0.1" and e["dst_port"] == 443)
    assert srv["dst_name"] == "Server"                          # Name aus der Firewall-Konfiguration
    # Netz-Ebene fasst die beiden DNS-Clients zusammen
    net = client.get(f"/api/firewalls/{fw_id}/flows", headers=admin, params={**params, "level": "net"}).json()
    dns = next(e for e in net["edges"] if e["dst"] == "8.8.8.0/24")
    assert dns["src"] == "192.168.10.0/24" and dns["count"] == 2 and dns["hosts"] == 3

    # Einstufen: Approver ohne „Beantragen“ darf nicht
    ap = make_user(client, admin, "approver", [("Approver", None)])
    ref = lambda e: {k: e[k] for k in ("src", "dst", "protocol", "dst_port")}  # noqa: E731
    assert client.post(f"/api/firewalls/{fw_id}/flows/decisions", headers=ap,
                       json={"items": [ref(srv)], "verdict": "legit"}).status_code == 403
    # Netz-Entscheidung gilt für alle Hosts darin; genauere schlägt allgemeinere
    r = client.post(f"/api/firewalls/{fw_id}/flows/decisions", headers=admin,
                    json={"items": [ref(dns), ref(srv)], "verdict": "legit", "note": "Standard"})
    assert r.json()["updated"] == 2
    bad = next(e for e in flows["edges"] if e["dst_port"] == 4444)
    client.post(f"/api/firewalls/{fw_id}/flows/decisions", headers=admin, json={"items": [ref(bad)], "verdict": "illegit"})
    host = client.get(f"/api/firewalls/{fw_id}/flows", headers=admin, params=params).json()
    by = {(e["src"], e["dst"], e["dst_port"]): e for e in host["edges"]}
    assert by[("192.168.10.20", "8.8.8.8", 53)]["verdict"] == "legit"
    assert by[("192.168.10.20", "8.8.8.8", 53)]["verdict_exact"] is False
    assert by[("192.168.10.55", "203.0.113.66", 4444)]["verdict"] == "illegit"
    assert host["counts"] == {"legit": 3, "illegit": 1, "open": 1}

    # Vorschau und Vorlage mit Präfix
    body = {"start": start, "end": end, "prefix": "NET_", "preview": True}
    prev = client.post(f"/api/firewalls/{fw_id}/flows/template", headers=admin, json=body).json()
    assert prev["counts"] == {"rules": 3, "allow": 2, "deny": 1, "objects": 8}   # 5 Hosts, 3 Dienste
    names = [i["name"] for i in prev["items"]]
    assert all(n.startswith("NET_") or n == "Server" for n in names)
    assert "Server" not in names                                # vorhandenes Objekt wird nur referenziert
    r = client.post(f"/api/firewalls/{fw_id}/flows/template", headers=admin, json={**body, "preview": False, "name": "Aus Logs"})
    assert r.status_code == 200, r.text
    with SessionLocal() as db:
        t = db.get(ChangeTemplate, r.json()["id"])
        rules = [i for i in t.operations if i["entity"] == "FirewallRule"]
        # Drop-Regel steht nach dem Ausrollen ganz oben (alle Regeln „oben“, in umgekehrter Reihenfolge eingetragen)
        assert rules[-1]["data"]["NetworkPolicy"]["Action"] == "Drop"
        assert rules[-1]["name"] == "NET_DENY_LAN-WAN_H_203.0.113.66_TCP_4444"     # Präfix nur einmal im Namen
        dns_rule = next(i for i in rules if "UDP_53" in i["name"])
        assert sorted(dns_rule["data"]["NetworkPolicy"]["SourceNetworks"]["Network"]) == ["NET_H_192.168.10.20", "NET_H_192.168.10.21"]
        srv_rule = next(i for i in rules if "Server" in i["name"])
        assert srv_rule["data"]["NetworkPolicy"]["DestinationNetworks"]["Network"] == ["Server"]
        # Die Vorlage lässt sich auf die Firewall anwenden: keine Fehler, keine Verweis-Warnungen
        from app import sync
        fw = db.get(Firewall, fw_id)
        plan = template_plan.plan(fw, sync.cached_config(db, fw), template_plan.normalize_items(t.operations))
        assert not plan["errors"], plan["errors"]
        assert plan["counts"]["add"] == len(t.operations)
    actions = {e["action"] for e in client.get("/api/audit", headers=admin).json()["items"]}
    assert {"flows.classified", "template.created"} <= actions


def test_template_items_rest_format():
    cfg = {"addressesIpv4": [{"name": "Webserver", "type": "ipv4Address", "ipv4Address": "10.10.20.10"}],
           "services": [{"name": "HTTPS", "type": "tcpOrUdp",
                         "services": [{"protocol": "tcp", "sourcePort": "1:65535", "destinationPort": "443"}]}],
           "firewallRulesIpv4": []}
    edges = [{"src": "198.51.100.0/24", "dst": "10.10.20.10", "protocol": "TCP", "dst_port": 443, "src_zone": "WAN",
              "dst_zone": "DMZ", "count": 9, "verdict": "legit"}]
    items, notes, counts = analysis.build_template_items(edges, cfg, "rest", prefix="FLOW_", position="bottom")
    assert counts == {"rules": 1, "allow": 1, "deny": 0, "objects": 1}
    host = next(i for i in items if i["entity"] == "addressesIpv4")
    assert host["data"] == {"name": "FLOW_N_198.51.100.0_24", "description": "Aus Verbindungsanalyse",
                            "type": "ipv4Network", "ipv4NetworkAddress": "198.51.100.0", "cidr": 24}
    rule = next(i for i in items if i["entity"] == "firewallRulesIpv4")
    assert rule["position"] == {"type": "bottom"} and rule["data"]["action"] == "accept"
    assert rule["data"]["destinationNetworks"] == {"ipv4Addresses": [{"name": "Webserver"}]}
    assert rule["data"]["servicesOrGroups"] == {"services": [{"name": "HTTPS"}]}
    assert rule["data"]["sourceZones"] == {"zones": [{"name": "WAN"}]}


def test_senders_admin_only(client, admin, fake):
    fw_id = _firewall(client, admin)
    _feed([line()], sender="10.99.0.7")
    with SessionLocal() as db:
        db.get(SyslogSender, "10.99.0.7").firewall_id = None
        db.commit()
    fa = make_user(client, admin, "fwadmin", [("Firewall-Administrator", None)])
    assert client.get("/api/flows/senders", headers=fa).status_code == 403
    s = client.get("/api/flows/senders", headers=admin).json()["senders"]
    assert s[0]["ip"] == "10.99.0.7" and s[0]["firewall_id"] is None
    assert client.put("/api/flows/senders/10.99.0.7", headers=admin, json={"firewall_id": fw_id}).status_code == 200
    assert client.get("/api/flows/senders", headers=admin).json()["senders"][0]["firewall"] == "FW-Test"
