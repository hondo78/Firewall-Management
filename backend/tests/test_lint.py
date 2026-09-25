from app import changes, lint

from .conftest import rule


def rest_rule(name, action="accept", src="LAN", dst="WAN", dst_nets=None, services=None, log=True, enabled=True):
    return {"name": name, "ruleType": "firewall", "enabled": enabled, "action": action,
            "sourceZones": {"zones": [{"name": src}]} if src else {"any": True},
            "destinationZones": {"zones": [{"name": dst}]} if dst else {"any": True},
            "sourceNetworks": {"any": True},
            "destinationNetworks": {"ipv4Addresses": [{"name": n} for n in dst_nets]} if dst_nets else {"any": True},
            "servicesOrGroups": {"services": [{"name": s} for s in services]} if services else {"any": True},
            "logTraffic": log}


def codes(findings):
    return {(f["code"], f["name"], f["severity"]) for f in findings}


def test_any_any_and_wan_open_rest():
    cfg = {"zones": [{"name": "WAN", "type": "wan"}, {"name": "LAN", "type": "lan"}],
           "firewallRulesIpv4": [rest_rule("ok", src="LAN", dst="WAN", dst_nets=["Srv"], services=["HTTPS"]),
                                 rest_rule("von-wan", src="WAN", dst="LAN", dst_nets=["Srv"], log=False),
                                 rest_rule("offen", src=None, dst=None)]}
    c = codes(lint.analyze(cfg))
    assert ("any_any", "offen", "high") in c
    assert ("wan_open", "von-wan", "high") in c and ("no_log_wan", "von-wan", "medium") in c
    assert not any(n == "ok" for _, n, _ in c)


def test_shadowing_conflict_and_redundant_xml():
    cfg = {"FirewallRule": [rule("Block-All", action="Drop", src="LAN", dst="WAN"),
                            rule("Web", action="Accept", src="LAN", dst="WAN", services=["HTTPS"]),
                            rule("Dup", action="Drop", src="LAN", dst="WAN", services=["SSH"])]}
    c = codes(lint.analyze(cfg))
    assert ("shadowed", "Web", "high") in c          # andere Aktion → Konflikt
    assert ("shadowed", "Dup", "medium") in c        # gleiche Aktion → redundant


def test_unused_and_duplicate_objects():
    cfg = {"firewallRulesIpv4": [rest_rule("r", dst_nets=["A"])],
           "addressesIpv4": [{"name": "A", "type": "ipv4Address", "ipv4Address": "10.0.0.1"},
                             {"name": "B", "type": "ipv4Address", "ipv4Address": "10.0.0.1"},
                             {"name": "Intern", "type": "ipv4Address", "ipv4Address": "1.1.1.1", "isInternal": True}],
           "natRulesIpv4": [{"name": "nat", "translatedDestination": {"name": "B"}}]}
    c = codes(lint.analyze(cfg))
    assert ("duplicate_address", "B", "info") in c
    assert not any(code == "unused" for code, _, _ in c)   # B wird in NAT verwendet, Intern ist eingebaut


def test_for_change_reports_only_new_findings():
    before = {"firewallRulesIpv4": [rest_rule("alt-offen", src=None, dst=None)]}
    ops = [{"entity": "firewallRulesIpv4", "action": "add", "name": "neu", "position": {"type": "bottom"},
            "data": rest_rule("neu", dst_nets=["X"], services=["HTTPS"])}]
    after = changes.effective_config(before, ops)
    found = lint.for_change(before, after, ops)
    # neue Regel liegt hinter der Any-Any-Regel → verdeckt; der alte Any-Any-Befund zählt nicht als neu
    assert codes(found) == {("shadowed", "neu", "medium")}
