from app import changes, diff
from app.sophos import entities

from .conftest import rule

CONFIG = {"FirewallRule": [rule("A"), rule("B"), rule("C")], "IPHost": [{"Name": "H"}]}


def names(cfg):
    return [r["Name"] for r in cfg["FirewallRule"]]


def test_effective_config_positions():
    new = rule("N")
    assert names(changes.effective_config(CONFIG, [
        {"entity": "FirewallRule", "action": "add", "name": "N", "data": new, "position": {"type": "top"}}])) \
        == ["N", "A", "B", "C"]
    assert names(changes.effective_config(CONFIG, [
        {"entity": "FirewallRule", "action": "add", "name": "N", "data": new,
         "position": {"type": "after", "ref": "A"}}])) == ["A", "N", "B", "C"]
    # Verschieben einer bestehenden Regel
    assert names(changes.effective_config(CONFIG, [
        {"entity": "FirewallRule", "action": "update", "name": "C", "data": rule("C"),
         "position": {"type": "before", "ref": "A"}}])) == ["C", "A", "B"]
    assert names(changes.effective_config(CONFIG, [
        {"entity": "FirewallRule", "action": "remove", "name": "B"}])) == ["A", "C"]


def test_rule_position():
    assert changes.rule_position(CONFIG, "A") == {"type": "top"}
    assert changes.rule_position(CONFIG, "C") == {"type": "after", "ref": "B"}


def test_merge_operation_collapses():
    add = {"entity": "IPHost", "action": "add", "name": "X", "data": {"Name": "X", "IPAddress": "1"}}
    upd = {"entity": "IPHost", "action": "update", "name": "X", "data": {"Name": "X", "IPAddress": "2"}}
    rem = {"entity": "IPHost", "action": "remove", "name": "X"}
    merged = changes.merge_operation([add], upd)
    assert merged == [{**upd, "action": "add", "position": None}]
    assert changes.merge_operation([add], rem) == []
    assert changes.merge_operation([rem], {**add})[0]["action"] == "update"


def test_order_operations():
    ops = [
        {"entity": "FirewallRule", "action": "add", "name": "R"},
        {"entity": "IPHost", "action": "add", "name": "H"},
        {"entity": "IPHost", "action": "remove", "name": "Old"},
        {"entity": "FirewallRule", "action": "remove", "name": "OldRule"},
    ]
    ordered = [(o["action"], o["name"]) for o in entities.order_operations(ops)]
    assert ordered == [("remove", "OldRule"), ("add", "H"), ("add", "R"), ("remove", "Old")]


def test_drift_conflicts():
    ops = changes.with_before([{"entity": "FirewallRule", "action": "update", "name": "A", "data": rule("A", "Drop")},
                               {"entity": "IPHost", "action": "add", "name": "Neu", "data": {"Name": "Neu"}}], CONFIG)
    assert changes.drift_conflicts(CONFIG, ops) == []
    drifted = {**CONFIG, "FirewallRule": [rule("A", status="Disable"), rule("B")]}
    problems = changes.drift_conflicts(drifted, ops)
    assert len(problems) == 1 and "verändert" in problems[0] and "Status" in problems[0]
    assert changes.drift_conflicts({**CONFIG, "IPHost": [{"Name": "Neu"}]}, ops)[0].endswith("bereits auf der Firewall")


def test_used_by_and_references():
    cfg = {"FirewallRule": [rule("A", services=["HTTPS"])], "Services": [{"Name": "HTTPS"}],
           "ServiceGroup": [{"Name": "G", "ServiceList": {"Service": ["HTTPS"]}}]}
    assert changes.used_by(cfg, "Services", "HTTPS") == ["Firewall-Regeln „A“", "Dienstgruppen „G“"]
    warnings = changes.check_references(cfg)
    assert any("LAN" in w for w in warnings)  # Zonen fehlen in dieser Test-Konfiguration


def test_compare_configs():
    new = {"FirewallRule": [rule("B"), rule("A", "Drop"), rule("D")], "IPHost": [{"Name": "H"}]}
    result = diff.compare_configs(CONFIG, new)
    r = result["FirewallRule"]
    assert r["added"] == ["D"] and r["removed"] == ["C"] and r["order_changed"]
    assert r["modified"][0]["name"] == "A"
    assert r["modified"][0]["fields"] == [{"field": "NetworkPolicy › Action", "before": "Accept", "after": "Drop"}]
    assert "IPHost" not in result
