"""Vergleich von Konfigurationsobjekten und -ständen (Grundlage für Anträge und den Konfigurationsvergleich)."""
import hashlib
import json

from .sophos.entities import oname


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def config_hash(config: dict[str, list[dict]]) -> str:
    return hashlib.sha256(canonical(config).encode()).hexdigest()


def flatten(value, prefix: str = "") -> dict[str, str]:
    """{"NetworkPolicy": {"SourceZones": {"Zone": ["LAN"]}}} → {"NetworkPolicy › SourceZones › Zone": "LAN"}"""
    out: dict[str, str] = {}
    if isinstance(value, dict):
        for k, v in value.items():
            out.update(flatten(v, f"{prefix} › {k}" if prefix else k))
    elif isinstance(value, list):
        # REST-Verweislisten [{"name": "LAN"}, …] kompakt als „LAN, DMZ“ darstellen
        if value and all(isinstance(v, dict) and list(v) == ["name"] for v in value):
            out[prefix] = ", ".join(str(v["name"]) for v in value)
        elif all(not isinstance(v, (dict, list)) for v in value):
            out[prefix] = ", ".join(str(v) for v in value)
        else:
            for i, v in enumerate(value, 1):
                out.update(flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix] = "" if value is None else str(value)
    return out


def diff_objects(before: dict | None, after: dict | None) -> list[dict]:
    a, b = flatten(before or {}), flatten(after or {})
    rows = []
    for key in list(dict.fromkeys([*a.keys(), *b.keys()])):
        if a.get(key) != b.get(key):
            rows.append({"field": key, "before": a.get(key), "after": b.get(key)})
    return rows


def compare_configs(old: dict[str, list[dict]], new: dict[str, list[dict]]) -> dict:
    """Pro Entität: hinzugefügt / entfernt / geändert / unverändert (wie der Vergleich im Config Studio)."""
    result = {}
    for entity in list(dict.fromkeys([*old.keys(), *new.keys()])):
        o = {oname(x): x for x in old.get(entity, [])}
        n = {oname(x): x for x in new.get(entity, [])}
        added = [name for name in n if name not in o]
        removed = [name for name in o if name not in n]
        modified = [{"name": name, "fields": diff_objects(o[name], n[name])}
                    for name in n if name in o and canonical(o[name]) != canonical(n[name])]
        common_old = [x for x in o if x in n]
        common_new = [x for x in n if x in o]
        unchanged = len(common_new) - len(modified)
        if added or removed or modified or common_old != common_new:
            result[entity] = {"added": added, "removed": removed, "modified": modified, "unchanged": unchanged,
                              "order_changed": common_old != common_new}
    return result


def summarize(comparison: dict) -> dict:
    return {e: {"added": len(c["added"]), "removed": len(c["removed"]), "modified": len(c["modified"]),
                "order_changed": c["order_changed"]} for e, c in comparison.items()}
