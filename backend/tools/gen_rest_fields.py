"""Erlaubte Felder je REST-Entität aus der Spezifikation (docs/sfos-rest-openapi.json) erzeugen.

python backend/tools/gen_rest_fields.py  →  backend/app/sophos/rest_fields.json
Erlaubt = Vereinigung der Felder aus Anlegen (POST), Ändern (PATCH) und Lesen (GET-Antwort) – so werden auch
nur lesend gelieferte Felder (z. B. wafService) nicht fälschlich abgelehnt.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = json.loads((ROOT / "docs" / "sfos-rest-openapi.json").read_text())
sys.path.insert(0, str(ROOT / "backend"))
src = (ROOT / "backend" / "app" / "sophos" / "entities.py").read_text()
# REST_RESOURCES ohne Import der App (keine Abhängigkeiten nötig)
resources = dict(re.findall(r'"(\w+)": \("(/[^"]+)",', src.split("REST_RESOURCES")[1].split("}")[0]))


def res(x):
    while isinstance(x, dict) and "$ref" in x:
        a = x["$ref"].split("/")
        x = spec["components"][a[-2]][a[-1]]
    return x


def props(sc, seen=0) -> set[str]:
    sc = res(sc)
    if not isinstance(sc, dict) or seen > 6:
        return set()
    out = set((sc.get("properties") or {}).keys())
    for k in ("allOf", "oneOf", "anyOf"):
        for part in sc.get(k, []):
            out |= props(part, seen + 1)
    if sc.get("type") == "array" or "items" in sc:
        out |= props(sc.get("items", {}), seen + 1)
    return out


def body(op):
    c = ((op or {}).get("requestBody") or {}).get("content", {})
    return next(iter(c.values()), {}).get("schema") if c else None


def response(op):
    r = (op or {}).get("responses", {})
    for code in ("200", "201"):
        c = (r.get(code) or {}).get("content", {})
        if c:
            return next(iter(c.values())).get("schema")
    return None


out = {}
for entity, path in resources.items():
    item = spec["paths"].get(path, {})
    one = spec["paths"].get(path + "/{idOrName}", {})
    keys = set()
    for op, sc in ((item.get("post"), body), (one.get("patch") or item.get("patch"), body),
                   (one.get("get"), response), (item.get("get"), response)):
        if op and sc(op):
            k = props(sc(op))
            keys |= k - {"items", "pages"}      # Listen-Hülle der GET-Antwort
    if keys:
        out[entity] = sorted(keys | {"name"})
target = ROOT / "backend" / "app" / "sophos" / "rest_fields.json"
target.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
print(f"{target}: {len(out)} Entitäten", {e: len(v) for e, v in out.items()})
