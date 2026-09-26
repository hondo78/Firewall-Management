"""Übersetzungen des Backends prüfen: Schlüssel aus tr("…") sammeln, je Sprache fehlende/unbenutzte Einträge und
abweichende Platzhalter melden; außerdem deutsch aussehende Texte außerhalb von tr() auflisten.

python tools/i18n_check.py [--keys datei.json] [--prune]
"""
import ast
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from i18n_wrap import Collector  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent / "app"
BROAD = re.compile(r"[äöüÄÖÜß„“]|\b(der|die|das|den|dem|des|ein|eine|nicht|kein|keine|und|oder|ist|sind|wird|werden|mit|für|"
                   r"von|auf|bei|nach|nur|bitte|bis|seit|über|unter|vor|zu|zum|zur|als|wie|sich|Sie|Ihr|Ihre|gesendet|erfolgreich|"
                   r"fehlgeschlagen|gestartet|übersprungen|gelöscht|angelegt|geändert|verschoben|Anmeldung|Antragsteller|"
                   r"Befristet|Vergleich|Sicherungen|Schritt|Probelauf|Prüfe|Lese|Schreibe|Hole|Warte|Firewall-\w+)\b")

keys: dict[str, str] = {}
leftovers = []
for f in sorted(ROOT.rglob("*.py")):
    src = f.read_text(encoding="utf-8")
    tree = ast.parse(src)
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "tr" and n.args:
            a = n.args[0]
            cands = [a] if isinstance(a, ast.Constant) else [a.body, a.orelse] if isinstance(a, ast.IfExp) else []
            for c in cands:
                if isinstance(c, ast.Constant) and isinstance(c.value, str):
                    keys[c.value] = f"{f.relative_to(ROOT)}:{c.lineno}"
    if f.name in ("i18n.py", "migrations.py"):
        continue
    # Kandidaten wie im Umbau (ohne Docstrings/Logging/Dict-Schlüssel), aber mit breiterer Erkennung
    col = Collector()
    import i18n_wrap
    old = i18n_wrap.is_text
    i18n_wrap.is_text = lambda s: len(s.strip()) > 3 and bool(BROAD.search(s)) and not re.fullmatch(r"[\w.\-/:{}#@]+", s.strip())
    col.visit(tree)
    i18n_wrap.is_text = old
    for n in col.targets:
        text = n.value if isinstance(n, ast.Constant) else "".join(v.value if isinstance(v, ast.Constant) else "{…}" for v in n.values)
        leftovers.append(f"{f.relative_to(ROOT)}:{n.lineno}  {text.strip()[:100]!r}")

# Konstanten, die erst bei der Verwendung übersetzt werden: Objekttyp-/Bereichsnamen (entities.py) und
# Nachrichten-Bausteine (notify/texts.py: SUBJECT, STATUS, ACTION)
ent = ast.parse((ROOT / "sophos" / "entities.py").read_text(encoding="utf-8"))
for n in ast.walk(ent):
    if isinstance(n, ast.Tuple):
        for e in n.elts[1:]:
            v = e.value if isinstance(e, ast.Constant) and isinstance(e.value, str) else None
            # Anzeigenamen (mit Leer-/Sonderzeichen oder großgeschriebene Wörter), keine Pfade/Bezeichner
            if v and not v.startswith("/") and not re.fullmatch(r"[a-z][A-Za-z0-9]*", v) and not re.fullmatch(r"[A-Z][a-z]+[A-Z]\w*", v) \
                    and not re.fullmatch(r"[A-Z]{2,}[A-Za-z]*", v):
                keys.setdefault(v, "sophos/entities.py")
txt = ast.parse((ROOT / "notify" / "texts.py").read_text(encoding="utf-8"))
for n in txt.body:
    if isinstance(n, ast.Assign) and isinstance(n.value, ast.Dict):
        for v in n.value.values:
            if isinstance(v, ast.Constant):
                keys.setdefault(v.value, "notify/texts.py")

out = sys.argv.index("--keys") if "--keys" in sys.argv else 0
if out:
    Path(sys.argv[out + 1]).write_text(json.dumps(sorted(keys), ensure_ascii=False, indent=1), encoding="utf-8")

problems = 0
for loc in sorted((ROOT / "locales").glob("*.json")):
    d = json.loads(loc.read_text(encoding="utf-8"))
    missing = [k for k in keys if k not in d]
    unused = [k for k in d if k not in keys]
    ph = lambda s: sorted(re.findall(r"\{(\d+)[^{}]*\}", s.replace("{{", "").replace("}}", "")))  # noqa: E731
    bad = [k for k, v in d.items() if ph(k) != ph(v)]
    if "--prune" in sys.argv and unused:
        d = {k: v for k, v in d.items() if k in keys}
        loc.write_text(json.dumps(dict(sorted(d.items())), ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"[{loc.stem}] {len(unused)} unbenutzte Einträge entfernt")
        unused = []
    print(f"[{loc.stem}] {len(d)} Einträge, {len(missing)} fehlen, {len(unused)} unbenutzt, {len(bad)} mit abweichenden Platzhaltern")
    for k in missing[:30]:
        print(f"   fehlt: {k!r} ({keys[k]})")
    for k in bad:
        print(f"   Platzhalter: {k!r}")
    problems += len(missing) + len(bad)
print(f"{len(keys)} Schlüssel; {len(leftovers)} mögliche deutsche Texte außerhalb von tr():")
for x in leftovers[:200]:
    print("   " + x)
sys.exit(1 if problems else 0)
