"""Einmaliger Umbau: deutsche Meldungen im Backend in tr("…") einpacken (nur Textstellen ersetzen, Formatierung bleibt).

python tools/i18n_wrap.py [--write] [dateien…]   (ohne --write: nur anzeigen)

f-Strings werden zu tr("… {0} …", ausdruck); verschachtelte Texte in Ausdrücken werden ebenfalls umgebaut.
Ausgelassen: Docstrings, Modul-Konstanten, Dict-Schlüssel, Vergleiche, logging-Aufrufe, audit()-Argumente.
"""
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "app"
WRITE = "--write" in sys.argv
ONLY = [a for a in sys.argv[1:] if not a.startswith("--")]

GERMAN = re.compile(r"[äöüÄÖÜß„“]|\b(der|die|das|den|dem|des|ein|eine|einer|einen|nicht|kein|keine|keinen|und|oder|ist|sind|"
                    r"wird|werden|wurde|mit|für|von|auf|bei|nach|nur|bitte|noch|schon|zur|zum|im|am|als|aus|"
                    r"Firewall|Antrag|Anträge|Regel|Benutzer|Objekt|fehlt|ungültig|gefunden|erlaubt|möglich|Keine|"
                    r"Ungültig|Unbekannte?r?|Fehler|Genehmigung|Entwurf|Anmeldung|Passwort|Zugang|Konto|Zeile|"
                    r"Anfrage|Antwort|Sicherung|Vorlage|Gruppe|Rolle|Rechte?|Berechtigung|abgelaufen|erforderlich)\b")
SKIP_CALL_ATTRS = {"debug", "info", "warning", "error", "exception", "critical", "startswith", "endswith", "split",
                   "replace", "strip", "join", "format", "execute", "where", "get", "setdefault", "pop", "encode"}
SKIP_CALLS = {"audit", "select", "text", "tr", "getLogger", "ContextVar", "Field", "Path", "open", "re.compile",
              "compile", "isinstance", "getattr", "hasattr", "setattr"}
SKIP_FILES = {"i18n.py", "migrations.py", "config.py"}


def is_text(s: str) -> bool:
    v = s.strip()
    if len(v) < 3 or not re.search(r"[A-Za-zÄÖÜäöüß]{2}", v):
        return False
    if re.fullmatch(r"[\w.\-/:{}#@]+", v) and not re.search(r"[äöüÄÖÜß]", v):
        return False
    return bool(GERMAN.search(v))


def joined_text(node: ast.JoinedStr) -> str:
    return "".join(v.value if isinstance(v, ast.Constant) else " x " for v in node.values)


class Collector(ast.NodeVisitor):
    def __init__(self):
        self.targets: list[ast.AST] = []
        self.stack: list[ast.AST] = []
        self.func_depth = 0

    def generic_visit(self, node):
        self.stack.append(node)
        super().generic_visit(node)
        self.stack.pop()

    def visit_FunctionDef(self, node):
        self.func_depth += 1
        body = node.body
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            body[0].value._docstring = True
        self.generic_visit(node)
        self.func_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
            node.body[0].value._docstring = True
        self.generic_visit(node)

    def _skip(self, node) -> bool:
        if getattr(node, "_docstring", False) or self.func_depth == 0:
            return True
        parents = self.stack
        parent = parents[-1] if parents else None
        if isinstance(parent, ast.Dict) and any(k is node for k in parent.keys):
            return True
        if isinstance(parent, ast.Compare):
            return True
        if isinstance(parent, ast.Subscript):
            return True
        if isinstance(parent, ast.JoinedStr):          # Teil eines f-Strings – wird mit diesem behandelt
            return True
        for p in reversed(parents):
            if isinstance(p, ast.Call):
                f = p.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                if isinstance(f, ast.Attribute) and f.attr in SKIP_CALL_ATTRS:
                    if isinstance(f.value, ast.Name) and f.value.id in ("log", "logger", "logging", "log_"):
                        return True
                    if f.attr in ("debug", "info", "warning", "error", "exception", "critical"):
                        return True
                    # Methoden auf dem Text selbst (" … ".join) – der Text ist dann kein Anzeige-Text
                    if f.value is node:
                        return True
                if name in SKIP_CALLS:
                    return True
                break
        for p in parents:
            if isinstance(p, ast.keyword) and p.arg == "details":
                return True
        return False

    def visit_Constant(self, node):
        if isinstance(node.value, str) and is_text(node.value) and not self._skip(node):
            self.targets.append(node)

    def visit_JoinedStr(self, node):
        if is_text(joined_text(node)) and not self._skip(node):
            self.targets.append(node)
            return  # Ausdrücke im f-String werden beim Umbau rekursiv behandelt
        self.generic_visit(node)


def offsets(src: bytes):
    starts = [0]
    for i, b in enumerate(src):
        if b == 10:
            starts.append(i + 1)
    return lambda line, col: starts[line - 1] + col


def process(path: Path) -> int:
    src_text = path.read_text(encoding="utf-8")
    src = src_text.encode("utf-8")
    tree = ast.parse(src_text)
    col = Collector()
    col.visit(tree)
    if not col.targets:
        return 0
    off = offsets(src)
    span = lambda n: (off(n.lineno, n.col_offset), off(n.end_lineno, n.end_col_offset))  # noqa: E731

    # Zusätzlich deutsche Texte innerhalb von f-String-Ausdrücken finden
    def inner_targets(node):
        found = []
        for sub in ast.walk(node):
            if sub is node:
                continue
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and is_text(sub.value):
                found.append(sub)
            elif isinstance(sub, ast.JoinedStr) and is_text(joined_text(sub)):
                found.append(sub)
        # nur äußerste
        outer = [n for n in found if not any(o is not n and span(o)[0] <= span(n)[0] and span(n)[1] <= span(o)[1] for o in found)]
        return outer

    def render(node) -> bytes:
        if isinstance(node, ast.Constant):
            return f"tr({node.value!r})".encode()
        key, args = "", []
        for v in node.values:
            if isinstance(v, ast.Constant):
                key += v.value.replace("{", "{{").replace("}", "}}")
            else:
                i = len(args)
                conv = {-1: "", 115: "!s", 114: "!r", 97: "!a"}[v.conversion]
                spec = ""
                if v.format_spec is not None:
                    spec = ":" + "".join(c.value if isinstance(c, ast.Constant) else "" for c in v.format_spec.values)
                key += "{" + str(i) + conv + spec + "}"
                args.append(render_expr(v.value))
        return b"tr(" + repr(key).encode() + b"".join(b", " + a for a in args) + b")"

    def is_label(expr) -> bool:
        # entities.LABELS[x] / LABELS.get(x, …) → Anzeigename des Objekttyps, ebenfalls übersetzen
        base = expr.value if isinstance(expr, ast.Subscript) else (
            expr.func.value if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "get" else None)
        return (isinstance(base, ast.Attribute) and base.attr == "LABELS") or (isinstance(base, ast.Name) and base.id == "LABELS")

    def render_expr(expr) -> bytes:
        s, e = span(expr)
        chunk = src[s:e]
        edits = sorted(((span(n), render(n)) for n in inner_targets(expr)), key=lambda x: -x[0][0])
        for (a, b), r in edits:
            chunk = chunk[:a - s] + r + chunk[b - s:]
        return b"tr(" + chunk + b")" if is_label(expr) else chunk

    edits = sorted(((span(n), render(n)) for n in col.targets), key=lambda x: -x[0][0])
    out = src
    last = len(src) + 1
    applied = []
    for (a, b), r in edits:
        if b <= last:
            out = out[:a] + r + out[b:]
            last = a
            applied.append(src[a:b].decode()[:100].replace("\n", " "))
    text = out.decode("utf-8")
    if not re.search(r"^from \.+i18n import tr$", text, re.M):
        depth = len(path.relative_to(ROOT).parts) - 1
        line = f"from {'.' * (depth + 1)}i18n import tr"
        # nach dem letzten Top-Level-Import einfügen
        tree2 = ast.parse(text)
        imports = [n for n in tree2.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        lines = text.split("\n")
        at = imports[-1].end_lineno if imports else 0
        lines.insert(at, line)
        text = "\n".join(lines)
    if WRITE:
        path.write_text(text, encoding="utf-8")
    else:
        print(f"\n### {path.relative_to(ROOT)} ({len(applied)})")
        for a in reversed(applied):
            print("   ", a)
    return len(applied)


if __name__ == "__main__":
    files = [Path(f).resolve() for f in ONLY] if ONLY else [p for p in ROOT.rglob("*.py") if p.name not in SKIP_FILES]
    total = sum(process(f) for f in sorted(files))
    print(f"\n{total} Stellen", file=sys.stderr)
