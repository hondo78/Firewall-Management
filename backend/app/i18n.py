"""Mehrsprachige Meldungen (gleiches Prinzip wie im Frontend: Schlüssel ist der deutsche Originaltext).

tr("Regel „{0}“ existiert nicht", name) → in der Sprache der aktuellen Anfrage (Accept-Language) bzw. der mit
use(lang) gesetzten Sprache. Übersetzungen: app/locales/<code>.json. Fehlende Einträge → deutscher Text.
Hintergrundaufgaben (Worker, Benachrichtigungen) setzen die Sprache ausdrücklich (Empfänger/Standardsprache).
"""
import json
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

LANGS = ("de", "en")
DEFAULT = "de"
_current: ContextVar[str] = ContextVar("fwm_lang", default=DEFAULT)
_dicts: dict[str, dict[str, str]] = {}
for _code in LANGS:
    _file = Path(__file__).parent / "locales" / f"{_code}.json"
    _dicts[_code] = json.loads(_file.read_text(encoding="utf-8")) if _file.exists() else {}


def tr(text: str, *args) -> str:
    s = _dicts.get(_current.get(), {}).get(text, text)
    return s.format(*args) if args else s


def current() -> str:
    return _current.get()


def normalize(code: str | None) -> str:
    code = (code or "").strip().lower()[:2]
    return code if code in LANGS else ""


def from_header(value: str | None) -> str:
    """Accept-Language auswerten (erste unterstützte Sprache, sonst Standard)."""
    for part in (value or "").split(","):
        code = normalize(part.split(";")[0])
        if code:
            return code
    return DEFAULT


def set_current(code: str):
    return _current.set(normalize(code) or DEFAULT)


@contextmanager
def use(code: str | None):
    token = _current.set(normalize(code) or DEFAULT)
    try:
        yield
    finally:
        _current.reset(token)
