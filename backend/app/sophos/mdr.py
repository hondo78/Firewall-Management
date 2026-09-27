"""MDR-Threat-Feed einer Firewall über Sophos Central (Firewall Management API, /firewall-config/…/mdr-threat-feed).

Zwei Objekttypen im Änderungs-Workflow – für jede Firewall mit Central-Zuordnung, unabhängig von der Anbindung:
- mdrThreatFeed: Einstellungen als ein Objekt „MDR-Threat-Feed“ {enabled, action}; nur „update“.
  clearIndicators: true in einem Update löscht beim Ausrollen *alle* Indikatoren (DELETE …/indicators), auch solche,
  die außerhalb des Tools angelegt wurden. Das lässt sich nicht zurücknehmen.
- mdrIndicators: Indikatoren {name: Wert, type: ipv4-addr|domain-name|url}.

Die API kann die Indikatoren nicht auflisten, nur gezielt nach Werten suchen. Bekannt sind deshalb nur die Indikatoren,
die über das Tool angelegt wurden: Beim Synchronisieren prüft die Suche, welche davon noch vorhanden sind.
Alle Aufrufe sind asynchron (Transaktion je Firewall) und dauern je nach Erreichbarkeit der Firewall einige Sekunden.
"""
import ipaddress
import re
from typing import Callable

from ..i18n import tr
from .central import CentralClient, CentralError

FEED_NAME = "MDR-Threat-Feed"
TYPES = ("ipv4-addr", "domain-name", "url")
ACTIONS = ("logOnly", "logAndDrop")
CHUNK = 100                       # API-Grenze je Aufruf

Log = Callable[[str], None]

_DOMAIN = re.compile(r"^(?=.{1,253}$)(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$", re.I)


def _bool(v) -> bool:
    return v is True or str(v).lower() == "true"


def _chunks(items: list, n: int = CHUNK):
    for i in range(0, len(items), n):
        yield items[i:i + n]


def validate_indicator(value: str, typ: str) -> str | None:
    """Fehlermeldung oder None."""
    if typ not in TYPES:
        return tr('Typ muss ipv4-addr, domain-name oder url sein')
    if not value or len(value) > 2048 or any(c.isspace() for c in value):
        return tr('Ungültiger Wert „{0}“', value)
    if typ == "ipv4-addr":
        try:
            ipaddress.IPv4Network(value, strict=False)
        except ValueError:
            return tr('„{0}“ ist keine IPv4-Adresse', value)
    elif typ == "domain-name" and not _DOMAIN.match(value):
        return tr('„{0}“ ist kein gültiger Domänenname', value)
    elif typ == "url" and "." not in value:
        return tr('„{0}“ ist keine gültige URL', value)
    return None


def _found(response) -> set[str] | None:
    """Werte aus der Suchantwort. None = unbekanntes Format (dann nichts als gelöscht betrachten)."""
    items = response.get("items") if isinstance(response, dict) else response
    if isinstance(response, dict) and items is None:
        items = response.get("indicators")
    if not isinstance(items, list):
        return None
    out = set()
    for i in items:
        if isinstance(i, str):
            out.add(i)
        elif isinstance(i, dict) and i.get("value"):
            out.add(str(i["value"]))
    return out


def fetch(client: CentralClient, cid: str, cached: list[dict], log: Log | None = None) -> dict[str, list[dict]]:
    feed = client.mdr_feed(cid, log)
    settings = {"name": FEED_NAME, "enabled": _bool(feed.get("enabled")), "action": feed.get("action") or "logOnly"}
    known = [o["name"] for o in cached]
    present = set(known)
    for part in _chunks(known):
        found = _found(client.mdr_search(cid, part, log).get("response") or {})
        if found is None:
            if log:
                log(tr('MDR-Suche: unbekanntes Antwortformat – Indikatoren bleiben unverändert'))
            break
        present -= set(part) - found
    return {"mdrThreatFeed": [settings], "mdrIndicators": [o for o in cached if o["name"] in present]}


def _ind(o: dict) -> dict:
    data = o.get("data") or o.get("before") or {}
    return {"type": data.get("type"), "value": o["name"]}


def _check_add(tx: dict) -> None:
    errors = (tx.get("response") or {}).get("errors") or {}
    invalid = (errors.get("invalidMDRIndicators") or {}).get("items") or []
    if invalid:
        raise CentralError(tr('Ungültige Indikatoren: {0}', ", ".join(str(i.get("value", i)) for i in invalid)))


def apply(client: CentralClient, cid: str, ops: list[dict], log: Log) -> Callable[[], None]:
    """Einstellungen, Löschungen, Neuanlagen – in dieser Reihenfolge. Gibt eine Rücknahme-Funktion zurück
    (für einen Fehler im anschließenden Konfigurationsteil). Bei einem Fehler hier wird selbst zurückgenommen."""
    undo: list[tuple[str, Callable[[], object]]] = []

    def rollback():
        for label, step in reversed(undo):
            try:
                step()
                log(tr('  zurückgenommen: {0}', label))
            except CentralError as e:
                log(tr('  Rücknahme fehlgeschlagen für {0}: {1} – bitte manuell prüfen!', label, e))

    try:
        for o in (o for o in ops if o["entity"] == "mdrThreatFeed"):
            d, before = o["data"], o.get("before") or {}
            if d.get("clearIndicators"):
                client.mdr_delete_all(cid, log)
                log(tr('MDR-Threat-Feed: alle Indikatoren gelöscht (nicht rücknehmbar)'))
            changed = {k: d[k] for k in ("enabled", "action") if k in d and d[k] != before.get(k)}
            if changed:
                client.mdr_settings(cid, changed.get("enabled"), changed.get("action"), log)
                log(tr('MDR-Threat-Feed: Einstellungen geändert ({0})', ", ".join(changed)))
                undo.append((FEED_NAME, lambda b=before: client.mdr_settings(cid, b.get("enabled"), b.get("action"))))
        removes = [_ind(o) for o in ops if o["entity"] == "mdrIndicators" and o["action"] == "remove"]
        for part in _chunks(removes):
            client.mdr_delete(cid, part, log)
            log(tr('MDR-Indikatoren gelöscht: {0}', ", ".join(i["value"] for i in part)))
            undo.append((tr('{0} Indikatoren', len(part)), lambda p=part: client.mdr_add(cid, p)))
        adds = [_ind(o) for o in ops if o["entity"] == "mdrIndicators" and o["action"] in ("add", "update")]
        for part in _chunks(adds):
            _check_add(client.mdr_add(cid, part, log))
            log(tr('MDR-Indikatoren angelegt: {0}', ", ".join(i["value"] for i in part)))
            undo.append((tr('{0} Indikatoren', len(part)), lambda p=part: client.mdr_delete(cid, p)))
    except CentralError:
        rollback()
        raise
    return rollback


def request_preview(cid: str, o: dict) -> str:
    """Vorschau der Central-Aufrufe einer Operation (für Entwurf und Antrag)."""
    import json
    base = f"/firewall/v1/firewall-config/firewalls/{cid}/mdr-threat-feed"
    if o["entity"] == "mdrThreatFeed":
        d, before = o.get("data") or {}, o.get("before") or {}
        lines = []
        if d.get("clearIndicators"):
            lines.append(f"DELETE {base}/indicators")
        body = {k: d[k] for k in ("enabled", "action") if k in d and d[k] != before.get(k)}
        if body:
            lines.append(f"PATCH {base}/settings\n{json.dumps(body, indent=2)}")
        return "\n\n".join(lines) or tr('(keine Änderung)')
    ind = [_ind(o)]
    path = f"{base}/indicators/delete" if o["action"] == "remove" else f"{base}/indicators"
    return f"POST {path}\n{json.dumps({'indicators': ind}, indent=2)}"
