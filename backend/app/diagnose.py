"""Probelauf / API-Diagnose gegen echte Sophos-Systeme – ausschließlich lesende Aufrufe.

Prüft Anmeldung, Rechte und die tatsächlich vorhandenen Endpunkte (inkl. der Pfad-Abweichung zwischen
Leitfaden und OpenAPI-Spezifikation) und probiert einige nicht dokumentierte, naheliegende GET-Endpunkte.
Nichts davon verändert Konfigurationen; der Export-Test liest nur die Zonen einer Firewall.
"""
import time
import uuid

from sqlalchemy.orm import Session as DbSession

from . import sync
from .models import CentralAccount, Firewall
from .sophos import connector, entities, xmlconv
from .sophos.central import CentralError
from .sophos.restapi import RestApiError
from .sophos.xmlapi import XmlApiError
from .i18n import tr


class Report:
    def __init__(self):
        self.steps: list[dict] = []

    def add(self, name: str, ok: bool | None, detail: str = "", *, method: str = "", path: str = "",
            status: int | None = None, ms: int | None = None, kind: str = "check") -> None:
        # ok: True = bestanden, False = Fehler, None = Information
        self.steps.append({"name": name, "ok": ok, "detail": detail, "method": method, "path": path,
                           "status": status, "ms": ms, "kind": kind})

    def run(self, name: str, fn, *, method: str = "", path: str = ""):
        t = time.monotonic()
        try:
            result, detail = fn()
            self.add(name, True, detail, method=method, path=path, ms=int((time.monotonic() - t) * 1000))
            return result
        except (CentralError, XmlApiError, RestApiError, KeyError, ValueError) as e:
            self.add(name, False, str(e), method=method, path=path, status=getattr(e, "status", None),
                     ms=int((time.monotonic() - t) * 1000))
            return None

    def out(self) -> dict:
        checks = [s for s in self.steps if s["ok"] is not None]
        return {"ok": all(s["ok"] for s in checks), "passed": sum(1 for s in checks if s["ok"]),
                "failed": sum(1 for s in checks if not s["ok"]), "steps": self.steps}


def _err(body) -> str:
    if isinstance(body, dict):
        if isinstance(body.get("detail"), dict):
            body = body["detail"]
        return body.get("message") or body.get("error") or str(body.get("detail") or body)[:200]
    return str(body)[:200]


def _verdict(status: int) -> str:
    if status == 200:
        return tr('vorhanden (liefert Daten)')
    if status == 405:
        return tr('Route vorhanden, GET aber nicht erlaubt')
    if status in (401, 403):
        return tr('Route vermutlich vorhanden, aber keine Berechtigung')
    if status == 404:
        return tr('nicht vorhanden')
    return tr('unklar')


def central(db: DbSession, acc: CentralAccount) -> dict:
    rep = Report()
    client = connector.central_client(acc)
    if not rep.run(tr('Token von Sophos ID'), lambda: (client.token(), tr('Service Principal angemeldet')),
                   method="POST", path="/api/v2/oauth2/token"):
        return rep.out()
    who = rep.run("whoami", lambda: (lambda w: (w, tr('{0} {1} · Region {2}', w.get('idType'), w.get('id'), (w.get('apiHosts') or {}).get('dataRegion', '–'))))(client.whoami()),
                  method="GET", path="/whoami/v1")
    if who and who.get("idType") in ("partner", "organization"):
        rep.run(tr('Tenants auflisten'), lambda: (lambda t: (t, tr('{0} Tenant(s)', len(t))))(
            client.tenants(who["idType"], who["id"])), method="GET", path=f"/{who['idType']}/v1/tenants")
        if not acc.tenant_id:
            rep.add(tr('Tenant ausgewählt'), False, tr('Bitte im Konto einen Tenant wählen'))
            return rep.out()
    fws = rep.run(tr('Firewalls auflisten'), lambda: (lambda f: (f, tr('{0} Firewall(s); Status: ', len(f)) + ", ".join(
        sorted({str((x.get('status') or {}).get('managingStatus') or (x.get('status') or {}).get('managing'))
                for x in f})) if f else "keine"))(client.firewalls()), method="GET", path="/firewall/v1/firewalls")
    groups = rep.run(tr('Firewall-Gruppen (inkl. Untergruppen)'), lambda: (lambda g: (g, tr('{0} Gruppe(n)', len(g))))(
        client.groups()), method="GET", path="/firewall/v1/firewall-groups?recurseSubgroups=true")
    if groups:
        g = groups[0]
        rep.run(tr('Sync-Status Gruppe „{0}“', g['name']), lambda: (lambda s: (s, ", ".join(
            f"{x.get('status')}" for x in s) or tr('keine Mitglieder')))(client.group_sync_status(g["id"])),
            method="GET", path="/firewall/v1/firewall-groups/{id}/firewalls/sync-status")
    if fws:
        ids = [f["id"] for f in fws[:10]]
        rep.run(tr('Firmware-Prüfung'), lambda: (lambda r: (r, ", ".join(
            f"{x.get('serialNumber')}: {', '.join(x.get('upgradeToVersion') or []) or tr('aktuell')}"
            for x in r.get("firewalls", [])[:5])))(client.firmware_check(ids)),
            method="POST", path="/firewall/v1/firewalls/actions/firmware-upgrade-check")
    rep.run(tr('Firewall-Lizenzen (Licensing API)'), lambda: (lambda l: (l, tr('{0} Firewall(s) mit Lizenzdaten', len(l))))(
        client.firewall_licenses()), method="GET", path="/licenses/v1/licenses/firewalls")
    rep.run(tr('Firewall-Alerts (Common API)'), lambda: (lambda a: (a, tr('{0} offene Alert(s)', len(a))))(
        client.firewall_alerts(50)), method="GET", path="/common/v1/alerts?product=firewall")

    # Pfad-Abweichung Leitfaden ↔ Spezifikation: welche Variante kennt die API?
    dummy = str(uuid.uuid4())
    for label, path in ((tr('Spezifikation'), f"/firewall/v1/firewall-config/firewalls/transactions/{dummy}"),
                        (tr('Leitfaden'), f"/firewall/v1/firewalls/transactions/{dummy}")):
        status, body = client.probe("GET", f"{client.data_region}{path}")
        msg = _err(body)
        known = status not in (0, 404) or "transaction" in msg.lower()
        rep.add(tr('Transaktions-Endpunkt ({0})', label), None,
                f"HTTP {status}: {msg} → {tr('Route vorhanden') if known else tr('Route vermutlich unbekannt')}",
                method="GET", path=path.replace(dummy, tr('{zufällige ID}')), status=status, kind="endpoint")

    # Export-Test: liest nur die Zonen einer Firewall (ändert nichts), prüft Recht fwcm.firewall.api.config:write
    target = next((f for f in fws or [] if (f.get("status") or {}).get("connected")), None)
    if target:
        def export():
            data = client.export_config(target["id"], ["Zone"])
            objs, version = xmlconv.parse_entities_xml(xmlconv.read_tar_entities(data), {"Zone"})
            return objs, tr('{0}: {1} Zone(n), API-Version {2}', target.get('name'), len(objs.get('Zone', [])), version or '?')
        rep.run(tr('Export-Test (nur Zonen)'), export, method="POST", path="/firewall/v1/firewall-config/firewalls/{id}/export")

    # Nicht dokumentierte, naheliegende GET-Endpunkte (nur lesend)
    if fws:
        fid = fws[0]["id"]
        probes = [(tr('Einzelne Firewall'), f"/firewall/v1/firewalls/{fid}")]
        if groups:
            probes.append((tr('Einzelne Gruppe'), f"/firewall/v1/firewall-groups/{groups[0]['id']}"))
        probes += [(tr('Transaktionsliste je Firewall'), f"/firewall/v1/firewall-config/firewalls/{fid}/transactions"),
                   ("Firewall-Konfigurationsobjekte", f"/firewall/v1/firewall-config/firewalls/{fid}")]
        for label, path in probes:
            status, body = client.probe("GET", f"{client.data_region}{path}")
            shown = path.replace(fid, "{id}")
            if groups:
                shown = shown.replace(groups[0]["id"], "{groupId}")
            rep.add(tr('Undokumentiert: {0}', tr(label)), None,
                    f"HTTP {status}" + ("" if status == 200 else f" ({_err(body)})") + f" → {_verdict(status)}",
                    method="GET", path=shown, status=status, kind="undocumented")
    return rep.out()


def firewall(db: DbSession, fw: Firewall) -> dict:
    if fw.connector == "central":
        acc = db.get(CentralAccount, fw.central_account_id) if fw.central_account_id else None
        if not acc:
            rep = Report()
            rep.add("Central-Konto", False, tr('Firewall ist keinem Central-Konto zugeordnet'))
            return rep.out()
        result = central(db, acc)
        return result
    if fw.connector == "rest":
        return rest(db, fw)
    rep = Report()
    client = connector.xml_client(fw)
    if not rep.run(tr('Anmeldung an der XML-API'), lambda: (client.test(), f"API-Version {client.api_version or '?'}"),
                   method="POST", path="/webconsole/APIController"):
        return rep.out()
    for entity in entities.NAMES:
        rep.run(tr('Lesen: {0}', tr(entities.LABELS[entity])), lambda e=entity: (lambda objs: (objs, tr('{0} Objekt(e)', len(objs))))(
            client.get(e)), method="POST", path=f"<Get><{entity}/></Get>")
    cached = sync.cached_config(db, fw)
    rep.add(tr('Schreibrechte'), None, tr('Werden erst beim Ausrollen geprüft (kein schreibender Test im Probelauf). Das Geräteprofil des API-Administrators muss Lese-/Schreibzugriff auf Firewall und Objekte haben.'))
    rep.add(tr('Zwischenspeicher'), None, tr('{0} Objekte im Cache, letzte Synchronisation {1}', sum(len(v) for v in cached.values()), fw.last_sync_at.isoformat() if fw.last_sync_at else 'nie'))
    return rep.out()


def rest(db: DbSession, fw: Firewall) -> dict:
    """SFOS REST-API: Anmeldung, Profilrechte des Keys und Lesen aller verwalteten Ressourcen."""
    from datetime import datetime, timezone
    rep = Report()
    client = connector.rest_client(fw)
    if not rep.run(tr('Anmeldung per API-Key'), lambda: (client.test(), f"{client.base_url}{client.prefix}"),
                   method="GET", path="/network/zones"):
        return rep.out()
    if client.prefix != "/api/firewall-config/v1":
        rep.add("Basis-Pfad", None, tr('Firewall antwortet unter {0} (nicht wie in der Spezifikation)', client.prefix),
                kind="endpoint")
    rep.run(tr('API-Einstellungen'), lambda: (lambda r: (r, ", ".join(f"{k}={v}" for k, v in r.items()
                                                                   if not isinstance(v, (dict, list)))[:200] or "ok"))(
        client.request("GET", "/administration/api-settings")), method="GET", path="/administration/api-settings")
    for entity, (path, label, _) in entities.REST_RESOURCES.items():
        t = time.monotonic()
        try:
            n = len(client.list(path))
            rep.add(tr('Lesen: {0}', tr(label)), True, tr('{0} Objekt(e)', n), method="GET", path=path,
                    ms=int((time.monotonic() - t) * 1000))
        except RestApiError as e:
            # 404: Ressource gibt es auf dieser Firmware nicht; 403: Admin-Profil erlaubt es nicht
            rep.add(tr('Lesen: {0}', tr(label)), None if e.status == 404 else False, str(e), method="GET", path=path,
                    status=e.status, ms=int((time.monotonic() - t) * 1000))
    if fw.api_key_expires_at:
        days = (fw.api_key_expires_at - datetime.now(timezone.utc)).days
        rep.add(tr('Ablauf des API-Keys'), days > 30 if days >= 0 else False,
                tr('läuft am {0} ab (in {1} Tagen)', fw.api_key_expires_at.date().isoformat(), days))
    else:
        rep.add(tr('Ablauf des API-Keys'), None, tr('Ablaufdatum nicht hinterlegt – bitte in den Einstellungen eintragen'))
    rep.add(tr('Schreibrechte'), None, tr('Werden erst beim Ausrollen geprüft (kein schreibender Test im Probelauf). Das Geräteprofil des Admins, der den Key erzeugt hat, braucht Lese-/Schreibzugriff auf Regeln und Objekte.'))
    return rep.out()
