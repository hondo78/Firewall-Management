"""Client für die Sophos Central API (Firewall Management API v1, OpenAPI-Spezifikation 1.5.0).

Ablauf: Service-Principal-Token (OAuth2 client_credentials) → whoami (Tenant/Partner/Organisation, Region)
→ Aufrufe unter <dataRegion>/firewall/v1/… mit Header X-Tenant-ID.
Konfiguration lesen/schreiben über die asynchronen Import/Export-Endpunkte (Archiv mit Entities.xml):
  Export: POST /firewall-config/firewalls/{id}/export → transactionId
          → GET /firewall-config/firewalls/transactions/{tx} → pre-signed GET-URL
  Import: POST /firewall-config/firewalls/import → pre-signed PUT-URL (S3) → Upload
          → POST /firewall-config/firewalls/import/{tx}/upload-complete → GET …/transactions/{tx} (items[] je Firewall)

Achtung: Der Leitfaden auf developer.sophos.com nennt dieselben Endpunkte ohne das Präfix /firewall-config
(z. B. POST /firewalls/{id}/export). Maßgeblich ist die OpenAPI-Spezifikation (assets/specs/firewall-v1.yaml);
bei HTTP 404 wird einmalig die Variante aus dem Leitfaden probiert und das funktionierende Präfix je Region gemerkt.
"""
import hashlib
import threading
import time

import httpx

from .. import config
from ..i18n import tr


class CentralError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


# Central erlaubt je Firewall nur einen laufenden Export („An export operation is already pending or in-progress“).
# Eigene Exporte (Synchronisation, Sicherung, Ausrollen, Probelauf, Download) laufen deshalb je Firewall nacheinander;
# läuft ein fremder Export (z. B. aus der Central-Oberfläche), wird gewartet.
_EXPORT_LOCKS: dict[str, threading.Lock] = {}
_EXPORT_LOCKS_GUARD = threading.Lock()
BUSY_MESSAGE = "already pending or in-progress"


def export_lock(firewall_id: str) -> threading.Lock:
    with _EXPORT_LOCKS_GUARD:
        return _EXPORT_LOCKS.setdefault(firewall_id, threading.Lock())


def is_busy(e: Exception) -> bool:
    return isinstance(e, CentralError) and (getattr(e, "busy", False) or (e.status in (400, 409) and BUSY_MESSAGE in str(e)))


# Präfix für Import/Export/Transaktionen: Spezifikation zuerst, dann Leitfaden
CONFIG_PREFIXES = ("/firewall-config", "")
_CONFIG_PREFIX: dict[str, str] = {}


class CentralClient:
    def __init__(self, id_url: str, api_url: str, client_id: str, client_secret: str,
                 tenant_id: str = "", data_region: str = "", transport: httpx.BaseTransport | None = None):
        self.id_url = id_url.rstrip("/")
        self.api_url = api_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id or ""
        self.data_region = (data_region or "").rstrip("/")
        self._token = ""
        self._token_exp = 0.0
        # transport: nur für Tests (httpx.MockTransport)
        self._http = httpx.Client(transport=transport) if transport else httpx.Client()

    # --- Authentifizierung -------------------------------------------------------------------------------

    def token(self) -> str:
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        try:
            r = self._http.post(f"{self.id_url}/api/v2/oauth2/token", timeout=config.HTTP_TIMEOUT_SECONDS, data={
                "grant_type": "client_credentials", "client_id": self.client_id,
                "client_secret": self.client_secret, "scope": "token",
            })
        except httpx.HTTPError as e:
            raise CentralError(tr('Sophos ID nicht erreichbar: {0}', e)) from e
        if r.status_code != 200:
            raise CentralError(tr('Anmeldung an Sophos Central fehlgeschlagen (HTTP {0}): {1}', r.status_code, _msg(r)))
        body = r.json()
        self._token = body["access_token"]
        self._token_exp = time.time() + int(body.get("expires_in", 3600))
        return self._token

    def _headers(self, tenant: bool = True) -> dict:
        h = {"Authorization": f"Bearer {self.token()}", "Accept": "application/json"}
        if tenant:
            if not self.tenant_id:
                raise CentralError(tr('Kein Tenant ausgewählt'))
            h["X-Tenant-ID"] = self.tenant_id
        return h

    def whoami(self) -> dict:
        r = self._call("GET", f"{self.api_url}/whoami/v1", tenant=False)
        return r

    def tenants(self, id_type: str, principal_id: str) -> list[dict]:
        """Tenants eines Partner- oder Organisations-Kontos (mit apiHost je Tenant)."""
        if id_type == "partner":
            url, header = f"{self.api_url}/partner/v1/tenants", "X-Partner-ID"
        elif id_type == "organization":
            url, header = f"{self.api_url}/organization/v1/tenants", "X-Organization-ID"
        else:
            return []
        items, page = [], 1
        while True:
            h = {"Authorization": f"Bearer {self.token()}", header: principal_id}
            body = self._call("GET", url, tenant=False, headers=h, params={"page": page, "pageTotal": "true"})
            items += body.get("items", [])
            total = int((body.get("pages") or {}).get("total") or 1)
            if page >= total:
                return items
            page += 1

    # --- HTTP-Grundlagen ---------------------------------------------------------------------------------

    def _call(self, method: str, url: str, *, tenant: bool = True, headers: dict | None = None, **kw):
        h = headers or self._headers(tenant)
        try:
            r = self._http.request(method, url, headers=h, timeout=config.HTTP_TIMEOUT_SECONDS, **kw)
        except httpx.HTTPError as e:
            raise CentralError(tr('Sophos Central nicht erreichbar: {0}', e)) from e
        if r.status_code >= 400:
            short = url.replace(self.data_region, "").replace(self.api_url, "")
            raise CentralError(f"{method} {short} → HTTP {r.status_code}: {_msg(r)}", status=r.status_code)
        return r.json() if r.content else {}

    def probe(self, method: str, url: str, *, tenant: bool = True, **kw) -> tuple[int, object]:
        """Rohaufruf ohne Exception (Diagnose): (HTTP-Status, JSON oder Text)."""
        try:
            r = self._http.request(method, url, headers=self._headers(tenant), timeout=config.HTTP_TIMEOUT_SECONDS, **kw)
        except httpx.HTTPError as e:
            return 0, str(e)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, r.text[:300]

    def _fw(self, method: str, path: str, **kw):
        if not self.data_region:
            raise CentralError(tr('Daten-Region unbekannt – Central-Konto erneut prüfen'))
        return self._call(method, f"{self.data_region}/firewall/v1{path}", **kw)

    def _cfg(self, method: str, path: str, **kw):
        """Import/Export/Transaktionen: Pfad laut Spezifikation, bei 404 einmalig die Leitfaden-Variante."""
        known = _CONFIG_PREFIX.get(self.data_region)
        prefixes = [known] if known is not None else list(CONFIG_PREFIXES)
        first_error = None
        for prefix in prefixes:
            try:
                result = self._fw(method, f"{prefix}{path}", **kw)
            except CentralError as e:
                if e.status == 404 and known is None:
                    first_error = first_error or e
                    continue
                raise
            _CONFIG_PREFIX[self.data_region] = prefix
            return result
        raise first_error

    def _paged(self, path: str, params: dict | None = None) -> list[dict]:
        items, page = [], 1
        while True:
            body = self._fw("GET", path, params={**(params or {}), "page": page, "pageSize": 100, "pageTotal": "true"})
            items += body.get("items", [])
            total = int(str((body.get("pages") or {}).get("total") or 1).strip(","))
            if page >= total or not body.get("items"):
                return items
            page += 1

    # --- Inventar ----------------------------------------------------------------------------------------

    def firewalls(self, group_id: str | None = None, search: str | None = None) -> list[dict]:
        params = {k: v for k, v in (("groupId", group_id), ("search", search)) if v}
        return self._paged("/firewalls", params)

    def groups(self) -> list[dict]:
        # Gruppen können verschachtelt sein (parentGroup) – Untergruppen mitliefern
        return self._paged("/firewall-groups", {"recurseSubgroups": "true"})

    def group_sync_status(self, group_id: str) -> list[dict]:
        return self._fw("GET", f"/firewall-groups/{group_id}/firewalls/sync-status").get("items", [])

    def update_firewall(self, firewall_id: str, name: str | None = None, geo: dict | None = None) -> dict:
        """PATCH /firewalls/{id}: Name (3–40 Zeichen) und/oder geoLocation {latitude, longitude} (als Strings)."""
        body: dict = {}
        if name is not None:
            body["name"] = name
        if geo is not None:
            body["geoLocation"] = {"latitude": str(geo["latitude"]), "longitude": str(geo["longitude"])}
        return self._fw("PATCH", f"/firewalls/{firewall_id}", json=body)

    def delete_firewall(self, firewall_id: str) -> dict:
        """DELETE /firewalls/{id}: Firewall aus Sophos Central entfernen (nicht die Firewall selbst)."""
        return self._fw("DELETE", f"/firewalls/{firewall_id}")

    def run_action(self, firewall_id: str, action: str) -> dict:
        """POST /firewalls/{id}/action – laut Spezifikation 1.5.0 nur „approveManagement“."""
        return self._fw("POST", f"/firewalls/{firewall_id}/action", json={"action": action})

    def approve_management(self, firewall_id: str) -> dict:
        return self.run_action(firewall_id, "approveManagement")

    # --- Firewall-Gruppen --------------------------------------------------------------------------------

    def create_group(self, name: str, assign: list[str], parent_id: str | None = None,
                     import_from: str | None = None) -> dict:
        """POST /firewall-groups. import_from: Firewall, deren Konfiguration die Gruppe übernimmt."""
        body: dict = {"name": name, "assignFirewalls": assign}
        if parent_id:
            body["parentGroupId"] = parent_id
        if import_from:
            body["configImportSourceFirewallId"] = import_from
        return self._fw("POST", "/firewall-groups", json=body)

    def update_group(self, group_id: str, name: str | None = None, assign: list[str] | None = None,
                     unassign: list[str] | None = None) -> dict:
        body: dict = {}
        if name is not None:
            body["name"] = name
        if assign:
            body["assignFirewalls"] = assign
        if unassign:
            body["unassignFirewalls"] = unassign
        return self._fw("PATCH", f"/firewall-groups/{group_id}", json=body)

    def delete_group(self, group_id: str) -> dict:
        return self._fw("DELETE", f"/firewall-groups/{group_id}")

    # --- Firmware ----------------------------------------------------------------------------------------

    def firmware_check(self, firewall_ids: list[str]) -> dict:
        return self._fw("POST", "/firewalls/actions/firmware-upgrade-check", json={"firewalls": firewall_ids})

    def firmware_upgrade(self, items: list[dict]) -> dict:
        return self._fw("POST", "/firewalls/actions/firmware-upgrade", json={"firewalls": items})

    def firmware_cancel(self, firewall_ids: list[str]) -> dict:
        return self._fw("DELETE", "/firewalls/actions/firmware-upgrade", params={"ids": ",".join(firewall_ids)})

    # --- Lizenzen & Alerts (andere Central-APIs, aber firewall-bezogen) ----------------------------------

    def firewall_licenses(self) -> list[dict]:
        """GET https://api.central.sophos.com/licenses/v1/licenses/firewalls (global, nicht regional)."""
        items, page = [], 1
        while True:
            body = self._call("GET", f"{self.api_url}/licenses/v1/licenses/firewalls",
                              params={"page": page, "pageSize": 100, "pageTotal": "true"})
            items += body.get("items", [])
            if page >= int((body.get("pages") or {}).get("total") or 1) or not body.get("items"):
                return items
            page += 1

    def firewall_alerts(self, limit: int = 200) -> list[dict]:
        """GET <dataRegion>/common/v1/alerts?product=firewall – offene Alerts (neueste zuerst)."""
        if not self.data_region:
            raise CentralError(tr('Daten-Region unbekannt – Central-Konto erneut prüfen'))
        body = self._call("GET", f"{self.data_region}/common/v1/alerts",
                          params={"product": "firewall", "sort": "raisedAt:desc", "pageSize": min(limit, 1000)})
        return body.get("items", [])

    # --- Konfiguration (Import/Export) -------------------------------------------------------------------

    def wait_transaction(self, transaction_id: str, log=None) -> dict:
        deadline = time.time() + config.CENTRAL_TRANSACTION_TIMEOUT
        last = ""
        while True:
            tx = self._cfg("GET", f"/firewalls/transactions/{transaction_id}")
            state = f"{tx.get('status')}/{tx.get('result')}"
            if log and state != last:
                log(f"Transaktion {transaction_id}: {state}")
                last = state
            if tx.get("status") == "finished":
                return tx
            if time.time() > deadline:
                raise CentralError(tr('Zeitüberschreitung beim Warten auf Transaktion {0}', transaction_id))
            time.sleep(config.CENTRAL_POLL_SECONDS)

    def export_config(self, firewall_id: str, entities: list[str] | None, log=None,
                      include_dependency: bool = False, wait_busy: bool = True) -> bytes:
        """wait_busy=False: bei einem bereits laufenden Export sofort mit CentralError abbrechen (is_busy)."""
        lock = export_lock(firewall_id)
        if not lock.acquire(blocking=wait_busy, timeout=config.CENTRAL_TRANSACTION_TIMEOUT if wait_busy else -1):
            e = CentralError(tr('Für diese Firewall läuft bereits ein Export dieses Tools'), status=409)
            e.busy = True
            raise e
        try:
            return self._export(firewall_id, entities, log, include_dependency, wait_busy)
        finally:
            lock.release()

    def _export(self, firewall_id: str, entities: list[str] | None, log, include_dependency: bool, wait_busy: bool) -> bytes:
        # fullExport=true verbietet exportEntities und includeDependency
        body = {"fullExport": True} if not entities else {
            "fullExport": False, "includeDependency": include_dependency, "exportEntities": entities}
        deadline = time.time() + config.CENTRAL_TRANSACTION_TIMEOUT
        waiting = False
        while True:
            try:
                ref = self._cfg("POST", f"/firewalls/{firewall_id}/export", json=body)
                break
            except CentralError as e:
                if not (wait_busy and is_busy(e)) or time.time() > deadline:
                    raise
                if log and not waiting:
                    log(tr('Für diese Firewall läuft bereits ein Export (z. B. aus Sophos Central) – warte …'))
                waiting = True
                time.sleep(max(config.CENTRAL_POLL_SECONDS, 5))
        tx = self.wait_transaction(ref["transactionId"], log)
        if tx.get("result") != "success":
            raise CentralError(tr('Export fehlgeschlagen: {0}', tx.get('result')))
        url = (tx.get("response") or {}).get("url")
        if not url:
            raise CentralError(tr('Export ohne Download-URL'))
        try:
            # Pre-signed URL: keine Central-Header mitsenden (S3 prüft die Signatur)
            r = self._http.get(url, timeout=config.HTTP_TIMEOUT_SECONDS * 4)
        except httpx.HTTPError as e:
            raise CentralError(tr('Download des Exports fehlgeschlagen: {0}', e)) from e
        if r.status_code != 200:
            raise CentralError(tr('Download des Exports fehlgeschlagen: HTTP {0}', r.status_code))
        return r.content

    def import_config(self, firewall_ids: list[str], archive: bytes, log=None) -> dict:
        if not 1 <= len(firewall_ids) <= 25:
            raise CentralError(tr('Import: 1 bis 25 Firewalls pro Vorgang'))
        init = self._cfg("POST", "/firewalls/import")
        tx_id, url = init["transactionId"], init["url"]
        if log:
            log(tr('Import-Transaktion {0} angelegt, lade Archiv hoch ({1} Byte)', tx_id, len(archive)))
        try:
            r = self._http.request(init.get("method", "PUT"), url, content=archive, headers=upload_headers(url),
                                   timeout=config.HTTP_TIMEOUT_SECONDS * 4)
        except httpx.HTTPError as e:
            raise CentralError(tr('Upload des Archivs fehlgeschlagen: {0}', e)) from e
        if r.status_code >= 300:
            raise CentralError(tr('Upload des Archivs fehlgeschlagen: HTTP {0} {1}', r.status_code, r.text[:200]))
        self._cfg("POST", f"/firewalls/import/{tx_id}/upload-complete", json={
            "firewallIds": firewall_ids,
            "checksumMd5": hashlib.md5(archive).hexdigest(),
            "fileSizeBytes": len(archive),
            # Nur vollständig erfolgreiche Importe zulassen (Standard wäre true = Teilimport)
            "performPartialImport": False,
        })
        return self.wait_transaction(tx_id, log)


    # --- MDR-Threat-Feed (asynchron: jede Anfrage liefert eine Transaktion je Firewall) ---------------------

    def wait_fw_transaction(self, firewall_id: str, transaction_id: str, log=None, timeout: int | None = None) -> dict:
        """GET /firewall-config/firewalls/{id}/transactions/{tx} bis status=finished."""
        deadline = time.time() + (timeout or config.CENTRAL_TRANSACTION_TIMEOUT)
        while True:
            tx = _normalize_fw_tx(self._cfg("GET", f"/firewalls/{firewall_id}/transactions/{transaction_id}",
                                             params={"fields": "request,response,expiryAt,finishedAt"}))
            if tx.get("status") == "finished":
                if log:
                    log(tr('Transaktion {0}: {1}', transaction_id, tx.get("result")))
                return tx
            if time.time() > deadline:
                raise CentralError(tr('Zeitüberschreitung beim Warten auf Transaktion {0}', transaction_id))
            time.sleep(config.CENTRAL_POLL_SECONDS)

    def _mdr(self, method: str, firewall_id: str, suffix: str = "", log=None, timeout: int | None = None,
             accept: tuple[int, ...] = (), **kw) -> dict:
        """accept: HTTP-Status der Firewall (response.statuscode), die das Ziel bereits erfüllen – z. B. 409
        „All entries already exist“ beim Anlegen. Solche Transaktionen gelten als Erfolg (result = „unchanged“)."""
        ref = self._cfg(method, f"/firewalls/{firewall_id}/mdr-threat-feed{suffix}", **kw)
        tx = self.wait_fw_transaction(firewall_id, ref["transactionId"], log, timeout)
        if tx.get("result") not in ("success", "partialSuccess"):
            if _status_code(tx) in accept:
                return {**tx, "result": "unchanged"}
            raise CentralError(tr('MDR-Threat-Feed: {0}', _tx_error(tx)), status=_status_code(tx))
        return tx

    def mdr_feed(self, firewall_id: str, log=None) -> dict:
        """Einstellungen des Feeds: {enabled, action: logOnly|logAndDrop, lastUpdatedAt}."""
        return self._mdr("GET", firewall_id, log=log, timeout=config.MDR_READ_TIMEOUT).get("response") or {}

    def mdr_settings(self, firewall_id: str, enabled: bool | None = None, action: str | None = None, log=None) -> dict:
        body = {k: v for k, v in (("enabled", enabled), ("action", action)) if v is not None}
        return self._mdr("PATCH", firewall_id, "/settings", log=log, json=body)

    def mdr_add(self, firewall_id: str, indicators: list[dict], log=None) -> dict:
        """Höchstens 100 Indikatoren {type: ipv4-addr|domain-name|url, value} pro Aufruf."""
        return self._mdr("POST", firewall_id, "/indicators", log=log, accept=(409,), json={"indicators": indicators})

    def mdr_delete(self, firewall_id: str, indicators: list[dict], log=None) -> dict:
        return self._mdr("POST", firewall_id, "/indicators/delete", log=log, accept=(404,), json={"indicators": indicators})

    def mdr_delete_all(self, firewall_id: str, log=None) -> dict:
        return self._mdr("DELETE", firewall_id, "/indicators", log=log)

    def mdr_search(self, firewall_id: str, values: list[str], log=None) -> dict:
        """Welche der (höchstens 100) Werte sind im Feed vorhanden? Antwort in tx.response."""
        return self._mdr("POST", firewall_id, "/indicators/search", log=log, timeout=config.MDR_READ_TIMEOUT,
                         json={"indicatorValues": values})


# Werte der mitsignierten Header beim S3-Upload (echte API eu02, 09/2026: SignedHeaders =
# content-type;host;if-none-match;x-amz-server-side-encryption). Weder Spezifikation noch Leitfaden nennen sie
# vollständig; ermittelt per Test-Upload ohne upload-complete.
S3_UPLOAD_HEADERS = {"content-type": "application/x-tar", "if-none-match": "*", "x-amz-server-side-encryption": "AES256"}


def upload_headers(url: str) -> dict:
    """Genau die Header senden, die die pre-signed URL als signiert ausweist – nicht mitsignierte Header
    ließen die Signaturprüfung ebenso scheitern wie fehlende."""
    from urllib.parse import parse_qs, urlsplit
    signed = (parse_qs(urlsplit(url).query).get("X-Amz-SignedHeaders") or [""])[0].lower().split(";")
    return {k: v for k, v in S3_UPLOAD_HEADERS.items() if k in signed}


def _normalize_fw_tx(tx: dict) -> dict:
    """Die echte API (eu02, 09/2026) liefert bei MDR-Transaktionen status/result = null, aber finishedAt und das
    Ergebnis der Firewall als response.statuscode. Auf die Werte der Spezifikation abbilden."""
    tx = dict(tx)
    if tx.get("status") is None and tx.get("finishedAt"):
        tx["status"] = "finished"
    if tx.get("status") == "finished" and tx.get("result") in (None, "notAvailable"):
        code = (tx.get("response") or {}).get("statuscode")
        try:
            code = int(code)
        except (TypeError, ValueError):
            code = None
        errors = (tx.get("response") or {}).get("errors")
        tx["result"] = ("error" if code is not None and code >= 400
                        else "partialSuccess" if errors else "success")
    return tx


def _status_code(tx: dict) -> int | None:
    try:
        return int((tx.get("response") or {}).get("statuscode"))
    except (TypeError, ValueError):
        return None


def _tx_error(tx: dict) -> str:
    resp = tx.get("response") or {}
    parts = [resp.get("statusmessage") or resp.get("message"), resp.get("error"), resp.get("errors"),
             f"HTTP {resp['statuscode']}" if resp.get("statuscode") else None]
    return " – ".join(str(p) for p in parts if p) or str(tx.get("result"))


def normalize_status(status: dict | None) -> dict:
    """Spezifikation: managingStatus/reportingStatus; Leitfaden: managing/reporting – beides akzeptieren."""
    status = dict(status or {})
    for spec, guide in (("managingStatus", "managing"), ("reportingStatus", "reporting")):
        if spec in status and guide not in status:
            status[guide] = status[spec]
    return status


def _msg(r: httpx.Response) -> str:
    try:
        body = r.json()
        return body.get("message") or body.get("error_description") or body.get("error") or r.text[:300]
    except ValueError:
        return r.text[:300]
