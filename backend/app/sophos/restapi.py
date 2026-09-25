"""Client für die SFOS REST-API („Firewall Configuration API“, OpenAPI 3.0, docs.sophos.com/nsg/sophos-firewall/rest-api).

Basis:  https://<firewall>:<admin-port>/api/firewall-config/v1   (Admin-Port meist 4444)
Auth:   Authorization: Bearer <api-key>   – Key unter Administration › API access erzeugen; Rechte = Profil des Admins
Objekte werden über Namen oder UUID adressiert (`/{idOrName}`). Listen sind seitenweise
(`page`, `pageSize`, `pageTotal` → `items`, `pages`). Regeln haben eine Reihenfolge: Anlegen mit `position`
(`top|bottom|after|before`) + `referenceItem.name`, Verschieben per `POST …/move`.

Achtung: Die Einstiegsseite der Doku nennt `/firewall-config/v1` – die Firewall antwortet dort mit 404.
Maßgeblich ist die Spezifikation (`/api/firewall-config/v1`); der Client fällt bei HTML-404 auf die andere Variante
zurück und merkt sich die funktionierende.
"""
from urllib.parse import quote, urlparse

import httpx

from .. import config

API_PREFIXES = ("/api/firewall-config/v1", "/firewall-config/v1")
_PREFIX_BY_BASE: dict[str, str] = {}
PAGE_SIZE = 100
FALLBACK_PAGE_SIZES = (50, 25, 10)
_PAGE_SIZES: dict[str, int] = {}  # je Pfad gelernte Seitengröße (Prozess-Laufzeit)


class RestApiError(Exception):
    def __init__(self, message: str, status: int | None = None, code: str = ""):
        super().__init__(message)
        self.status = status
        self.code = code


def normalize_base_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if not url:
        raise RestApiError("Keine API-Adresse hinterlegt")
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.port is None and not parsed.path:
        url = f"{url}:4444"
    return url


def quote_name(name: str) -> str:
    return quote(name, safe="")


class RestApiClient:
    def __init__(self, base_url: str, api_key: str, verify_tls: bool = True,
                 transport: httpx.BaseTransport | None = None):
        self.base_url = normalize_base_url(base_url)
        self.api_key = api_key
        kw = {"verify": verify_tls, "timeout": config.HTTP_TIMEOUT_SECONDS}
        self._http = httpx.Client(transport=transport, **kw) if transport else httpx.Client(**kw)

    # --- HTTP-Grundlagen ---------------------------------------------------------------------------------

    def _send(self, method: str, url: str, **kw) -> httpx.Response:
        if not self.api_key:
            raise RestApiError("Kein API-Key hinterlegt")
        headers = {"Authorization": f"Bearer {self.api_key}", "Accept": "application/json"}
        try:
            return self._http.request(method, url, headers=headers, **kw)
        except httpx.HTTPError as e:
            raise RestApiError(f"Firewall nicht erreichbar: {e}") from e

    def request(self, method: str, path: str, *, json=None, params: dict | None = None):
        known = _PREFIX_BY_BASE.get(self.base_url)
        prefixes = [known] if known else list(API_PREFIXES)
        last: httpx.Response | None = None
        for prefix in prefixes:
            r = self._send(method, f"{self.base_url}{prefix}{path}", json=json, params=params)
            # HTML-404 = Route/Präfix unbekannt; JSON-404 = Objekt nicht gefunden (Präfix stimmt)
            if r.status_code == 404 and "json" not in r.headers.get("content-type", "") and not known:
                last = r
                continue
            _PREFIX_BY_BASE[self.base_url] = prefix
            return self._result(method, path, r)
        return self._result(method, path, last)

    @staticmethod
    def _result(method: str, path: str, r: httpx.Response):
        if r.status_code >= 400:
            code, msg = "", r.text[:300]
            try:
                body = r.json()
                code = body.get("code") or body.get("error") or ""
                msg = body.get("message") or body.get("error") or msg
            except ValueError:
                pass
            hint = {401: " – API-Key ungültig oder abgelaufen",
                    403: " – das Admin-Profil des Keys erlaubt diese Aktion nicht oder IP nicht freigegeben"}
            raise RestApiError(f"{method} {path} → HTTP {r.status_code}: {msg}{hint.get(r.status_code, '')}",
                               status=r.status_code, code=code)
        if not r.content:
            return {}
        try:
            return r.json()
        except ValueError:
            raise RestApiError(f"{method} {path}: keine JSON-Antwort (HTTP {r.status_code})", status=r.status_code)

    # --- Objekte -----------------------------------------------------------------------------------------

    def list(self, path: str) -> list[dict]:
        size = _PAGE_SIZES.get(path, PAGE_SIZE)
        items, page = [], 1
        while True:
            try:
                body = self.request("GET", path, params={"page": page, "pageSize": size, "pageTotal": "true"})
            except RestApiError as e:
                # Manche Endpunkte (z. B. /application/policies) erlauben nur kleinere Seiten als dokumentiert:
                # SFOS antwortet dann mit 400 „Invalid page size“ → kleinere Seitengröße, von vorn beginnen
                smaller = [x for x in FALLBACK_PAGE_SIZES if x < size]
                if e.status == 400 and "page size" in str(e).lower() and smaller:
                    size = _PAGE_SIZES[path] = smaller[0]
                    items, page = [], 1
                    continue
                raise
            batch = body.get("items") or []
            items += batch
            pages = body.get("pages") or {}
            total = pages.get("total")
            if not batch or (total is not None and page >= int(total)) or (
                    total is None and len(batch) < int(pages.get("size") or size)):
                return items
            page += 1

    def get(self, path: str, name: str) -> dict:
        return self.request("GET", f"{path}/{quote_name(name)}")

    def create(self, path: str, body: dict) -> dict:
        return self.request("POST", path, json=body)

    def update(self, path: str, name: str, body: dict) -> dict:
        return self.request("PATCH", f"{path}/{quote_name(name)}", json=body)

    def delete(self, path: str, name: str) -> dict:
        return self.request("DELETE", f"{path}/{quote_name(name)}")

    def move(self, path: str, name: str, position: dict) -> dict:
        return self.request("POST", f"{path}/move", json={"name": name, **position_body(position)})

    def test(self) -> dict:
        """Günstiger Aufruf zum Prüfen von Adresse, Freigabe und Key."""
        return self.request("GET", "/network/zones", params={"page": 1, "pageSize": 1})

    @property
    def prefix(self) -> str:
        return _PREFIX_BY_BASE.get(self.base_url, API_PREFIXES[0])


def position_body(position: dict | None) -> dict:
    """{"type": "after", "ref": "X"} → {"position": "after", "referenceItem": {"name": "X"}}"""
    position = position or {"type": "bottom"}
    kind = position.get("type") or "bottom"
    if kind in ("after", "before") and position.get("ref"):
        return {"position": kind, "referenceItem": {"name": position["ref"]}}
    return {"position": "top" if kind == "top" else "bottom"}


def request_preview(path: str, action: str, data: dict | None, name: str, position: dict | None,
                    before: dict | None = None, is_rule: bool = False) -> str:
    """HTTP-Aufrufe, die für eine Operation an die Firewall gehen (ohne Key) – zur Anzeige im Antrag."""
    import json as _json
    base = "/api/firewall-config/v1" + path

    def dump(v) -> str:
        return _json.dumps(v, indent=2, ensure_ascii=False)
    if action == "remove":
        return f"DELETE {base}/{quote_name(name)}"
    if action == "add":
        body = dict(data or {})
        if is_rule:
            body.update(position_body(position))
        return f"POST {base}\n{dump(body)}"
    body = patch_body(before, data)
    lines = [f"PATCH {base}/{quote_name(name)}\n{dump(body)}"] if body else []
    if is_rule and position:
        lines.append(f"POST {base}/move\n{dump({'name': name, **position_body(position)})}")
    return "\n\n".join(lines) or "(keine Änderung)"


def patch_body(before: dict | None, after: dict | None) -> dict:
    """Nur geänderte Felder der obersten Ebene (PATCH-Semantik)."""
    before, after = before or {}, after or {}
    body = {k: v for k, v in after.items() if before.get(k) != v}
    # Entfernte Textfelder (z. B. Beschreibung) leeren – andere Felder lassen sich per PATCH nicht entfernen
    body.update({k: "" for k, v in before.items() if k not in after and isinstance(v, str)})
    return body
