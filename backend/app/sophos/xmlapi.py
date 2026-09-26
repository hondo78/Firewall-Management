"""Client für die lokale XML-API einer Sophos Firewall (SFOS).

POST https://<firewall>:4444/webconsole/APIController, Formularfeld `reqxml`:
    <Request><Login><Username/><Password/></Login><Get|Set operation=…|Remove>…</…></Request>
Die Firewall muss die API aktiviert und die IP dieses Servers in der Allowlist haben
(Backup & firmware › API).
"""
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from xml.sax.saxutils import escape

import httpx

from .. import config
from . import xmlconv
from ..i18n import tr


class XmlApiError(Exception):
    pass


def normalize_base_url(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if not url:
        raise XmlApiError(tr('Keine API-Adresse hinterlegt'))
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.port is None and not parsed.path:
        url = f"{url}:4444"
    return url


class XmlApiClient:
    def __init__(self, base_url: str, username: str, password: str, verify_tls: bool = True):
        self.base_url = normalize_base_url(base_url)
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.api_version = ""

    def _login_xml(self) -> str:
        return (f"<Login><Username>{escape(self.username)}</Username>"
                f"<Password>{escape(self.password)}</Password></Login>")

    def request(self, body: str) -> ET.Element:
        reqxml = f"<Request>{self._login_xml()}{body}</Request>"
        try:
            with httpx.Client(verify=self.verify_tls, timeout=config.HTTP_TIMEOUT_SECONDS) as client:
                r = client.post(f"{self.base_url}/webconsole/APIController", data={"reqxml": reqxml})
        except httpx.HTTPError as e:
            raise XmlApiError(tr('Firewall nicht erreichbar: {0}', e)) from e
        if r.status_code != 200:
            raise XmlApiError(tr('HTTP {0} von der Firewall', r.status_code))
        try:
            root = ET.fromstring(r.content)
        except ET.ParseError as e:
            raise XmlApiError(tr('Ungültige XML-Antwort: {0}', e)) from e
        self.api_version = root.get("APIVersion", self.api_version)
        # Fehler auf Anfrage-Ebene, z. B. 534 „Api operations are not allowed from the requester IP address“
        top = root.find("Status")
        if top is not None and top.get("code") not in (None, "200", "216"):
            raise XmlApiError(f"{top.get('code')}: {(top.text or '').strip()}")
        login = root.findtext("Login/status") or ""
        if login and "success" not in login.lower():
            msg = tr('Anmeldung an der Firewall fehlgeschlagen: {0}', login)
            if "authentication failure" in login.lower():
                # Die Firewall nennt keinen Grund – typische Ursachen mitliefern
                msg += tr(' – Benutzer/Passwort prüfen. Das Konto muss ein lokaler Administrator sein (nicht AD/RADIUS), '
                          'ohne Einmal-Passwort (OTP) für die Web-Administration; den genauen Grund zeigt die Firewall '
                          'im Log-Viewer unter „Admin events“.')
            raise XmlApiError(msg)
        return root

    def test(self) -> str:
        self.request("")
        return self.api_version

    def get(self, entity: str) -> list[dict]:
        root = self.request(f"<Get><{entity}></{entity}></Get>")
        objects, _ = xmlconv.parse_objects(root, {entity})
        # Keine Objekte: Sophos liefert <Entity><Status code="…">No. of records Zero.</Status></Entity>
        return objects.get(entity, [])

    def get_many(self, entities: list[str]) -> dict[str, list[dict]]:
        body = "".join(f"<{e}></{e}>" for e in entities)
        root = self.request(f"<Get>{body}</Get>")
        objects, _ = xmlconv.parse_objects(root, set(entities))
        return {e: objects.get(e, []) for e in entities}

    def _check(self, root: ET.Element, entity: str) -> str:
        el = root.find(entity)
        status = el.find("Status") if el is not None else None
        if status is None:
            raise XmlApiError(tr('Keine Statusmeldung für {0} in der Antwort', entity))
        code, text = status.get("code", ""), (status.text or "").strip()
        if code != "200":
            raise XmlApiError(f"{code}: {text}")
        return text

    def set(self, entity: str, data: dict, operation: str, position: dict | None = None) -> str:
        payload = xmlconv.with_position(data, position) if entity == "FirewallRule" else data
        xml = xmlconv.to_xml(entity, payload, transactionid=True, pretty=False)
        root = self.request(f'<Set operation="{operation}">{xml}</Set>')
        return self._check(root, entity)

    def remove(self, entity: str, name: str) -> str:
        root = self.request(f"<Remove><{entity}><Name>{escape(name)}</Name></{entity}></Remove>")
        return self._check(root, entity)


def request_preview(entity: str, action: str, data: dict | None, name: str, position: dict | None) -> str:
    """Das XML, das für eine Operation an die Firewall geht (ohne Login) – zur Anzeige im Antrag."""
    if action == "remove":
        return f"<Remove>\n  <{entity}>\n    <Name>{escape(name)}</Name>\n  </{entity}>\n</Remove>"
    payload = xmlconv.with_position(data or {}, position) if entity == "FirewallRule" else (data or {})
    inner = xmlconv.to_xml(entity, payload, transactionid=True)
    inner = "\n".join("  " + line for line in inner.splitlines())
    op = "add" if action == "add" else "update"
    return f'<Set operation="{op}">\n{inner}\n</Set>'
