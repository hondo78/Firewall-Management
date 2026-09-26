# Firewall-Management (Sophos)

Web-Anwendung zur Verwaltung von Sophos Firewalls mit Rollen & Rechten, **Vier-Augen-Prinzip** für jede
Konfigurationsänderung und lückenlosem, manipulationssicherem Audit-Log. UI: **http://<host>:8096**

## Funktionen

- **Anbindung über REST-APIs**
  - **SFOS REST-API** (empfohlen, `https://<fw>:4444/api/firewall-config/v1`, API-Key per Bearer-Token):
    direktes Anlegen/Ändern/Verschieben/Löschen von Regeln und Objekten, Rechte über das Admin-Profil des Keys,
    Warnung vor Ablauf des Keys.
  - **Sophos Central – Firewall Management API** (`/firewall/v1`): Inventar (Firewalls, Gruppen, Status),
    Firmware-Updates, Konfiguration lesen/schreiben über **Export/Import** (Archiv mit `Entities.xml`).
    Löschen ist über den Import nicht möglich.
    Zusätzlich Lizenzen (Licensing API) und offene Alerts (Common API) je Firewall.
  - **Alte XML-API der Firewall** (`/webconsole/APIController`, Benutzer/Passwort): nur noch für Firmware ohne
    REST-API.
- **Konfigurationsansicht im Stil des Sophos Config Studio**: Navigator nach Bereichen (Regeln, Hosts & Dienste,
  Netzwerk, System, Richtlinien, Benutzer & Schnittstellen), Regeltabelle wie in SFOS mit Sicherheits-Spalte
  (Web/App/IPS/AV/…) und aufklappbaren Details, NAT-Tabelle Original → Übersetzt. Formulare wie auf der Firewall
  für Firewall-/NAT-Regeln (inkl. Web-Filter, IPS, Anwendungskontrolle, Heartbeat, QoS, Benutzer, Ausnahmen),
  Web-/Anwendungs-/IPS-/Traffic-Shaping-Richtlinien, Zonen (Gerätezugriff), Zeitpläne und alle Adress-/Dienst-Objekte.
  Regelliste und „Firewall-Regel bearbeiten“ im Aufbau der SFOS-Weboberfläche (Reiter, Ziehen zum Umsortieren,
  Zeilenmenü, Seiten-Editor mit festem Speichern-Fuß).
  JSON (REST) bzw. XML bleibt als zweite Option „Experte“; Export als JSON bzw. `Entities.xml` (Config Studio).
- **Änderungsanträge (Vier-Augen-Prinzip)**: Änderungen landen in einem Entwurf (Vorschau direkt in der Tabelle),
  werden mit Titel, Begründung, Ticket und optionalem Wartungsfenster eingereicht und müssen von 1–3 *anderen*
  Personen genehmigt werden. Ablehnung nur mit Begründung. Danach automatisches oder manuelles Ausrollen.
- **Sicheres Ausrollen**: Vor dem Anwenden wird der Ist-Stand der Firewall mit dem Stand beim Einreichen verglichen
  (Drift-Prüfung → Status *Konflikt*). XML-API: bei Fehlern werden bereits angewendete Schritte zurückgerollt.
  „Rückgängig machen“ erzeugt einen Gegen-Antrag.
- **Rollen & Rechte**: frei definierbare Rollen aus Einzelrechten, pro Benutzer global oder je Firewall-Gruppe
  zugewiesen (z. B. „Firewall-Administrator“ für Filialen, „Betrachter“ für die Zentrale). Die Verbindungs-
  einstellungen einer Firewall (Adresse, API-Key/Passwort, TLS, Anbindung) und die Sophos-Central-Konten sieht
  und ändert nur ein Superadmin; im Audit-Log sind diese Angaben für alle anderen geschwärzt.
- **Dokumentation**: Audit-Log mit SHA-256-Hash-Kette (Integritätsprüfung, CSV-Export, optional Syslog),
  Verlauf/Kommentare je Antrag, Ausroll-Protokoll mit dem gesendeten XML, Versionsstände der Konfiguration
  inkl. Vergleich (auch zwischen Firewalls) und Erkennung von Änderungen außerhalb des Tools.
- **WAF-Regeln (Webserver-Schutz)**: vollständig wie in SFOS (gehosteter Server, Domänen, Traffic Routing, Ausnahmen,
  Schutz/IPS/Traffic-Shaping, Zusatzoptionen) – über einen optionalen zusätzlichen XML-API-Zugang, weil die REST-API
  WAF-Regeln nicht vollständig liefert. Webserver und WAF-Schutzrichtlinien per REST mit eigenen Formularen.
- **Sicherungen**: automatische Sicherung der Konfiguration aller Firewalls nach Zeitplan (täglich/wöchentlich/monatlich,
  Aufbewahrung, Anheften, optional zusätzlich als Datei in `backups/`), manuell „Jetzt sichern“, Download (JSON bzw.
  Entities.xml), Vergleich mit dem aktuellen Stand und Wiederherstellen über einen Entwurf (Vier-Augen-Freigabe).
  Zusätzlich lässt sich der eingebaute SFOS-Sicherungszeitplan (Ziel lokal/FTP/E-Mail) per Antrag ändern.
- **Befristete Änderungen**: Antrag mit „gültig bis“ – danach legt das System automatisch die Rücknahme an
  (wahlweise vorab genehmigt, weil die Befristung Teil der Freigabe war). Rücknahme ausgerollter Anträge auch durch
  Approver/Superadmins, stets mit Vier-Augen-Freigabe.
- **Sammelanträge & Vorlagen**: dieselbe Änderung auf mehreren Firewalls (einmal genehmigen, je Firewall ausrollen),
  wiederverwendbare Vorlagen, Abgleich einer Gruppe gegen eine Referenz-Firewall.
- **Regel-Prüfung**: Any-Any, offen aus dem Internet, verdeckte/redundante Regeln, fehlende Protokollierung,
  ungenutzte/doppelte Objekte – beim Einreichen, für den Approver und als Tab „Analyse“.
- **Benachrichtigungen**: E-Mail, Microsoft Teams, Slack (Incoming Webhook, optional @here bei neuen Anträgen), Telegram (mit Genehmigen-Knopf) für neue Anträge, Entscheidungen,
  Ausrollen/Fehler, ablaufende Befristungen und API-Keys sowie Änderungen außerhalb des Tools.
- **Anmeldung**: Zwei-Faktor (TOTP) wahlweise verpflichtend, SSO per OpenID Connect (Entra ID, Authentik, Keycloak …)
  mit Rollen aus Gruppen, erneute Anmeldung vor dem Genehmigen.
- **Probelauf**: prüft Anmeldung, Rechte und alle benötigten Endpunkte mit rein lesenden Aufrufen, für
  Central-Konten und einzelne Firewalls. Abweichungen zwischen Sophos-Leitfaden und OpenAPI-Spezifikation sowie
  die Suche nach nicht dokumentierten Endpunkten: siehe `docs/sophos-api-notes.md`.

## Sprachen

Oberfläche auf **Deutsch und Englisch** (Umschalter in der Navigation und auf der Anmeldeseite; Standard =
Browsersprache). Weitere Sprachen: eine Wörterbuch-Datei ergänzen – siehe `frontend/tools/README-i18n.md`.

## Start

```bash
cp .env.example .env    # Werte erzeugen (siehe Kommentare), chmod 600 .env
docker compose up -d --build
```

Anmeldung mit `ADMIN_USERNAME` / `ADMIN_PASSWORD` (nur beim ersten Start verwendet).

### Demo mit der Sophos-Attrappe

`COMPOSE_PROFILES=mock` (Standard in `.env.example`) startet `sophos-mock`, das Sophos Central und die
XML-API von vier Demo-Firewalls nachbildet:

- Sophos Central: *Administration › Sophos Central › Konto verbinden*, Client-ID `mock-client`,
  Secret `mock-secret`, unter „Erweitert“ beide URLs auf `http://sophos-mock:8000` → „Firewalls übernehmen“.
- REST-API: *Firewalls › Firewall hinzufügen*, Anbindung „SFOS REST-API“, Adresse
  `http://sophos-mock:8000/fw/X21002ZENTRALE1` (oder eine andere Seriennummer), API-Key `sfos_mock_key`.
- XML-API (alt): Adresse `http://sophos-mock:8000/fw/C0100LABOR00001`, Benutzer `apiadmin`, Passwort `mock-password`.
- Drift simulieren: `docker compose exec backend python -c "import httpx; httpx.post('http://sophos-mock:8000/mock/fw/<SERIAL>/tamper')"`

Für den Produktivbetrieb `COMPOSE_PROFILES=` leeren (Stand dieser Installation: Attrappe ist aus,
Demo-Benutzer und Demo-Firewalls sind deaktiviert bzw. entfernt). Wieder einschalten:
`COMPOSE_PROFILES=mock docker compose up -d sophos-mock`.

### Echte Firewalls

Vor dem ersten Antrag den **Probelauf** ausführen (Sophos Central: Administration › Sophos Central ›
„Probelauf & Endpunkt-Prüfung“, XML-API: Firewall › Einstellungen › Probelauf). Er ändert nichts.

- **Sophos Central**: Service Principal unter *Globale Einstellungen › API-Anmeldeinformationen* anlegen.
  Partner-/Organisationskonten: Tenant nach dem Speichern auswählen.
- **REST-API** (empfohlen): auf der Firewall unter *Administration › API access* die IP dieses Servers erlauben.
  Einen eigenen API-Administrator mit passendem Geräteprofil (Lesen/Schreiben für Firewall-Regeln und Objekte)
  anlegen, damit einen API-Key erzeugen und ihn samt Ablaufdatum unter *Firewall › Einstellungen* eintragen.
  Der Key hat genau die Rechte dieses Administrators.
- **XML-API** (alt): auf der Firewall *Backup & firmware › API* aktivieren, die IP dieses Servers erlauben und einen
  eigenen API-Administrator verwenden.
