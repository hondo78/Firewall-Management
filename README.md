# Firewall-Management (Sophos)

Web-Anwendung zur Verwaltung von Sophos Firewalls mit Rollen & Rechten, **Vier-Augen-Prinzip** für jede
Konfigurationsänderung und lückenlosem, manipulationssicherem Audit-Log. UI: **http://<host>:8096**

## Funktionen

- **Anbindung über REST-APIs**
  - **Sophos Central – Firewall Management API** (`/firewall/v1`): Inventar (Firewalls, Gruppen, Status),
    Firmware-Updates, Konfiguration lesen/schreiben über **Export/Import** (Archiv mit `Entities.xml`).
    Löschen ist über den Import nicht möglich.
    Zusätzlich Lizenzen (Licensing API) und offene Alerts (Common API) je Firewall.
  - **Lokale XML-API der Firewall** (`https://<fw>:4444/webconsole/APIController`): vollständiges
    Anlegen/Ändern/Löschen, auch für Firewalls ohne Sophos Central.
- **Konfigurationsansicht im Stil des Sophos Config Studio**: Navigator nach Bereichen (Regeln, Hosts & Dienste,
  Netzwerk, System), Regeltabelle wie in SFOS, Formular-Editoren für Regeln, IP-Hosts, Dienste, Gruppen und ein
  XML-Experteneditor für alle Objekte; Download als `Entities.xml` (öffnet im Config Studio).
- **Änderungsanträge (Vier-Augen-Prinzip)**: Änderungen landen in einem Entwurf (Vorschau direkt in der Tabelle),
  werden mit Titel, Begründung, Ticket und optionalem Wartungsfenster eingereicht und müssen von 1–3 *anderen*
  Personen genehmigt werden. Ablehnung nur mit Begründung. Danach automatisches oder manuelles Ausrollen.
- **Sicheres Ausrollen**: Vor dem Anwenden wird der Ist-Stand der Firewall mit dem Stand beim Einreichen verglichen
  (Drift-Prüfung → Status *Konflikt*). XML-API: bei Fehlern werden bereits angewendete Schritte zurückgerollt.
  „Rückgängig machen“ erzeugt einen Gegen-Antrag.
- **Rollen & Rechte**: frei definierbare Rollen aus Einzelrechten, pro Benutzer global oder je Firewall-Gruppe
  zugewiesen (z. B. „Firewall-Administrator“ für Filialen, „Betrachter“ für die Zentrale).
- **Dokumentation**: Audit-Log mit SHA-256-Hash-Kette (Integritätsprüfung, CSV-Export, optional Syslog),
  Verlauf/Kommentare je Antrag, Ausroll-Protokoll mit dem gesendeten XML, Versionsstände der Konfiguration
  inkl. Vergleich (auch zwischen Firewalls) und Erkennung von Änderungen außerhalb des Tools.
- **Probelauf**: prüft Anmeldung, Rechte und alle benötigten Endpunkte mit rein lesenden Aufrufen, für
  Central-Konten und einzelne Firewalls. Abweichungen zwischen Sophos-Leitfaden und OpenAPI-Spezifikation sowie
  die Suche nach nicht dokumentierten Endpunkten: siehe `docs/sophos-api-notes.md`.

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
- XML-API: *Firewalls › Firewall hinzufügen*, Adresse `http://sophos-mock:8000/fw/C0100LABOR00001`,
  Benutzer `apiadmin`, Passwort `mock-password`, TLS-Prüfung aus.
- Drift simulieren: `docker compose exec backend python -c "import httpx; httpx.post('http://sophos-mock:8000/mock/fw/<SERIAL>/tamper')"`

Für den Produktivbetrieb `COMPOSE_PROFILES=` leeren (Stand dieser Installation: Attrappe ist aus,
Demo-Benutzer und Demo-Firewalls sind deaktiviert bzw. entfernt). Wieder einschalten:
`COMPOSE_PROFILES=mock docker compose up -d sophos-mock`.

### Echte Firewalls

Vor dem ersten Antrag den **Probelauf** ausführen (Sophos Central: Administration › Sophos Central ›
„Probelauf & Endpunkt-Prüfung“, XML-API: Firewall › Einstellungen › Probelauf). Er ändert nichts.

- **Sophos Central**: Service Principal unter *Globale Einstellungen › API-Anmeldeinformationen* anlegen.
  Partner-/Organisationskonten: Tenant nach dem Speichern auswählen.
- **XML-API**: auf der Firewall *Backup & firmware › API* aktivieren, die IP dieses Servers erlauben und einen
  eigenen API-Administrator verwenden.
