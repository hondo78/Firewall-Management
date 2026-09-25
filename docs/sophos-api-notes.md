# Sophos-API: Abweichungen und nicht dokumentierte Punkte

Stand: 25.09.2026. Verglichen wurden der Leitfaden <https://developer.sophos.com/firewall-management/> und die
OpenAPI-Spezifikation `https://developer.sophos.com/assets/specs/firewall-v1.yaml` (Version 1.5.0), die hinter
der API-Referenz (`/reference/firewall-v1/`) liegt. Weitere Spezifikationen unter `assets/specs/<name>.yaml`
(z. B. `licensing-v1`, `common-v1`, `audit-events-v1`, `partner-v1`, `organization-v1`, `whoami-v1`).

## Leitfaden ≠ Spezifikation

| Thema | Leitfaden | Spezifikation (maßgeblich) | Umsetzung |
|---|---|---|---|
| Export | `POST /firewalls/{id}/export` | `POST /firewall/v1/firewall-config/firewalls/{id}/export` | Spezifikation, bei 404 Rückfall auf Leitfaden (je Region gemerkt) |
| Import starten | `POST /firewalls/import` | `POST …/firewall-config/firewalls/import` | dito |
| Upload abschließen | `POST /firewalls/import/{tx}/upload-complete` | `POST …/firewall-config/firewalls/import/{tx}/upload-complete` | dito |
| Transaktion (Import/Export) | `GET /firewalls/transactions/{tx}` | `GET …/firewall-config/firewalls/transactions/{tx}` | dito |
| MDR-Threat-Feed / Transaktion je Firewall | `/firewalls/{id}/mdr-threat-feed…` | `/firewall-config/firewalls/{id}/mdr-threat-feed…` | nicht genutzt |
| Firewall-Status | `status.managing`, `status.reporting` | `status.managingStatus` (`approvedByCustomer`, `approvalPending`, …), `status.reportingStatus` | beide Varianten werden gelesen |
| Zeitstempel Statuswechsel | `statusChangedAt` | `stateChangedAt` | nur Anzeige |
| HTTP-Status Export/Import | 200/201 | 202 (Accepted), upload-complete 200 | jeder 2xx wird akzeptiert |

## In der Spezifikation, aber nicht im Leitfaden

- `GET /firewalls`: Query-Parameter `groupId` und `search`.
- `GET /firewall-groups`: `recurseSubgroups`, `search`, `searchFields`. Gruppen sind verschachtelbar (`parentGroup`).
  Das Tool übernimmt Untergruppen als „Eltern › Kind“.
- `upload-complete`: `firewallIds` max. **25** pro Import; `performPartialImport` ist standardmäßig **true**
  (das Tool setzt `false`, damit ein Antrag ganz oder gar nicht angewendet wird); `secureMasterKey`
  (max. 128 Zeichen) ist nötig, damit verschlüsselte Werte (Passwörter, Schlüssel) importiert werden.
- Import/Export akzeptieren zusätzlich den Header `X-Partner-ID` (Partner-Ebene).
- Der Upload geht laut Beschreibung an **Amazon S3** (pre-signed PUT). Zusätzliche Header wie `Content-Type`
  dürfen nicht gesendet werden, wenn sie nicht mitsigniert wurden; das Tool sendet den reinen Body.
- Benötigte Central-Rechte (`x-soph-permissions`): Lesen `fwcm.firewall.group:read`, Import/Export
  `fwcm.firewall.api.config:write`, Transaktionen `fwcm.firewall.api.config:read`.
- `configImport.status` einer Gruppe kennt `initializing`, `initializingFailed`, `initializingFailedExport`,
  `uploaded`, `uploadFailed`, `downloadFailed`, `processing`, `failed`, `success`.

## Firewall-relevant in anderen Central-APIs

- **Lizenzen**: `GET https://api.central.sophos.com/licenses/v1/licenses/firewalls` (global, nicht regional):
  je Seriennummer Lizenzen mit Laufzeit. Anzeige im Tab „Lizenzen & Alerts“.
- **Alerts**: `GET <dataRegion>/common/v1/alerts?product=firewall` (Typ `xgFirewall` in `managedAgent`).
  Anzeige im Tab „Lizenzen & Alerts“.
- **Audit-Events**: `GET https://api.central.sophos.com/audit/v1/audit-events` (Admin-Aktionen in Central).
  Noch nicht angebunden.

## Nicht dokumentierte Endpunkte

Die Spezifikation enthält genau die 23 Firewall-Operationen des Leitfadens (nur unter anderen Pfaden). Weitere
Endpunkte lassen sich nur gegen ein echtes Konto ermitteln. Der **Probelauf** (Administration › Sophos Central
› „Probelauf & Endpunkt-Prüfung“) testet ausschließlich lesend:

- welche Pfad-Variante für Transaktionen die API kennt (Spezifikation vs. Leitfaden),
- naheliegende, nicht dokumentierte GET-Endpunkte: `GET /firewalls/{id}`, `GET /firewall-groups/{id}`,
  `GET /firewall-config/firewalls/{id}/transactions`, `GET /firewall-config/firewalls/{id}`.
  Das Ergebnis (200 = vorhanden, 405 = Route existiert ohne GET, 404 = nicht vorhanden) landet im Audit-Log.
