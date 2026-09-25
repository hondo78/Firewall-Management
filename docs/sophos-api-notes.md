# Sophos-APIs: Abweichungen und nicht dokumentierte Punkte

## SFOS REST-API (lokal auf der Firewall)

Doku: <https://docs.sophos.com/nsg/sophos-firewall/rest-api/>. Eine herunterladbare Spezifikation gibt es dort
nicht. Die Referenzseiten enthalten die OpenAPI-Daten aber komprimiert (docusaurus-openapi, `api:"eJ…"` = base64+zlib)
in den JS-Chunks. Daraus zusammengesetzt: `docs/sfos-rest-openapi.json` (**709 Operationen auf 391 Pfaden**, Stand 25.09.2026).
Die Firewall selbst bietet unter *Administration › API access* ebenfalls einen Download `OpenAPI.yaml` an.

| Thema | Doku-Startseite | Spezifikation / echte Firewall |
|---|---|---|
| Basis-URL | `https://<fw>:<port>/firewall-config/v1` | `https://<fw>:<port>/api/firewall-config/v1` – nur diese antwortet (ohne `/api`: HTML-404, geprüft gegen SFOS am 25.09.2026) |
| Codebeispiele | `GET /webconsole/APIController` mit Bearer-Key | das ist die **alte XML-API**; die Beispiele sind falsch |
| Auth | `Authorization: Bearer <api-key>` | dito; ohne/mit falschem Key: `401 {"error":"unauthenticated","message":"Token missing or invalid."}` |

Abweichungen der echten Firewall (SFOS, 25.09.2026) von der Spezifikation:
- Ports in Diensten kommen als **Text** (`"destinationPort": "1719"`, `"sourcePort": "1:65535"`), nicht als `{from, to}`.
  Das Tool zeigt beide Varianten an und schreibt neue Ports im Format, das die Firewall liefert.
- Zusätzliche Felder: `ruleId` (Regeln; wird wie `id` nicht gespeichert) und `isInternal` (eingebaute Objekte –
  Löschen wird im Tool gesperrt).

Weitere Eigenschaften (aus der Spezifikation):
- Objekte werden per Name **oder** UUID adressiert (`/{idOrName}`). Listen sind seitenweise (`page`, `pageSize` Std. 50,
  `pageTotal`) → `{items, pages:{current,total,size,maxSize}}`. Filter: `nameContains`, `nameNotEquals`.
- Regeln (`/firewall/rules/ipv4|ipv6`, `/nat/rules/…`, `/sd-wan/routes/…`, `/tls-inspection/rules/ipv4`): Anlegen
  erfordert `position` (`top|bottom|after|before`) + `referenceItem.name`; `PATCH` kennt **keine** Position →
  Verschieben über `POST …/move`. Massenlöschung: `POST …/delete` mit `{items:[{name}|{id}]}`.
- Firewall-Regeln sind `oneOf` `ruleType: firewall | waf`. „Beliebig“ = `{"any": true}`, sonst z. B.
  `{"zones":[{"name":"LAN"}]}` bzw. `{"ipv4Addresses":[…], "ipv4Groups":[…], "fqdnAddresses":[…], …}`.
- Nur lesend: `id`, `createdAt`, `updatedAt` – das Tool speichert und sendet sie nicht.
- Fehlerformat: `{"error", "message", "code"}`; 409 bei Namenskonflikt bzw. Objekt in Verwendung.
- Rechte = Geräteprofil des Admins, der den Key erzeugt hat. Keys haben ein Ablaufdatum (in SFOS angezeigt).

Das Tool verwaltet davon: Firewall-Regeln IPv4/IPv6, NAT-Regeln IPv4, IPv4/IPv6-Adressen und -Gruppen, FQDN-Adressen
und -Gruppen, MAC-Adressen, Ländergruppen, Dienste, Dienstgruppen, Zonen, Zeitpläne (`app/sophos/entities.py`).

## Sophos Central (Firewall Management API)

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
