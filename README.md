# Firewall Management (Sophos)

[Deutsche Version](README.de.md) · [Approval guide](docs/approval-guide.md) · [Demo video](docs/media/approval-demo.mp4) (2:55, subtitles, no sound)

A self-hosted web application for managing Sophos firewalls. Every configuration change goes through a
**four-eyes approval**, roles control who may do what, and a hash-chained audit log records every step.
It connects to firewalls through the SFOS REST API, the Sophos Central (Fusion) Firewall Management API or
the legacy XML API. The UI runs on **http://&lt;host&gt;:8096** and is available in English and German.

[![Demo: one change request from draft to audit log](docs/media/approval-demo-poster.jpg)](docs/media/approval-demo.mp4)

*Demo: a firewall administrator requests a change, two approvers review and approve it, it is deployed with a
drift check, and an auditor verifies the hash chain. All people and firewalls are fictitious (Sophos mock).*

## Contents

- [How a change works](#how-a-change-works)
- [Features](#features)
- [Connecting firewalls](#connecting-firewalls)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Development](#development)
- [Further documentation](#further-documentation)

## How a change works

Nobody writes directly to a firewall. Changes are collected in a personal draft, submitted as a change request
and deployed through the API only after other people have approved them.

```
Draft ──submit──▶ Awaiting approval ──n × approve──▶ Approved ──deploy──▶ Deployed
                     │                                  │                   │
                     ├─▶ Rejected (comment required)    ├─▶ Failed ─▶ deploy again
                     └─▶ Withdrawn                      └─▶ Conflict ─▶ submit again on the current state
                                                                            └─▶ Revert … (new request)
```

- The requester can never approve their own request, whatever their role, superadmins included.
- The number of required approvals (1–3 distinct people) is fixed when the request is submitted.
- Approvers must re-authenticate if their sign-in is older than 30 minutes (configurable); two-factor
  authentication can be required. The same applies to approvals via Telegram: they count only within that time
  after a web sign-in that met the two-factor requirement.
- Before writing, the tool reads the firewall's live configuration. If the affected objects changed since
  submission, deployment stops with **Conflict** instead of overwriting someone else's change.
- If an API call fails, changes already written are rolled back.

The [approval guide](docs/approval-guide.md) walks through the whole flow with screenshots.

## Features

**Configuration editor in the style of Sophos Config Studio**
- Entity navigator (rules, hosts & services, network, system, policies, users & interfaces, web server
  protection, Sophos Central), global search, column picker, resizable columns.
- Rule list and "Edit firewall rule" laid out like the SFOS web UI: IPv4/IPv6 tabs, drag to reorder, security
  features column, row menu, page editor with a sticky save bar.
- Forms like on the firewall for firewall and NAT rules (web filter, IPS, application control, heartbeat, QoS,
  users, exclusions), web/application/IPS/traffic-shaping policies, zones with device access, schedules and all
  address and service objects. JSON (REST) or XML stays available as an expert mode.
- **WAF rules** (web server protection) in full: hosted server, domains, paths and web servers, exceptions,
  protection policy. The REST API does not return WAF rules completely, so these use an optional second XML API
  login on the same firewall.
- Bulk add in Config Studio formats, import of an `Entities.xml` or `.tar` into the draft, export as JSON or
  `Entities.xml`.

**Change workflow**
- Drafts with a live preview in the tables and the exact API calls that will be sent.
- Change requests with title, justification, ticket reference (optionally mandatory), earliest deployment time.
- **Temporary changes**: "Temporary until" creates an automatic revert when it expires (optionally pre-approved,
  because the expiry was part of the approval).
- **Batch requests**: the same change on several firewalls, approved once, deployed per firewall.
- **Templates**: maintain standard rules, objects and settings as a desired state, take them over from a firewall
  including dependencies, and roll them out with a per-firewall preview (create / align / already compliant).
  Rolling out always creates change requests.
- **Revert** creates a counter-request, which again needs approval by someone else.
- **Rule check** on submission and in the Analysis tab: any-any rules, open from the internet, shadowed or
  redundant rules, missing logging, unused or duplicate objects. Clicking a finding opens the object's form;
  the fix goes into the draft and is re-evaluated immediately.

**Sophos Central / Fusion** (Firewall Management API, all operations of spec 1.5.0)
- Import the inventory (firewalls, nested groups, status). Firewalls that are already connected directly
  (REST/XML) are linked by serial number instead of being added twice.
- Manage the inventory: rename, set location, approve management, remove from Central; create, edit and delete
  groups (optionally importing a firewall's configuration), sync status per group.
- **MDR threat feed**: feed settings and indicators (IPv4, domains, URLs) as objects in the editor, changed
  through approved change requests; search in Central.
- Firmware updates (check, schedule, cancel), licences and open alerts per firewall, export of selected object
  types with dependencies.

**Backups and history**
- Scheduled backups of every firewall's configuration (daily/weekly/monthly, retention, pinning, optional file
  copies), manual backups, download, compare with the current state, restore through a draft.
- A new version is stored whenever the configuration changes; compare any two versions or two firewalls.
- Changes made outside the tool are detected on the next synchronisation and logged.
- The SFOS built-in backup schedule can be changed through a change request.

**Security and compliance**
- Roles built from individual permissions, assigned globally or per firewall group.
- Connection settings (addresses, API keys, passwords, Central accounts) are visible and editable only by
  superadmins, and masked in the audit log for everyone else.
- Audit log with a SHA-256 hash chain, integrity check, filters, CSV export and optional syslog forwarding.
- Own login with lockout, TOTP two-factor authentication (optionally mandatory), SSO via OpenID Connect
  (Entra ID, Authentik, Keycloak …) with roles from groups.
- Secrets (API keys, passwords, Central client secrets, notification tokens) are encrypted with AES-GCM.

**Notifications**
- E-mail, Microsoft Teams, Slack and Telegram (with an Approve button) for new requests, decisions,
  deployments and failures, expiring temporary changes and API keys, and changes made outside the tool.
- Every recipient gets messages in their own language.

**Dry run**
- Checks sign-in, permissions and every endpoint the tool needs, with read-only calls only, for Central accounts
  and single firewalls.

## Connecting firewalls

| Connection | Use it for | Notes |
|---|---|---|
| **SFOS REST API** (recommended) | Direct management of rules and objects | `https://<fw>:4444/api/firewall-config/v1`, API key as bearer token. The key has exactly the rights of its API administrator; the dashboard warns before it expires. |
| **Sophos Central / Fusion** | Firewalls managed through Central | Configuration via asynchronous export/import (`Entities.xml`). The import cannot delete objects. Also provides inventory, groups, MDR threat feed, firmware, licences and alerts, including for directly connected firewalls linked to Central. |
| **XML API (legacy)** | Firmware without a REST API | `/webconsole/APIController`, username and password. |

Run the **dry run** before the first change request: *Administration › Sophos Central › Dry run & endpoint check* for Central
accounts, *Firewall › Settings › Dry run* for single firewalls. It changes nothing.

- **REST API**: on the firewall, allow this server's IP under *Administration › API access*, create a dedicated
  API administrator with a suitable device profile (read/write for firewall rules and objects), generate an API
  key and enter it with its expiry date under *Firewall › Settings*.
- **Sophos Central**: create a service principal under *Global settings › API credentials*. For partner and
  organisation accounts, select the tenant after saving.
- **XML API**: on the firewall, enable *Backup & firmware › API*, allow this server's IP and use a dedicated API
  administrator.

API quirks found on real systems (paths that differ between guide and spec, page sizes, S3 upload headers,
transactions without a status) are documented in [docs/sophos-api-notes.md](docs/sophos-api-notes.md).

## Quick start

```bash
cp .env.example .env    # generate the values (see comments), then: chmod 600 .env
docker compose up -d --build
```

Sign in with `ADMIN_USERNAME` / `ADMIN_PASSWORD`. These are only used while no user exists yet.

### Demo with the Sophos mock

`COMPOSE_PROFILES=mock` starts `sophos-mock`, which emulates Sophos Central, the SFOS REST API and the XML API of
several demo firewalls. It keeps its state in memory and resets on restart.

- **Sophos Central**: *Administration › Sophos Central › Connect account*, client ID `mock-client`, secret
  `mock-secret`, both URLs under "Advanced" set to `http://sophos-mock:8000`, then "Import firewalls".
- **REST API**: *Firewalls › Add firewall*, connection "SFOS REST API", address
  `http://sophos-mock:8000/fw/X21002ZENTRALE1` (or another serial), API key `sfos_mock_key`.
- **XML API**: address `http://sophos-mock:8000/fw/C0100LABOR00001`, user `apiadmin`, password `mock-password`.
- Simulate drift: `docker compose exec backend python -c "import httpx; httpx.post('http://sophos-mock:8000/mock/fw/<SERIAL>/tamper')"`

For production, leave `COMPOSE_PROFILES` empty. Start the mock on demand with
`COMPOSE_PROFILES=mock docker compose up -d sophos-mock`.

## Configuration

Settings in `.env`:

| Variable | Purpose |
|---|---|
| `FWM_MASTER_KEY` | Base64 key that encrypts all stored credentials. **Never change or lose it.** |
| `JWT_SECRET` | Signs session tokens. |
| `POSTGRES_PASSWORD` | Database password. |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | First superadmin, only used while the user table is empty. |
| `FWM_PORT` | Host port of the UI (default 8096). |
| `TZ` | Time zone for schedules and display (default Europe/Berlin). |
| `SYSLOG_HOST`, `SYSLOG_PORT`, `SYSLOG_PROTOCOL` | Optional audit forwarding via syslog. |
| `COMPOSE_PROFILES` | `mock` starts the Sophos mock. |

Optional tuning variables for the backend: `CENTRAL_TRANSACTION_TIMEOUT` (600 s), `CENTRAL_POLL_SECONDS` (3),
`MDR_READ_TIMEOUT` (90 s), `HTTP_TIMEOUT_SECONDS` (30), `LOGIN_MAX_FAILURES` (5), `LOGIN_LOCK_MINUTES` (5).

Everything else is set in the UI under *Administration › Settings*: required approvals, auto-deploy, mandatory
ticket reference, re-authentication, two-factor requirement, temporary changes, sync interval, backup schedule and
default language. Notifications and SSO have their own pages.

## Architecture

```
Browser ──▶ frontend (React/Vite in nginx, :8096) ──/api──▶ backend (FastAPI, 1 worker) ──▶ PostgreSQL 16
                                                                    │
                                              ┌─────────────────────┼─────────────────────┐
                                        SFOS REST API        Sophos Central API       SFOS XML API
                                        (per firewall)       (per tenant/region)      (per firewall)
```

- **backend/** – FastAPI with SQLAlchemy. `app/changes.py` holds the workflow (drafts, validation, submit,
  decisions, deploy with drift check, revert). `app/sophos/` contains the connectors: `restapi.py`,
  `central.py`, `mdr.py`, `xmlapi.py` and `connector.py` as the single entry point. There is also a worker
  thread for syncs, auto-deploy, expiry, reminders and backups. Schema changes are idempotent SQL in
  `app/migrations.py`.
- **frontend/** – React SPA with no UI library. The configuration editor is in `src/pages/firewall/`, the SFOS
  forms in `src/components/Sophos*.jsx`, and the translations in `src/i18n/`.
- **mock/** – FastAPI emulation of Sophos Central, the REST API and the XML API for demos and end-to-end tests.
- One uvicorn worker on purpose: the login lockout and the deploy lock are in-process.

Detailed developer notes, including the reasons behind many design decisions, are in [CLAUDE.md](CLAUDE.md).

## Development

```bash
docker compose run --rm --no-deps -T backend pytest -q          # backend tests (SQLite in memory, no network)
cd frontend && npm install && npx vite build                      # frontend build check
cd frontend && npm run i18n:check                                 # every UI string translated
python backend/tools/i18n_check.py                                # every backend message translated
```

The tests are baked into the backend image, so rebuild before running them (`docker compose build backend`).
For end-to-end tests against the mock, see [CLAUDE.md](CLAUDE.md#tests).

**Languages**: the key is the German source text, `t('…')` in the frontend and `tr('…')` in the backend.
Adding a language takes one dictionary file per side; see
[frontend/tools/README-i18n.md](frontend/tools/README-i18n.md).

**Demo video**: [docs/demo/](docs/demo/README.md) contains the scripts that seed the mock and record the video
with Playwright, so it can be regenerated after UI changes.

## Further documentation

- [Approval guide](docs/approval-guide.md): the four-eyes workflow step by step, roles, settings, audit.
- [Sophos API notes](docs/sophos-api-notes.md): differences between Sophos guides, specifications and real systems.
- [CLAUDE.md](CLAUDE.md): architecture and implementation notes for developers.
- Specifications: [SFOS REST API](docs/sfos-rest-openapi.json) (reconstructed),
  [Sophos Central Firewall API 1.5.0](docs/sophos-central-firewall-v1.yaml).
