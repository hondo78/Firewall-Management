# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Management tool for **Sophos Firewalls** with roles/permissions, a **four-eyes approval workflow** for every config change, and a hash-chained audit log. UI on `:8096` (`FWM_PORT`). Unlike most LAN tools in `~/docker` it **has its own login** (JWT). The approval workflow needs identities, so don't remove it. The UI design follows the Sophos Config Studio: an entity navigator, SFOS-style rule table, a compare view and Entities.xml export. See `README.md` for features and the demo setup.

## Commands

```bash
docker compose up -d --build                         # db, backend, frontend (sophos-mock only with COMPOSE_PROFILES=mock)
docker compose logs -f backend
docker compose run --rm --no-deps -T backend pytest -q          # tests: SQLite in memory, no DB/network needed (tests/ is baked into the image → rebuild first)
docker compose run --rm --no-deps -T backend pytest -q tests/test_workflow.py::test_drift_blocks_deploy
COMPOSE_PROFILES=mock docker compose up -d sophos-mock   # the mock is off in .env (production); start it explicitly for tests
cd frontend && npm install && npx vite build          # frontend build check; `npm run dev` proxies /api to localhost:8000
```

`.env` holds generated secrets (`chmod 600`). **`FWM_MASTER_KEY` must never change.** It encrypts Central client secrets and firewall API passwords (`crypto.py`, AES-GCM, AAD `central:<id>` / `firewall:<id>`). `ADMIN_PASSWORD` is used only while `users` is empty. There is no Alembic: `create_all` creates new tables only. Changes to existing tables go into `app/migrations.py` as idempotent Postgres SQL, which runs at startup after `create_all`.

## Architecture

Services: `db` (Postgres 16), `backend` (FastAPI, **one** uvicorn worker, because the login lockout and `changes._deploy_lock` are in-process), `frontend` (React/Vite in nginx, proxies `/api/`, dynamic Docker DNS resolver; `index.html` is `no-cache`, and `/assets/` is immutable with a **404 for missing files**. Otherwise a browser with a stale `index.html` gets HTML as JS and shows a white page. An `ErrorBoundary` plus an 8-second fallback in `index.html` replace the white page with a message), `sophos-mock` (profile `mock`, in-memory, resets on restart).

### Sophos connectors (`app/sophos/`)
Three connectors per firewall (`Firewall.connector`):
- `rest`: the SFOS REST API. **Default and recommended.**
- `central`: Sophos Central import/export.
- `xmlapi`: the legacy XML API.

They use **two data formats**. `rest` keeps REST JSON objects 1:1 (entities like `firewallRulesIpv4`, key `name`). `central`/`xmlapi` keep XML-derived dicts (entities like `FirewallRule`, key `Name`). `entities.py` holds both catalogs (`REST_RESOURCES`, `XML_MANAGED`) plus the shared helpers `oname`, `references`, `RULE_ENTITIES`, `fmt_for`. Entity names never overlap. Switching a firewall between formats clears the cache, is blocked while requests are open, and withdraws drafts (`routers/firewalls.py::_apply_fw`).
- `restapi.py`: base `https://<fw>:4444/api/firewall-config/v1`, `Authorization: Bearer <key>`. The key is stored encrypted in `api_password_enc`, and `api_key_expires_at` drives the dashboard warning. **The docs landing page says `/firewall-config/v1`, which returns an HTML 404 on a real SFOS.** The client falls back on HTML-404 only (a JSON 404 means the object was not found). Rule create needs `position`+`referenceItem`, and PATCH has no position: moves go through `POST …/move`. `connector._rest_apply` PATCHes only the changed top-level fields (`patch_body`), moves separately, and rolls back applied ops on error. The reconstructed spec is in `docs/sfos-rest-openapi.json`.
- `central.py`: Sophos Central API. Flow: token (`id.sophos.com/api/v2/oauth2/token`) → `whoami/v1` (tenant/partner/organization + `dataRegion`) → `<dataRegion>/firewall/v1/...` with `X-Tenant-ID`. Config goes through the **async import/export**:
  - Export: `POST /firewall-config/firewalls/{id}/export` → poll `GET /firewall-config/firewalls/transactions/{tx}` → pre-signed GET URL (a tar containing `Entities.xml`).
  - Import: `POST /firewall-config/firewalls/import` → PUT the archive to the pre-signed S3 URL (no extra headers) → `POST …/import/{tx}/upload-complete` (md5, size, ≤25 firewallIds, `performPartialImport: false`) → poll.
  - **The dev guide and the OpenAPI spec (`developer.sophos.com/assets/specs/firewall-v1.yaml`) disagree on these paths.** The guide omits `/firewall-config`. `_cfg()` tries the spec path first, falls back to the guide path on 404, and remembers the working prefix per region (`_CONFIG_PREFIX`). Details: `docs/sophos-api-notes.md`.
  - The status fields `managingStatus` (spec) and `managing` (guide) are both read via `normalize_status`. Nested Central groups sync as „Parent › Child“ (`recurseSubgroups=true`). Licenses (`api.central.sophos.com/licenses/v1/licenses/firewalls`) and alerts (`<region>/common/v1/alerts?product=firewall`) back the „Lizenzen & Alerts“ tab.
  - **Import cannot delete.** `connector.capabilities()` blocks `remove` for `connector="central"`.
- `xmlapi.py`: the local SFOS XML API (`reqxml` form field, `<Login>` + `<Get>`/`<Set operation=add|update>`/`<Remove>`). The status code 200 is per entity. The base URL may be a full URL (the mock uses `http://sophos-mock:8000/fw/<serial>`).
- `connector.py`: the only entry point for everything else (`fetch_config`, `apply`, `test_connection`). XML-API apply does a **best-effort rollback** of already-applied ops on error.
- `xmlconv.py`: lossless XML⇄dict. Text-only → str, repeated tags → list. **List containers** (name ends in `s`/`List`, uniform children) are always `{Tag: [...]}`, even with a single child. `Position`/`After`/`Before` are write-only directives: they are stripped from stored objects and passed per operation (`with_position`).
- `entities.py`: the managed entity list (`MANAGED`, export names = XML tags) and `order_operations` (rule removals first, then adds/updates in dependency order, then object removals).

### Workflow extensions (`changes.py`, `worker.py`)
- **Temporary changes:** `expires_at`/`expiry_state`. `worker._expire_due` → `changes.expire` creates a system revert (`created_by=NULL`, shown as "system"). It is pre-approved (`status=approved`, event `preapproved`) when the setting `temp_revert_preapproved` is on; otherwise it waits in `pending`. If the config has changed, `expiry_state="failed"` plus an audit entry and a notification.
- **Batch requests:** `batch_id` on several `ChangeRequest`s, one per firewall. `submit(..., extra_firewall_ids)` validates every target first (`_prepare_batch`, all or nothing, same format required). `decide`/`withdraw` act on all pending members; `_check_decide` runs for every member before anything changes. Deploys stay per firewall.
- Position refs (`after`/`before`) must exist in the target config (`validate_operation`).
- **Templates:** `change_templates` (ops without `before`) applied via `draft_add`. The group diff is `GET /api/groups/{id}/drift?reference=`.
- **Lint:** `lint.py` normalizes rules from both formats into `Rule` (sets, None = any). `for_change` reports only findings the request introduces (compared by `_key`, which ignores positions). `analyze` gives the full report. "unused" only checks rules, groups and NAT, not VPN or web filter, which is why the UI collapses these hints.

### Notifications (`notify/`)
- `notify.change_event(id, kind)` is called **inside** the workflow functions (submit/decide/deploy/expire…), so web and Telegram trigger the same messages. It runs in a thread pool; tests set `notify.SYNC = True` (SQLite StaticPool).
- Channels: SMTP, a Teams workflow webhook with an Adaptive Card, and Telegram (long polling in a thread started by the worker, linked via a one-time code; `approve:<id>` callbacks go through `changes.decide`).
- Config lives in `settings["notifications"]` with secrets encrypted (AAD `notify:<channel>.<field>`). `check_reminders` (worker) handles expiry within 24 h and API keys at 30/7/1 days (`api_key_warned_days`).
- `public_url` there is also the base for OIDC redirects.

### Authentication (`security.py`, `mfa.py`, `oidc.py`, `routers/auth.py`)
- JWT claims: `iat` (login time), `mfa`, `src` (local|oidc). Purpose tokens (`purpose=login_totp`) are rejected as sessions.
- `get_current_user` blocks everything except `/api/auth/me|totp/|password` while the MFA requirement (setting `require_mfa`: none|privileged|all) is unmet. The error is a 403 with `detail={"code":"mfa_setup_required"}`, and the frontend `api()` puts that `code` on the error.
- `require_recent_auth` (decide endpoint, web only) returns a 403 `reauth_required` when `iat` is older than `reauth_minutes` → `POST /api/auth/reauth`.
- TOTP is RFC 6238 without a dependency; `segno` renders the QR SVG.
- OIDC uses code flow + PKCE + nonce. The ID token is verified against JWKS (no HS/none). Users are matched by `oidc_subject` and are never bound to the local superadmin. Roles are synced from the groups claim. The token reaches the SPA via a one-time exchange code, never in a URL. Tests fake the IdP by swapping `oidc._http` for an `httpx.MockTransport`.

### Removing firewalls
`DELETE /api/firewalls/{id}` **archives** the firewall (`archived=True`, credentials and config cache cleared) instead of deleting it. Change requests and snapshots reference it via `ON DELETE CASCADE`, so a hard delete would erase history. Archived firewalls are hidden everywhere (`firewall_or_404`, lists, worker) and are not re-imported by the Central inventory sync.

### Probelauf (`diagnose.py`)
Read-only checks against real systems (`POST /api/central-accounts/{id}/diagnose`, `POST /api/firewalls/{id}/diagnose`). They also probe the guide vs. spec path variant and a few undocumented GET endpoints (`CentralClient.probe` never raises). Keep every step non-mutating: the export test reads only `Zone`.

### Change workflow (`changes.py`, spans routers/worker)
Operation = `{entity, action: add|update|remove, name, data, before, position?, before_position?}`.
1. Draft: one per user+firewall (`status="draft"`). `draft_add` validates against the cache **plus the draft's own ops** (`effective_config`), merges repeated edits of the same object (`merge_operation`), and refuses to remove objects that are still referenced (`used_by`). No renames: the name is the key.
2. `submit`: re-validates against the current cache, snapshots `before`, and fixes `required_approvals` from settings.
3. `decide`: requires `change.approve` on that firewall. **Never the creator (this includes superadmins)**, each approver counts once, and a reject needs a comment.
4. Deploy: `claim_for_deploy` (atomic status UPDATE → `deploying`), then `deploy()`:
   - fetch the **live** config and run `drift_conflicts` against `before` → `conflict`;
   - otherwise `connector.apply` → re-sync (snapshot `reason=deploy`) → `deployed`;
   - on error → `failed`, which can be retried.
   - The worker (`worker.py`) auto-deploys `approved` requests (setting `auto_deploy`, respects `deploy_after`). A manual deploy runs in a thread (`worker.deploy_in_background`). On startup, stuck `deploying` requests become `failed`.
- Revert: `submit_revert` builds the inverse ops of a deployed request and **submits them directly** as a new request (`reverts_id` → original, so there is no draft). Allowed for `change.create` **or** `change.approve` (`can_revert`), and superadmins can always revert. Four-eyes still applies: the person reverting cannot approve it. Only one active revert per request, and it is refused with a 409 if the config has changed since.

### Config cache & history (`sync.py`, `diff.py`)
`config_objects` = the last synced state (ordered, `position`). A new `config_snapshots` row is written only when the config hash changes. A snapshot with `reason=sync` after an initial one means a change outside the tool, so the audit gets `config.drift_detected`. `diff.compare_configs` powers the snapshot compare and the compare against another firewall. The worker syncs all firewalls and Central inventories every `sync_interval_minutes`.

### Permissions (`permissions.py`)
Roles = sets of permission keys. A `RoleAssignment` is global (`group_id NULL`) or scoped to a `FirewallGroup`. `can(db, user, perm, firewall)` is the central check. `GLOBAL_ONLY` perms (`audit.view`, `admin`) count only from global assignments. `firewall_or_404`: an invisible firewall → 404, a missing specific perm → 403. `serializers.firewall_out` sends per-firewall `permissions` to the UI, and the frontend helpers are `can()`/`canAnywhere()` in `api.js`.

### Audit (`audit.py`)
Every relevant action calls `audit(db, action, ...)`, which **commits by default** (`commit=False` flushes only). It keeps a hash chain `sha256(prev_hash + canonical JSON)` with a `pg_advisory_xact_lock` on Postgres. `ts` is truncated to seconds, and `models.TZDateTime` (a TypeDecorator) keeps timestamps UTC-aware on SQLite, otherwise `verify_chain` breaks in tests. Never modify existing entries. Syslog export is optional (`SYSLOG_HOST`).

### Frontend
Format-aware: `components/entities.js` provides `isRestEntity`, `anyRuleView`, `anySummary`, `restRefOptions`, and `RestEditors.jsx` holds the REST forms. `EditorShell` switches its expert mode between JSON (REST) and XML. `pages/FirewallView.jsx` holds the studio view: `buildRows` overlays the user's draft on the cached config (preview comes from the backend `effective_config`). `components/Editors.jsx` has the form editors plus the XML expert mode (parsed server-side via `POST /api/xml/parse`). `components/entities.js` has the object helpers (list containers!). The `Picker` dropdown is an absolute overlay on purpose: an inline list shifted the layout on blur, and clicks missed.

### Tests
`tests/test_restapi.py` covers the REST client and connector with `httpx.MockTransport`. `tests/conftest.py` switches to SQLite in memory and monkeypatches `connector.fetch_config`/`apply` with `FakeFirewall`, so the tests need no network. End-to-end against the real connectors without touching the production DB: start the mock (`COMPOSE_PROFILES=mock docker compose up -d sophos-mock`), then `docker compose run --rm --no-deps -T -e DATABASE_URL=sqlite:////tmp/e2e.db -e DISABLE_WORKER=1 backend python <script>` using `TestClient(app)`. Docker has no free address pools here, so a second compose project cannot start. The mock serves REST at `/fw/<serial>/api/firewall-config/v1` (key `sfos_mock_key`). Its REST state is independent of its XML state.
