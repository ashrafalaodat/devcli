# Gateway verification record

## 2026-11-12: React and TypeScript frontend

Implemented and tested:

- Replaced the imperative HTML/JavaScript client with functional React pages in `frontend/src/`, strict TypeScript models, shared controls, a typed CSRF-aware API client and the interaction-based presence hook. Overview, booking, sharing, primary selection, cluster listing, token creation/download/revocation/preferences and all administrator controls retain their existing backend contracts. This is the browser implementation itself, rather than a React wrapper around the previous DOM script.
- Pinned React/React DOM19.3.1, TypeScript7.0.2, Vite8.3.8, React Vite plugin6.3.0 and Playwright1.65.0 with a committed npm lockfile. Local verification used Go1.26.0, Node22.20.0, npm11.19.0 and installed headless Google Chrome. Make installs with `npm ci`, checks types, tests the API/label helpers and generates the embedded production bundle before compiling Go. The container recipe has a pinned Node build stage; the final runtime still serves the embedded assets without Node. The three generated assets remain tracked for direct Go-only builds.
- Added an explicitly enabled, loopback-only Vite asset/HMR proxy. The browser continues using the backend's verified HTTPS origin, preserving OIDC callbacks, secure cookies, CSRF and API routing. Tests cover listener/public/target restrictions, normal TLS verification, private/traversal path rejection, exact module allowlists, request credential stripping, discarded response cookies, restricted methods/upgrades and production versus development CSP. Actual Vite8 required its exact `node_modules/vite/dist/client/env.mjs` import path; that path was added and tested without opening arbitrary dependencies or filesystem access.
- Thirteen frontend unit tests verify credential/header handling, malformed and failed responses, unauthorized cleanup, label parsing and empty-value distinctions. Headless Chrome executes the real production React bundle under the strict production CSP and exercises developer and administrator actions, idle-safe presence, PAT/logout behavior, editable automatic booking, foreign-owner/error guards, transient credential handling, text escaping and mobile layout. Expanded tests cover registration/import, maintenance and force release with audit reasons, validation, pending/error/retry states and confirmations.
- Fixed a refresh-ordering race discovered during migration review. Mutation refreshes now queue a fresh read behind any older request, and sign-out generations discard stale results. A held-response browser regression proves switching primary is followed by a new authoritative snapshot. Activity also schedules correction behind a pending read so an old snapshot cannot leave a stale inactivity deadline.
- A separate local smoke fixture ran actual Vite and the Go development asset proxy over verified TLS. Headless Chrome loaded the React source, observed a real source edit over the proxied WSS HMR channel and rendered the update. The source was restored and task-owned processes/trust entry removed afterward. This fixture had no login or Kubernetes connection; expected anonymous401 responses were excluded from JavaScript failure checks.
- Rebuilt and restarted only the verified local host backend, then checked `/readyz`, the served module entry/root and strict production CSP over HTTPS9090. Read-only metadata reports schema8 and the same four live registry entries with four encrypted credentials present. No database migration was needed. No registered remote cluster was contacted or modified, and no normal booking or PAT was changed for testing.

Commands actually executed (`TMPDIR` and `GOTMPDIR` used `/local/workspace/devctl-tmp`; npm cache used `/local/workspace/devctl-npm-cache`):

| Command | Result |
| --- | --- |
| `make build test frontend-test` | Passed; pinned dependency installation, strict TypeScript,13 frontend unit cases, Go race suite, production bundle and headless UI contracts. External-service Go cases skip without their test configuration |
| `make demo-test` | Passed; isolated real PostgreSQL internal suites (API16.181s, store14.151s), then actual Keycloak/CLI/native kubectl integration26.241s (manual8.63s, stable-primary16.57s). Browser cases skipped here and ran separately below |
| `./scripts/browser-test.sh` | Passed6.122s; disposable Keycloak browser SSO/PAT flow3.03s and automatic-booking/browser/CLI flow2.06s, with isolated schemas and local TLS protocol fixtures |
| `go test -race ./internal/webui ./internal/browser ./cmd/devctld -count=1` | Passed; focused development-proxy tests also reran successfully after adding the exact Vite environment module route |
| `bash .demo/react-dev-smoke/run.sh` | Passed; temporary actual Vite/verified HTTPS/WSS React Fast Refresh fixture described above |
| `go vet ./...`, `node --check internal/webui/testdata/primary-ui.cjs`, `bash -n scripts/*.sh`, `git diff --check` | Passed |
| `docker buildx build --check --progress plain .` | Passed; container recipe validation only |
| `./scripts/package-client.sh` | Passed; Linux full-CLI archive rebuilt |
| Verified backend restart; TLS checks of `/readyz`, `/`, production CSP; read-only schema/registry counts | Passed; schema8 and4 live registrations/credentials preserved |

Implemented but not tested in this iteration: a full application container image build and container runtime. The Docker filesystem had insufficient free space for that rebuild; no unrelated Docker data was pruned. The host production bundle/backend were built and exercised. Frontend browser actions run against deterministic API fixtures; real provider/gateway tests separately cover SSO and transport. Corporate OIDC, production proxies/load, desktop keyrings/non-Linux runtimes and real Kubernetes workload behavior remain deployment validation work. Kubernetes privilege isolation, workload/storage cleanup, resource accounting and queueing remain deferred under the current coordination-only scope. [ADR009](adr-009.md) records the frontend/build decisions.

## 2026-11-12: editable PAT automatic booking and two supported clients

Implemented and tested:

- Added optional `auto_booking.enabled` plus equality-label `auto_booking.selector` metadata to PAT creation, listing, single-record reads and edits. Owners edit through SSO; an administrator editing another owner must supply an audit reason. The browser exposes create-time opt-in and per-token editors, including administrator controls. The full CLI supports `token create --auto-book --selector region=eu` and `token update PAT_ID --selector region=us`, `--auto-book=false` or `--clear-selector`. Omitted CLI update fields are preserved; expired/revoked/retired credentials cannot be edited. Policy edits preserve the ID, digest, fixed expiry, downloaded file and current booking.
- Only an explicitly opted-in, still-valid PAT can allocate on a gateway request with no existing primary. One PostgreSQL transaction revalidates the token, applies the saved labels, reserves a completely unused live/nonmaintenance registration through the existing booking path, assigns primary and records activity. An existing primary always wins, even outside the saved selector. Automatic booking never joins another holder’s shared booking or falls back outside labels. Empty selector permits any unused registration. No matching capacity returns an actionable native-kubectl error. Credential expiry before commit rolls back a new allocation.
- Migration008 defaults all existing credentials to disabled, preserves revocation/scope/expiry, and retains later edits across restart. Twenty-four simultaneous first-use store calls through two Store instances created exactly one hold; API and six concurrent native kubectl processes also resolved one committed primary. Tests covered unavailable/shared/maintenance/retired environments, strict label syntax, at most32 entries, present-empty versus absent-empty label matching, owner/admin permissions, audit reasons and rejected client query overrides.
- Real Keycloak browser plus CLI SSO verified the same saved PAT kubeconfig first books EU, keeps EU while its selector is edited to US with the actual CLI, then books US after release without changing token/digest/file/expiry. It retained the primary/policy across restart, returned clear no-match/disabled errors, enforced CSRF and foreign-owner denial, and proved intentional enabled-PAT rebooking after logout. Disabling preferences or revoking the token prevented further automatic allocation. Token refresh and preference reads/edits never allocate.
- Removed the standalone kubectl subcommand executable, source command, dedicated tests, installer, package script, Makefile target and container build output. Removed its welcome/access cards, renumbered browser access to02, changed the UI to two client choices and updated current README/security/OIDC/OpenAPI documentation. Generic full-CLI credential/heartbeat support and meaningful reservation tests remain. Old historical verification/ADRs are marked superseded rather than presented as current instructions. Existing configurations authored by the removed executable require full-CLI setup or a browser PAT config once; existing PAT files remain usable.
- Headless Chrome verified default opt-out, creation/edit/clear/disable policy forms, owner/admin audit rules, immutable downloaded config, unchanged current primary, ended-token guards, two-client layout and the existing inactivity/deregistration/PAT/logout/mobile behaviors. The local demo now serves this UI over verified HTTPS9090 and reports schema8. Read-only metadata confirms four live registry entries with four credentials retained and zero normal PATs automatically opted in. No registered remote cluster was contacted or changed.

Commands actually executed (temporary Go/browser files used `/local/workspace/devctl-tmp`):

| Command | Result |
| --- | --- |
| `make build` | Passed; only full CLI and backend are built |
| `make test` | Passed with race detection; external-service cases skip without their configuration |
| `DEVCTL_TEST_DATABASE_URL=… go test -race ./internal/store ./internal/model -count=1` | Passed; focused store/model run9.189s/1.028s |
| `DEVCTL_TEST_DATABASE_URL=… go test -race ./internal/api ./internal/browser -count=1` | Passed10.963s/2.368s |
| `make demo-test` | Passed; all internal packages with real PostgreSQL (API12.952s, store11.300s), then actual Keycloak/CLI/kubectl integration25.152s (manual7.51s, stable-primary16.62s). Browser cases explicitly skipped here and ran separately below |
| `./scripts/browser-test.sh` | Passed5.580s; existing browser suite2.74s plus new automatic-booking/browser/CLI suite1.82s, against a disposable local Keycloak, isolated schemas and TLS protocol fixtures |
| `node internal/webui/testdata/primary-ui.cjs` with installed Playwright | Passed; headless Chrome two-client and editable-policy contracts |
| `go test -race ./internal/cli -count=1` | Passed2.446s; new creation/update/selector validation and standalone-client removal regressions |
| `go vet ./...`, JavaScript/shell syntax, `git diff --check` | Passed |
| OpenAPI reference/path-parameter validation, migration008 comparison and removed-client source/build checks | Passed |
| Verified local backend restart, `/readyz`, served HTML/JS, read-only schema/registry/preference counts | Passed; schema8,4 live registrations/credentials,0 existing PATs automatically enabled |
| `./scripts/package-client.sh` | Passed; current Linux full-CLI archive rebuilt; old repository-owned plugin binary/archive removed |

An initial integration compile found an unused import, which was removed before the successful runs. The headless harness also exposed a timing assumption in its existing heartbeat check: a one-millisecond sleep was insufficient for the fixture HTTP response. It now awaits that response explicitly, preserving the production heartbeat behavior. Independent review passed; missing-label versus empty-value matching was corrected and regression-tested.

Implemented but not deployment-tested: production proxy/load behavior, corporate identity integration, desktop keyrings/non-Linux runtimes and real Kubernetes workload behavior. The backend container recipe now builds two executables; the application image was not rebuilt in this iteration. Gateway tests use local TLS Kubernetes protocol fixtures, not a real control plane. Kubernetes privilege isolation, workload/storage cleanup, resource accounting and queues remain deferred. Enabled PATs intentionally retain automatic-booking capability after logout until disabled, revoked or expired; this does not provide upstream credential revocation or override IdP/PAT expiry.

## 2026-11-11: administrator cluster deregistration

Implemented and tested:

- Added `devctl admin deregister CLUSTER_ID --reason 'Retiring environment'` and **Administration → Cluster placement controls → Deregister**. Browser removal requires a nonblank audit reason and explicit confirmation naming the cluster. Occupied cards disable the action with release guidance; a concurrent server conflict refreshes authoritative registry state. Developers and the reduced kubectl plugin have no admin command/control.
- Added authenticated administrator `DELETE /v1/admin/clusters/{id}` with strict reason/body validation and the existing browser Origin/CSRF guard. Active private or shared bookings reject409; explicit owner/admin release must happen first. Unknown IDs return404. Retrying an already deregistered ID succeeds without another deregistration audit record. CLI preserves meaningful permission/conflict/not-found exit codes.
- Migration007 retains archived public cluster metadata for historical sessions, booking idempotency and audits, but sets the encrypted kubeconfig to NULL and excludes the entry from availability, booking, selection, maintenance and credential lookup. Retired IDs stay reserved; a partial unique index permits display-name reuse with a new ID. Historical booking detail remains readable through the API and CLI. PAT validity and all other registrations remain unchanged.
- Twelve concurrent booking-versus-deregistration rounds through two PostgreSQL Store instances proved that a cluster cannot be both retired and newly booked. Tests also covered existing-schema migration, restart stability, expiry before removal, database credential constraints, retained idempotency results, exact audit actor/reason and idempotent retries.
- Actual Keycloak CLI/browser flows verified admin versus developer authorization, CSRF, occupied-booking conflicts, explicit stop then removal, preserved historical metadata, ciphertext removal and unavailable placement. Upstream request counters proved no Kubernetes call occurred during deregistration. Headless Chrome covered reason validation, cancellation, confirmation, occupied controls, server409 refresh, removal from both cluster lists/selectors, PAT/history preservation, no accidental maintenance request and mobile layout.
- The existing local HTTPS9090 backend was rebuilt/restarted with schema7 and its served JavaScript checked. Read-only database metadata confirms all four normal registrations remain live with credentials present. No normal registry entry was deregistered and no registered remote Kubernetes endpoint was contacted. PostgreSQL/Keycloak containers were not recreated.

Commands actually executed (Go/test temporary files used `/local/workspace/devctl-tmp`):

| Command | Result |
| --- | --- |
| `make build` | Passed; backend, full CLI and kubectl plugin binaries built |
| `make test` | Passed with race detection; external-service suites skip without their test configuration |
| `DEVCTL_TEST_DATABASE_URL=… go test -race ./internal/store -count=1` | Passed7.494s using isolated schemas on local PostgreSQL54329 |
| `DEVCTL_TEST_DATABASE_URL=… go test -race ./internal/api -count=1` | Passed9.408s; focused new `TestDeregister*` regressions also passed1.412s |
| `go test -race ./internal/cli ./internal/webui` | Passed; CLI focused run2.600s, client/web UI regressions included |
| `DEVCTL_TEST_DATABASE_URL=… DEVCTL_TEST_ISSUER=… go test -race ./tests/integration -run '^TestEndToEnd$' -count=1 -v` | Passed8.729s (test7.71s), with real local Keycloak and native CLI/kubectl against TLS protocol fixtures |
| `./scripts/browser-test.sh` | Passed3.794s (test2.77s), disposable local Keycloak and isolated schema |
| `node internal/webui/testdata/primary-ui.cjs` with installed Playwright | Passed; headless Chrome UI contract tests |
| `go vet ./...`, JavaScript/shell syntax and `git diff --check` | Passed |
| OpenAPI reference/path-parameter validation and migration007 comparison | Passed; DELETE documented; standalone SQL matches embedded migration |
| `./scripts/package-client.sh` and `./scripts/package-plugin.sh` | Passed; current Linux client/plugin archives rebuilt |
| Verified demo backend restart, `/readyz`, served JavaScript and read-only schema/registry counts | Passed; schema7 and4 live registrations with4 stored credentials |

Implemented but not deployment-tested: production proxies/load, non-Linux runtimes/keyrings, corporate SSO and this policy against real Kubernetes workloads. Host binaries and client archives were rebuilt; the backend application container image was not rebuilt in this iteration. Deregistration intentionally performs no cluster cleanup or upstream credential revocation. Historical backups/WAL may retain old encrypted values under their existing retention policies; this is logical credential removal rather than a secure-erasure guarantee. [ADR007](adr-007.md) records the archival decision.

## 2026-11-11: activity-based reservation retention

Implemented and tested:

- Removed booking duration from the browser and `devctl start`, and removed manual CLI renewal. Old booking TTL request fields are rejected; the former authenticated renewal endpoint returns410 with migration guidance. PAT/access-token lifetime controls remain supported and independent.
- Added a durable administrator inactivity grace period: default4h, whole-second durations from1m through168h. CLI `admin settings --inactive-grace 4h --reason 'Team policy'` and browser Administration → Booking policy update it with an audit reason. Partial count/grace patches preserve omitted fields; combined changes are atomic. Shortening applies to already-idle current bookings, while increasing never revives expired ones.
- Accepted gateway requests, still-authorized open streams, explicit primary selection and authenticated browser interaction extend only the exact current primary booking. PostgreSQL stores UTC activity/deadlines, throttles writes to15s and serializes activity with expiry/release using the reservation advisory lock. Ten rounds each of live/elapsed activity-versus-expiry races across two stores passed. Automatic primary promotion does not fabricate activity.
- Browser presence follows actual trusted input on a visible page, with at most one send per30s and one pending observed interaction. Headless Chrome verified idle tabs, passive polling, synthetic events and hidden pages do not create self-renewing activity. Requests contain exact session ID/selection version, with server timestamps/policy; stale or foreign assertions are rejected. Real Keycloak browser tests verified authentication, CSRF and independent deadlines while holding two clusters.
- OAuth token refresh and the detached authorization helper do not advance inactivity deadlines. A real-provider detached refresh test checked unchanged activity and deadline values. Moving OAuth authorization leases are bounded by verified JWT expiry and checked separately from reservation validity, so a valid stream survives its previous inactivity deadline after genuine activity extends it. Scripts and watches count as client activity, as requested; no human-presence claim is made.
- The background worker released an inactive reservation while the CLI was closed. Idle release blocks gateway access and preserves PAT validity/expiry and Kubernetes workloads. Remaining bookings promote safely; ended reservations cannot be revived by stale heartbeats. Existing apply/log/exec/watch/port-forward gateway, sharing, owner/limit checks, refresh, PAT-survives-logout and restart regressions continue to pass.
- Migration006 gives existing active bookings one full initial grace window without changing historical actual activity. Its version guard preserves the baseline and deadline across restart. The upgraded demo is ready over verified HTTPS9090: schema6, all four registry entries retained, booking-count default1 and inactivity grace14400seconds. Only the verified local host backend was restarted; identity/database containers were not recreated and no remote Kubernetes endpoint was contacted.

Commands actually executed (Go temporary files used `TMPDIR` and `GOTMPDIR` under `/local/workspace/devctl-tmp`):

| Command | Result |
| --- | --- |
| `make build` | Passed; backend, CLI and kubectl plugin binaries built |
| `make test` | Passed with race detection; external-service suites skip without their configuration |
| `DEVCTL_TEST_DATABASE_URL=… go test -race ./internal/store` | Passed; focused final store run6.262s |
| `DEVCTL_TEST_DATABASE_URL=… go test -race ./internal/api -count=1` | Passed9.629s after the migration correction |
| `make demo-test` | Passed; every internal package with real PostgreSQL, then real Keycloak CLI/plugin/stable-primary integration28.432s (7.53s/2.67s/17.21s). Browser case explicitly skipped here and run separately below |
| `./scripts/browser-test.sh` | Passed3.562s (browser test2.54s), with disposable Keycloak, isolated PostgreSQL schema, actual SSO/CSRF and native kubectl/PAT against local TLS fixtures |
| `node internal/webui/testdata/primary-ui.cjs` with installed Playwright | Passed; per-cluster presence, idle/hidden/polling guards, throttling, policy, primary, PAT, mobile and existing UI contracts |
| `go test -race ./internal/cli` and `go test -race ./internal/webui` | Passed; final targeted CLI policy run1.208s, web UI1.048s |
| `go vet ./...`, JavaScript/shell syntax and `git diff --check` | Passed |
| OpenAPI reference/path-parameter validation and migration006 comparison | Passed;33 documented paths; standalone migration matches embedded SQL |
| Verified backend restart, `/readyz`, served HTML and read-only database metadata | Passed; current UI removes duration/renewal and exposes admin inactivity policy |

Tests caught and corrected a PostgreSQL named-argument typo in the initial migration, legacy integration parsers missing `--json` after human-readable status was added, and a browser test helper incorrectly reusing an idempotency key for a new post-release booking. The final runs above passed after these corrections. Validation used disposable TLS Kubernetes protocol fixtures, never the registered remote clusters.

Implemented but not deployment-tested: corporate OIDC, this policy against real Kubernetes workloads, production proxies/load and desktop keyrings/non-Linux runtimes. Host binaries were rebuilt; the application backend container image was not rebuilt for this iteration. Deferred under the current coordination-only scope: Kubernetes privilege isolation, workload/storage cleanup, upstream credential revocation, resource accounting and queueing. API activity can continue unattended; conversely a running workload that makes no gateway requests has no automatic activity signal and can outlive its reservation.

## 2026-11-11: PATs survive sign-out

Logout now preserves personal access tokens and their original expiry. It still releases all of the identity's bookings, clears the current native/browser login and attempts provider-supported OAuth refresh-token revocation. With no booking the saved PAT config receives the no-booked-cluster error; after a fresh login and explicit booking, the same file works again. Explicit PAT revocation and expiry remain enforced, and logout never restores an already revoked or expired PAT. This supersedes the logout/PAT-revocation behavior in earlier dated records below.

Implemented and tested:

- Real PostgreSQL store/browser regressions covered multiple live PATs through repeated logout, unchanged creation/expiry/revocation metadata, cleared primary/bookings, other-user isolation, explicit rebooking, expired/revoked denial, cleared browser cookie and provider refresh-token revocation. Focused race tests passed (store1.435s, browser1.306s).
- API/gateway regressions passed with real PostgreSQL (2.110s): authenticated POSTlogout leaves PATs valid, returns403 no-booking rather than401 invalid credential, rebooking reuses the same PAT, and explicit revocation still returns401. Logout closes an existing stream because its reservation ended, while its PAT remains valid.
- The real Keycloak browser integration passed (3.619s, test2.60s). It saved a PAT kubeconfig before sign-out, proved its validity and expiry survived, rejected the old browser cookie and revoked provider refresh token, completed a fresh browser SSO login, explicitly booked again, and used the identical saved file. Explicit revocation denied access and a later logout did not revive the credential. Only disposable local identity-provider/API fixtures and isolated PostgreSQL schemas were used.
- The durable headless UI regression passed: sign-out confirmation and success messages describe PAT preservation, no PAT DELETE request is sent, token metadata/expiry stay unchanged and bookings are released. The two sentences previously removed from the download callout remain absent.

Commands actually executed: `make build`, `make test` (race tests; external-service cases skip without their environment), `make test-db` (store5.585s, API9.511s, browser2.379s), focused store/browser/API race tests, `./scripts/browser-test.sh`, JavaScript/OpenAPI syntax checks, the headless UI driver and `git diff --check`. Temporary Go/test files used `/local/workspace/devctl-tmp`.

No migration or token resurrection was introduced. The demo host backend was rebuilt/restarted and its served HTML checked for the corrected sign-out statement; Keycloak and PostgreSQL containers were not recreated. No normal demo logout or remote Kubernetes request was used for validation. Corporate OIDC and real-cluster workload behavior remain outside the tests executed for this change.

## 2026-11-11: developer booking limits and one primary-cluster config

Implemented and tested:

- Administrators can set a global maximum held-booking count (default1) and optional per-developer overrides from1 through100, with audit reasons. PostgreSQL serialization covers count checks, idempotency and allocation. Forty simultaneous booking requests through two Store instances held exactly3 bookings under a limit of3. Lowering a limit preserves existing bookings and prevents additional ones.
- The first explicit booking becomes primary; later bookings leave it unchanged. Selecting a different owned active cluster changes one durable identity-wide primary and increments its version. Stop/expiry/administrative release promotes the oldest remaining active booking or clears the selection. Other users cannot change that selection. Restart preserves limits, reservations, selection and version.
- Every new configuration uses only the stable `/k8s` gateway, with no developer, session or binding identifier in its URL. CLI/plugin setup, login, credentials, refresh and Kubernetes requests never book capacity. Full CLI booking remains explicit; the plugin can switch an existing selection. Normal kubectl first-use SSO without a reservation returns “no cluster is booked” and leaves zero reservations.
- Browser PATs are now developer-scoped `kubernetes:primary` credentials. They can be issued before booking, follow later primary changes and explicit rebooking, and survive individual reservation expiry/stop. Default8h/max168h token expiry and revocation remain independent limits. They cannot authenticate control/admin APIs, select a primary or create reservations.
- Migration005 preserves the registry and existing bookings, backfills primary selections, retires old per-booking PATs without widening them, and removes automatic bindings. Existing over-limit holders retain their reservations. Fresh owner-wide PATs survive a subsequent Store.Open. Historical data remains for audit, while retired gateway/control connection paths return410.
- Real PostgreSQL/API tests verified owner/administrator permissions, policy validation, stable PAT routing between two TLS endpoints, unchanged additional-booking selection, promotion/no-booking/rebooking, retired routes, actual stock kubectl, and fail-closed database/revocation/expiry behavior. Stream tests verified fresh JWT renewal, rejected expired new requests, no heartbeat-generated activity, version-based termination after an away-and-back switch, and lease/database failure.
- The real Keycloak CLI integration preserved apply/log/exec/watch/port-forward transports, sharing, contact visibility, OAuth refresh/revocation, restart and expiry (7.60s). The real plugin integration verified discovery, first-use PKCE without allocation, refresh rotation, an explicit second booking, primary switching between TLS fixtures with byte-identical config, reduced controls and logout (1.56s in the combined run;4.02s in its focused run).
- The stable full-CLI integration passed16.65s (17.672s with race harness): interactive first-use SSO/no-booking rejection, offline config, default1 limit, audited increase to2, no implicit switch on second booking, concurrent kubectl commands, detached real refresh/rotation and authorization renewal without another CLI command, unchanged config across switching, restart, promotion and explicit rebooking.
- The enhanced real browser SSO/PAT integration used a disposable local Keycloak and isolated PostgreSQL schema. It issued a config before booking, exercised admin default/override policy, held two distinct TLS fixtures, switched with the same PAT/file, rejected foreign selection, lowered limits without eviction, stopped both bookings, explicitly rebooked using the same PAT, and retained restart/concurrent provider refresh/admin revocation/logout checks. No registered cluster was contacted.
- Durable headless UI contract tests cover held/limit counts, first/additional/primary behavior, switches/promotion, one-download PAT creation without a session selector, global/per-user override/reset, CSRF, text escaping and390px mobile layout. Both installers passed in private temporary paths containing spaces/apostrophes, without real shell RC changes or offline token issuance.

Commands actually executed: `make build`, `make test` (all packages with race detection; real-service suites skip without configuration), `make test-db` (store5.473s, API9.332s, browser2.671s), targeted real-Keycloak integration commands above, `./scripts/browser-test.sh`, `go vet ./...`, `bash -n scripts/*.sh`, OpenAPI JSON/path/reference validation, `git diff --check`, and headless `node internal/webui/testdata/primary-ui.cjs` with the installed Playwright1.62 module. Builds/tests used `GOTMPDIR` and `TMPDIR` under `/local/workspace/devctl-tmp`.

The first no-booking CLI regression exposed that client-go discovery/DoRaw discards JSON Status messages on409 and prints only a generic conflict. The gateway now returns403 plain text for the no-primary case, preserving the actionable message in actual kubectl; the control API's no-primary response remains409 JSON. The regression was rerun successfully after this correction. No TLS verification was disabled.

Final combined verification also passed: `./scripts/demo-test.sh` ran every internal package with real PostgreSQL, then the real Keycloak integration suite (29.284s; manual8.56s, plugin2.75s, stable-primary16.96s). Its browser case explicitly skipped and was run separately with `./scripts/browser-test.sh` against a disposable identity provider (3.373s, test2.35s). `make client-package plugin-package` produced both native Linux archives. OpenAPI has32 paths and migration005 matches the embedded SQL.

A real headless browser smoke against the upgraded demo passed fresh Alice/admin Keycloak SSO over verified HTTPS, actual primary/limit rendering, developer/admin separation, reusable PAT form without a session selector, administrator default/override views, and390px layout. It made zero Kubernetes requests and changed no bookings, selections, policies, PATs or clusters. Only authentication/profile/audit reads and test authentication sessions were used. An initial harness request client did not share Chrome’s CA trust; same-origin browser fetch corrected the harness without bypassing TLS. The failed run’s single test browser session was removed; successful checks used only verified browser transport. Temporary demo-CA trust was removed and pre-existing trust entries preserved. Private screenshots are under `.demo/primary-*.png`.

The normal demo was upgraded with `make demo-up`: schema version5, four registered clusters preserved, default booking limit1, verified HTTPS9090 ready. The migration deliberately invalidates old session-scoped PATs/configs; users must prepare/download one new stable config. No cluster resources were created or changed.

Implemented but not deployment-tested: corporate OIDC, non-Linux desktop/keyring/process behavior, production reverse proxies/load, and this routing model against real Kubernetes workloads. All Kubernetes test traffic used local disposable TLS protocol fixtures; exec output is a fixture frame rather than a process in a real Pod. Resource isolation/accounting, queueing, automatic cleanup and upstream credential revocation remain deferred under the current reservation-only scope. Discovery data cached by Kubernetes clients may need refreshing after a cluster switch. The backend application container image was not rebuilt in this iteration; host binaries and the local Keycloak image were built.

## 2026-11-11: three clients, browser SSO and session-scoped PATs

Implemented and tested:

- Full CLI remains available, including new private PAT file creation/list/revoke commands. The smaller `kubectl-devctl` executable exposes login/setup/status/logout, with hidden credential/heartbeat support. Actual kubectl plugin discovery and first-use real Keycloak PKCE login created one stable booking; forced access expiry silently rotated access and refresh tokens. The plugin does not depend on an installed `devctl` binary.
- Browser SSO uses a separate public web client with PKCE S256, one-time browser-bound state, verified nonce and independently verified API access token. Secure/HttpOnly/SameSite cookies contain only a random identifier. OAuth credentials are encrypted in PostgreSQL; only cookie digests are persisted. Signed local OIDC tests with real PostgreSQL covered invalid state/cookie/replay/nonce/audience/subject/groups, encrypted persistence, CSRF/Origin, restart, logout, absolute expiry and pruning. Twenty concurrent requests across two handler/store instances used one rotating refresh grant.
- Session-scoped opaque PATs are stored only as SHA-256 digests and delivered once in a gateway-only kubeconfig. Actual stock kubectl ran with no helper available on PATH. PATs cannot authenticate the control/admin APIs or automatic routes and cannot access another session. Real PostgreSQL gateway tests closed native watch and bidirectional streams after revocation, credential expiry, booking stop/logout or database outage. Credentials remain valid only for their original booking.
- The real-Keycloak browser integration test passed in 1.87 seconds (2.893 seconds with race harness). It covered browser-only login, administrator cluster import into an isolated schema, exclusive conflict and holder-approved sharing, foreign-owner credential denial, native kubectl with downloaded PAT, backend restart, eight concurrent real token refreshes with rotation, maintenance, audit, administrative PAT revocation and booking release, and logout. It used a disposable local Keycloak instance, disposable PostgreSQL schemas, and a TLS Kubernetes API fixture. No registered remote cluster was contacted.
- The responsive browser UI renders developer booking/share/renew/stop, team contacts, downloads/revocation and role-protected admin registration/maintenance/release/audit controls. Headless Chrome tests with fixture responses covered text escaping, CSRF submission, one-time download, role visibility, logout and mobile layout. A separate real browser smoke used actual local Keycloak and the running demo over verified HTTPS: Alice/admin login, four existing registry entries, developer/admin navigation, access controls, populated audit view and 390px mobile layout passed without JavaScript/certificate errors or browser token storage. No bookings, PAT issuance, admin changes, logout or Kubernetes requests were made against the normal registry during that smoke.
- The existing persistent local realm received only the new `devctl-web` client through an authenticated admin-console browser flow. Existing user subjects and registry data were retained. `make demo-up` rebuilt the service and Keycloak image and preserved both identity-provider/database volumes. Browser callback is the exact approved `https://127.0.0.1:9090/auth/callback`.
- Client and plugin installers were tested in private temporary paths containing spaces/apostrophes, with idempotent temporary shell RC updates and no modification of actual user startup files or global kubeconfig. Offline setup issued no token. CLI PAT tests verified private0600 files, path-only stdout, preservation of existing files/symlinks, safe returned IDs and truthful revocation-failure errors without sensitive response bodies.

Commands actually executed:

| Command | Result |
| --- | --- |
| `make build` | Pass; CLI, backend and kubectl plugin built |
| `make test` | Pass with race detection; real-service suites skip without their environment variables |
| `make test-db` | Pass; real PostgreSQL store4.299s, API7.330s, browser2.517s |
| `DEVCTL_TEST_DATABASE_URL=… go test -race ./internal/browser -count=1 -v` | Pass, 2.003s; signed OIDC and PostgreSQL |
| `DEVCTL_TEST_ISSUER=http://127.0.0.1:8081/realms/devctl DEVCTL_TEST_DATABASE_URL=… go test -race ./tests/integration -count=1 -v` | Pass, 28.025s; automatic workflow18.50s, existing gateway/manual7.35s, actual plugin1.14s; browser case explicitly skipped here and run separately |
| `make browser-test` | Pass, latest2.806s (test1.79s), against disposable Keycloak18081/backend19090; test resources removed afterward |
| `make demo-up` | Pass; verified HTTPS9090 ready, registry and identity volumes preserved |
| `go test -race ./internal/cli -count=1` | Pass after PAT file-error fixes, 2.720s |
| `go test -race ./internal/webui -count=1` | Pass |
| `go vet ./...`, shell syntax, `git diff --check` | Pass |
| OpenAPI JSON/path parameter validation and migrations003/004 comparison | Pass; 27 documented paths, embedded SQL matches migrations |
| `make client-package plugin-package` and isolated plugin installer invocation | Pass; native Linux archive contains executable and installer only |

Build/test temporary files used `/local/workspace/devctl-tmp`. The first disposable Keycloak startup failed because the host root disk was full. Two old inactive Go compiler temporary directories were moved intact to `/local/workspace/devctl-preserved-go-tmp`, freeing space; no repository, cluster or identity data was removed. An initial browser navigation waiting for network idle timed out; DOM readiness and explicit UI visibility checks passed. A temporary trust entry for only the generated demo CA was removed after real browser tests, preserving existing trust entries. No insecure TLS option was used.

Implemented but not deployment-tested: corporate OIDC; desktop OS keyrings and non-Linux installers/process behavior; browser/PAT/plugin traffic against real Kubernetes workloads; production reverse proxies/load, multi-host refresh crash recovery and week-long sessions. The backend application container image was not rebuilt in this iteration; source container build files include all three binaries, and host binaries plus the Keycloak demo image were built. Browser functionality and PAT permissions were tested against disposable TLS API fixtures, which do not establish real-cluster security or workload behavior.

Explicit limits: PATs do not refresh or extend themselves; default8h/max168h and reservation expiry bound access. Provider role removal does not automatically revoke a PAT: administrators must revoke it or release its booking. Download permissions depend on the browser; users must keep PAT YAML private. Smaller plugin commands do not restrict the underlying identity's server permissions. Kubernetes permission changes, cleanup, queuing, capacity accounting and corporate SSO remain deferred as described in the current README.

## 2026-11-10: automatic kubectl workflow

The previous working version was committed and pushed as `a6a016e` before this implementation started. The new automatic workflow adds offline setup, an interactive credential helper, immutable automatic bindings, activity observation, and a detached authenticated renewal worker. Existing explicit-session behavior remains available.

Implemented and tested:

- Actual kubectl in a pseudo-terminal triggered real Keycloak Authorization Code + S256 PKCE login on its first ordinary `get pods`, with no separate login/start command. Six concurrent commands reused the same booking. Setup and noninteractive missing-login tests made no authentication/allocation requests.
- Real PostgreSQL concurrency tests covered creation and reuse of compatible own bookings, restart persistence, immutable parameters, owner/issuer isolation, ended bindings, activity throttling, idle renewal rejection, and authorization expiry capped by verified-token and reservation expiry.
- A detached worker survived the originating kubectl process, refreshed credentials through real Keycloak, rotated both access and refresh tokens, and advanced the server authorization lease without another CLI command. Its own control requests left `last_activity_at` unchanged. The full automatic E2E took 16.22 seconds with race detection.
- Gateway stream tests with PostgreSQL and a test authenticator continued automatic streams past their original credential expiry after a fresh authenticated heartbeat, rejected expired credentials on new requests, and closed streams on stop, authorization-lease expiry, or database failure. Explicit session-ID streams retained original-token expiry behavior. These controlled expiry tests use a test authenticator; they are not a ten-minute real-IdP soak test.
- The existing E2E passed in 7.37 seconds against the same disposable Keycloak realm, covering manual bookings, sharing, gateway ownership, actual kubectl apply/logs/exec/watch/port-forward transports, refresh, logout, and backend restart.
- A native Linux client archive contained only the executable and installer. Installation into temporary paths tested spaces/apostrophes, repeat installation, preserved RC content, private gateway-only metadata, and a single shell integration block. No real shell startup file or global kubeconfig was edited.

Commands and checks executed: `make build`, `make test`, `make test-db`, focused `go test -race ./internal/cli -count=1`, both integration tests with `DEVCTL_TEST_ISSUER=http://127.0.0.1:8082/realms/devctl` and a local PostgreSQL test URL, `go vet ./...`, shell syntax, OpenAPI path/parameter validation, embedded migration SQL comparison, client packaging, and isolated installer checks. Build/test commands used `GOTMPDIR=/local/workspace/devctl-tmp`.

The new identity-provider defaults were tested using a disposable local Keycloak container with ten-minute access tokens, one day of SSO inactivity, seven days maximum SSO duration, and refresh-token rotation. Existing persistent demo realms retain their previous provider policy until an administrator changes it. The seven-day maximum is configuration, not a completed seven-day endurance test. All Kubernetes traffic in these new tests used disposable TLS API fixtures; registered remote clusters were not contacted or modified.

Implemented but not deployment-tested: automatic browser/keyring behavior on actual desktop installations, Windows/Mac process detachment, production reverse proxies and load, corporate OIDC, and automatic access against real Kubernetes workloads. Automatic mode requires the REST API and gateway to share a public HTTPS origin. The 15-second renewal interval assumes access tokens last comfortably longer than that interval; shorter lifetimes fail closed. No human-presence inference, idle workload cleanup, or automatic booking extension was added.

## 2026-11-09: demo identity persistence

A recreated Keycloak container imported Alice with a new OIDC subject while PostgreSQL retained a booking owned by her earlier subject. The ownership rejection was correct. The orphaned booking was released through the authenticated administrator endpoint with an audit reason; no Kubernetes resources were changed.

Keycloak now stores its development H2 database in a named volume. Startup migrates an existing container's stopped database before recreating it, retaining a private backup and refusing to overwrite unknown volume data. A real migration and container recreation preserved the administrator's subject on a fresh Authorization Code login; Alice's existing login also remained valid. Running the migration again was a no-op. A separate disposable volume confirmed that a fresh volume is writable by Keycloak's UID 1000, and that test volume was removed.

`make test`, `make test-db`, and `make demo-test` passed with `GOTMPDIR=/local/workspace/devctl-tmp`. The end-to-end suite completed in 7.46 seconds. The new PostgreSQL test proves that matching names/emails do not transfer ownership across subjects or issuers, while explicit administrator release records the actor/reason and frees the reservation. Shell syntax, Compose configuration, and `git diff --check` also passed. Read-only `/version` probes against the supplied remote kubeconfigs found two reachable clusters and two TLS verification failures; verification was not disabled and no cluster resources were modified.

Failure paths for unknown/incomplete migration volumes and production identity-provider recovery were not exercised against live services. H2 remains a local development choice; production identity-provider deployment is deferred.

## 2026-11-07: gateway implementation

Recorded 2026-11-07 for the updated **server-side Kubernetes gateway** architecture. This supersedes the earlier direct kubeconfig-download implementation. No company cluster was contacted or changed during this update, and no corporate identity provider was configured. No real shell startup file was edited.

## Implemented and tested

- Existing PostgreSQL reservations, exclusive-by-default bookings, holder-enabled sharing, visible co-user contacts, optional expiry, idempotency and concurrency remain working. Tests use real PostgreSQL 18.1 in disposable schemas.
- Original static-token and certificate/private-key kubeconfigs remain encrypted with AES-256-GCM in the backend registry. Gateway metadata and generated local YAML contain no upstream token, private key or original API endpoint. The former authenticated raw kubeconfig route returns HTTP 410.
- The backend forwards HTTP requests to the session's server-selected Kubernetes endpoint, using the original server-held credentials and verified TLS. Tests cover both token and mutual-TLS client authentication and prove that missing CA trust fails closed.
- Every request requires an approved devctl OIDC access token and ownership of an active, unexpired booking. An administrator cannot use another holder's gateway session merely by holding the application admin role. There is no client-supplied arbitrary destination.
- Incoming Authorization, Cookie, impersonation, forwarded identity and WebSocket bearer-auth subprotocol values do not become upstream identity. Requests retain Kubernetes API paths, query strings, verbs, payload and content type. Traversal, ambiguous session routing, CONNECT and credential-bearing upstream redirects are rejected. Failure responses do not expose credentials.
- Long-lived watch responses and raw bidirectional WebSocket/SPDY upgrades terminate after stop, expiry, invalid token or database unavailability. Polling is configurable, defaults to 1s, and individual checks time out after 5s. Upstream HTTP/1.1 preserves Kubernetes upgrades even when the API also advertises HTTP/2. Backend shutdown cancels request contexts.
- The built-in `devctl credential --session ID` emits only a valid v1 ExecCredential document with a devctl API access token and its real expiry. It refreshes an existing login where possible and never opens a browser from kubectl. Missing/expired login or ended/foreign session produces no credential JSON.
- `start` selects the resulting session; `select` updates a stable active metadata file. `kubeconfig` prints only its per-session metadata path, and `exec` sets a child's KUBECONFIG. Bash and Zsh shell integration were executed in tests; explicit shell installation was checked for idempotence against temporary RC files. No ~/.bashrc, ~/.zshrc, Fish user configuration or ~/.kube/config was changed.
- Generated plugin/shell configuration preserves nonsecret API, OIDC, profile and public-CA settings across shells. Private CA trust uses `DEVCTL_API_CA_FILE` in addition to system roots; hostname verification remains enabled. Stop and logout leave an inactive stable configuration to avoid accidental fallback to another global kubeconfig.
- Current-profile initialization replaces embedded credentials in known legacy app-owned session YAML files with inactive metadata. Tests cover regular-file/inode guards, path bounds, malformed records, unrelated file preservation and metadata preservation. This does not revoke unrelated copies or remove files in other profiles.
- Real Keycloak 26.5.2 Authorization Code + S256 PKCE login, state/nonce handling, access-token audience/group checks, refresh, provider refresh-token revocation, rejected outsiders and backend restart all pass.
- **Actual kubectl v1.34.2** ran through the HTTPS gateway against a disposable TLS Kubernetes API fixture: version, discovery, server-side apply (`--validate=false`), logs, watch, WebSocket exec, and a local HTTP roundtrip over SPDY-over-WebSocket port-forward. The upstream fixture advertises HTTP/2. A newly launched Bash shell used plain kubectl with the global selection. Cached, still-valid OIDC tokens failed after stop/logout/expiry.
- The local demo upgrades its host backend to verified HTTPS using a generated CA/certificate under `.demo/tls`, preserves the existing master key/database, and publishes gateway-only metadata. The CA metadata loader rejects private-key/mixed/malformed PEM bundles.

The Kubernetes fixture implements protocol responses, not a real Kubernetes control plane. Exec stdout is a protocol frame, not a process running in a real Pod. Port-forward uses real client transport and an in-process endpoint. These tests prove forwarding/client compatibility; they do not establish real-cluster admission, scheduling or authorization behavior.

## Commands executed and results

Build and tests used `GOTMPDIR=/local/workspace/devctl-tmp` because the host root filesystem has only about 220 MiB free; no unrelated cache or workload was removed for this update.

| Command | Result |
| --- | --- |
| `make build` | Pass; updated CLI and backend binaries |
| `make demo-up` | Pass after the NFS process-identity fix described below; PostgreSQL, Keycloak and HTTPS host backend ready |
| `make test` | Pass, `go test -race ./...`; database/Keycloak suites explicitly skip when their configuration variables are absent |
| `make test-db` | Pass; real PostgreSQL scheduling/concurrency plus gateway/API security/stream tests |
| `make demo-test` | Pass; all internal tests with real PostgreSQL, then real Keycloak/backend/CLI/kubectl end-to-end test. Latest end-to-end test: 8.09s; race harness: 9.107s |
| `go vet ./...` | Pass |
| `bash -n scripts/*.sh` | Pass |
| OpenAPI JSON/path parameter check and embedded migration comparison | Pass |

Focused runs also passed: `go test -race ./internal/cli -count=1`, `go test -race ./internal/api ./internal/store ./internal/kube ./cmd/devctld -count=1`, and `go test -race ./tests/integration -count=1 -v` with the local PostgreSQL/Keycloak test variables set.

The database schema did not need to change: existing encrypted cluster registrations, bookings, sharing and audit tables are reused. New indirect Go dependencies needed by the streaming fixture were pinned by `go mod tidy`; base container images remain pinned by digest.

## Issues caught and corrected

- Real kubectl exposed that client-go does not enable exec credential authentication for HTTP kubeconfig servers, even on loopback. The gateway now requires HTTPS and the demo uses an explicit development CA; no insecure TLS workaround was introduced. Only the development Keycloak issuer remains on explicitly enabled loopback HTTP.
- SPDY upgrades could otherwise negotiate HTTP/2 against a real API server. The gateway explicitly uses HTTP/1.1 upstream, and tests advertise HTTP/2 to check this path.
- Public CA publication originally risked accepting a combined certificate/private-key PEM file. Startup now parses and permits only certificates before publishing CA metadata.
- Rebuilding binaries on this NFS workspace renames a running executable to `.nfs...`; the old demo PID guard no longer recognized its own backend, and the initial refresh correctly refused to replace an unknown port-8080 listener. The shared ownership guard now checks the workspace executable, argv and working directory for that NFS case. Only the verified existing devctl demo process was restarted.

## Implemented but not deployment-tested

- Production cluster forwarding, actual Pod exec/log/port-forward behavior, admission, scheduling, cluster-side authorization, and performance under realistic workload.
- Corporate OIDC; the supplied organisation integration checklist still requires IT setup and approval.
- Actual desktop OS keyrings and graphical browser launching; automation uses the explicit private-file development fallback and Keycloak's real HTML login flow through a cookie-capable HTTP client.
- Fish runtime initialization (output is unit-tested; Fish is not installed), macOS and Windows runtime behavior.
- Production CA/reverse-proxy deployment, multi-host outages, production load and restore procedures. Direct HTTPS and verification are tested locally.
- The updated backend container image was not rebuilt in this iteration because of root-filesystem space limits. The source Dockerfile remains available; current application binaries and the host-based demo were built and tested. Prior container-build results belong to the superseded direct-delivery version and are not claimed for this gateway update.

## Deferred and operational limits

- No automatic namespace/RBAC/policy changes, workload or storage cleanup, resource budgeting, cluster creation, queues, upstream credential rotation or master-key rotation were added.
- Existing unmanaged or previously copied original credentials can bypass devctl until separately revoked. Migration only replaces known copies inside the current devctl profile. Imported cluster-admin permissions can allow users to obtain/create other credentials through Kubernetes; the gateway does not create a security boundary against those privileges.
- Live streams are cancelled on periodic checks, not instantaneously; already accepted operations continue. Provider group/account changes follow JWT/provider expiry semantics unless the booking is explicitly released.
