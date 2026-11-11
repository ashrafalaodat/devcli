# Gateway verification record

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
