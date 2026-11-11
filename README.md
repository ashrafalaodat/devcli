# devctl

A Go backend with a full CLI, a smaller kubectl plugin, and a browser UI for **booking existing Kubernetes clusters and using them through an authenticated API gateway**. PostgreSQL holds durable reservations, labels, participant identities, audit events, and encrypted upstream kubeconfigs. Experimental OIDC login uses Authorization Code with PKCE and local Keycloak.

The original cluster kubeconfigs stay on the backend. CLI/plugin kubeconfigs contain public gateway metadata and an exec credential helper. Browser downloads contain a personal, revocable gateway token (PAT) instead, so stock kubectl works without installing another executable. Neither contains an upstream token or client private key. Kubectl runs locally and sends Kubernetes API requests through the gateway; the service does not execute arbitrary local shell commands.

```text
local kubectl → devctl gateway → selected Kubernetes API
                  │
                  └─ authenticated owner + active booking required
```

The gateway uses the permissions already present in the administrator-imported kubeconfig. devctl does not create namespaces, change Kubernetes RBAC, install policies, create clusters, issue Kubernetes ServiceAccount tokens, or clean up workloads. A registered configuration can grant broad privileges, including cluster-admin; register only credentials approved for this use. See [security and operations](docs/security.md) for the limits of this access model.

## Booking rules

- Automatic selection or a cluster ID/name and label selectors. Stable first-fit selection prefers empty clusters over shared clusters.
- A booking is exclusive by default. A second booking is rejected with HTTP 409 / CLI exit 4 unless the controlling holder explicitly enabled sharing.
- Sharing permits two simultaneous developers by default, configurable by administrators from 2 to 10. Participants see usernames, display names, email addresses, and session IDs so they can coordinate manually.
- Only the controlling holder can enable/disable sharing. Disabling sharing prevents new joins without evicting participants. When the controller leaves, the oldest remaining holder becomes controller and sharing resets to private.
- Sessions last until `stop` or `logout`. An optional `--ttl` from 1 minute through 168 hours expires a booking server-side. Closing a terminal or missing a heartbeat does not release the cluster; activity heartbeats renew gateway authorization only.
- `logout` releases **all bookings for the authenticated identity**, clears the current local login/selection, and attempts refresh-token revocation. Other participants' bookings remain active.
- Unavailable requests fail immediately. This version does not queue requests; `wait` checks whether an existing booking is active.

Stop, expiry, logout, and administrator release prevent new requests through that booking's gateway route. Long-running requests are also subject to backend authorization rechecks; work already accepted by Kubernetes is not rolled back. No workloads or data are deleted. Existing unmanaged kubeconfigs and original credentials distributed by earlier devctl versions can still bypass the gateway and must be handled separately.

## Choose an access method

| Method | Local installation | Authentication | Controls |
| --- | --- | --- | --- |
| Full CLI | `devctl` | Short-lived access token, automatically refreshed with a stored refresh token | Book, select, share, renew, stop, credentials, and administrator commands |
| kubectl plugin | `kubectl-devctl` | The same SSO, refresh rotation, and credential store as the CLI | Login, setup, status, logout; normal Kubernetes commands through kubectl |
| Browser | Stock `kubectl` only | Browser SSO; downloaded kubeconfig carries one expiring, revocable PAT | Booking and credential controls in the UI, plus role-protected administrator actions |

The smaller plugin command set is a convenience, not a separate authorization role. The backend always enforces the authenticated user's permissions. See [the three-client decision](docs/adr-004.md).

### Browser: no extra executable

Run `make demo-up`, then open **https://127.0.0.1:9090/** and trust the local public CA at `.demo/tls/ca.crt` through your browser's certificate settings. Do not disable TLS verification. Sign in with a development account, book an available cluster, and create/download a personal kubeconfig from that booking. The UI shows sharing participants and contact details, expiry, credential metadata and revocation controls.

```bash
chmod 600 ~/Downloads/devctl-SESSION_ID.yaml
export KUBECONFIG="$HOME/Downloads/devctl-SESSION_ID.yaml"
kubectl get namespaces
```

Use the actual downloaded filename. This YAML contains a sensitive **gateway-only PAT**, not the original cluster credentials. A PAT is tied to one owned active booking, defaults to eight hours, has a seven-day maximum, and is capped by booking expiry. It cannot call the reservation/admin API or refresh itself. After expiry, sign in through the browser and download a replacement. Revocation, logout or an ended booking blocks further gateway use and closes open connections after the normal authorization recheck. Removing a user's IdP group alone does not immediately revoke an existing PAT; administrators must revoke their credentials or release their bookings.

Administrators see controls to register an approved static kubeconfig, change maintenance with a reason, release a booking with a reason, inspect audit events, and revoke personal credentials. Registration encrypts the imported file; these reservation/admin operations do not contact or modify the cluster. Selecting a file in the admin UI does not make it visible to ordinary developers.

Browser logout releases all bookings and revokes all PATs for that identity, clears the current browser session, and attempts provider refresh-token revocation. It does not delete cluster workloads. Closing the browser alone does not log out.

For an **existing persistent demo realm**, first open the Keycloak administration console at `http://127.0.0.1:8081/admin/`, select the `devctl` realm, and import `deploy/keycloak-web-client.json` under **Clients → Import client**. Fresh realms already include this client. Its exact approved callback is `https://127.0.0.1:9090/auth/callback`. Add the client without recreating the realm or deleting volumes: changing user subjects breaks ownership of existing reservations.

When browsing a demo running on a remote server, forward local ports 9090 and 8081 to the same remote ports, keep the forwarding session open, and open the exact `https://127.0.0.1:9090/` URL. The browser callback needs no port 18000; that loopback port is used by CLI/plugin login only. Configure real deployments with reachable HTTPS gateway/issuer URLs and approved exact redirects.

### Plugin: smaller terminal interface

Build/distribute it with `make plugin-package`. Extract `dist/devctl-plugin-<os>-<arch>.tar.gz` on the client and run:

```bash
./install.sh --api https://devctl.example.test \
  --issuer https://identity.example.test/realms/engineering --shell bash
# For a private gateway CA, add --ca-file /path/to/public-gateway-ca.pem.
```

The archive contains only `kubectl-devctl` and its installer; it does not require `devctl`. The installer defaults to `~/.local/bin` and optionally installs the same explicit shell integration. Put that directory on PATH so kubectl can discover the plugin. On the local demo:

```bash
source .demo/env
export PATH="$PWD/bin:$PATH"
export KUBECONFIG="$(kubectl devctl login)"
# Or choose a cluster: kubectl devctl login --cluster cluster-4196 --new-booking
kubectl get namespaces
kubectl devctl status
kubectl devctl logout
```

`login` completes SSO when needed and books or reuses a compatible environment; stdout is only the config path. `kubectl devctl setup` prepares automatic first-use login without booking. Both configure kubectl to invoke the installed plugin itself for credentials. Access-token refresh and refresh-token rotation happen automatically outside the kubeconfig, using the OS credential store or an explicitly enabled development fallback. Use the full CLI or UI for sharing, renewal, stop and administrator controls.

### Full CLI: normal kubectl commands and management

The automatic workflow needs one setup step. After that, developers use ordinary kubectl commands; the configured credential helper handles login, allocation, and refresh. The backend REST API and Kubernetes gateway must use the same public HTTPS origin for this mode. Explicit session kubeconfigs still support the separately configured gateway origin.

With the local demo running, prepare the automatic config in the current terminal:

```bash
source .demo/env
export KUBECONFIG="$(./bin/devctl setup)"
# Optional specific cluster: ./bin/devctl setup --cluster cluster-4196 --new-booking
kubectl get namespaces
```

Setup prints only the config path. It does not log in or book a cluster. On the first interactive kubectl request, the helper opens browser SSO, or prints a URL when `DEVCTL_NO_BROWSER=1`. It then reuses a compatible booking owned by that identity or creates an exclusive booking. Concurrent commands and later terminals using this profile stay on that exact booking. Noninteractive commands can reuse an existing login but never launch a browser. Only public gateway metadata is stored in the kubeconfig; original Kubernetes credentials remain encrypted on the backend.

For the remote demo, keep SSH forwards for local ports 8081 and 18000 open and use `export DEVCTL_NO_BROWSER=1` before running kubectl. Open the printed URL unchanged in the laptop browser. The callback port supports one browser login at a time. Once logged in, concurrent kubectl processes share the profile's token refresh lock.

Actual gateway traffic and authorized open streams record activity. A detached helper refreshes credentials and renews server authorization while that activity continues. It polls every 15 seconds and exits after two minutes without Kubernetes activity, on authentication failure, or when the booking ends. Its own status/heartbeat calls do not count as activity. Missing heartbeats never release the cluster or delete workloads. Automatic streams can continue across an access-token refresh through this authenticated renewal channel; older explicit session routes continue to close at their original token expiry.

Stopping a session, optional expiry, logout, and administrator release all block that binding. A subsequent kubectl command cannot silently acquire another cluster. Explicitly reactivate with:

```bash
export KUBECONFIG="$(./bin/devctl setup --new-booking)"
kubectl get namespaces
```

Changing the configured cluster, selectors, or TTL also requires `--new-booking`. An existing compatible owned booking keeps its existing lease; use `renew` explicitly to extend it. A profile is pinned to its first authenticated identity, so separate accounts need separate `DEVCTL_CONFIG_DIR` values. Session management and administrator commands remain available below.

To distribute the client, a service operator runs `make client-package`. This creates `dist/devctl-client-<os>-<arch>.tar.gz` containing the helper binary and installer. On the client machine, extract that archive and run:

```bash
./install.sh --api https://devctl.example.test --issuer https://identity.example.test/realms/engineering \
  --shell bash
# For a private service CA, also pass --ca-file /path/to/public-gateway-ca.pem.
# Omit --shell to leave startup files alone and receive the current-terminal command.
```

The installer puts the helper in `~/.local/bin` (override with `DEVCTL_INSTALL_DIR`). Optional `--shell bash|zsh|fish` installs the existing bounded shell block; `--rc-file FILE` can target another startup file. Open a new shell after installation, then run kubectl. This archive uses the native build platform; Linux is the tested platform. It contains no login tokens, server master key, or upstream kubeconfigs. See [the automatic-access decision](docs/adr-003.md) for authentication lifetime and renewal details.

## Local setup

Prerequisites: Go 1.26, Docker Engine with Compose, `curl`, `openssl`; Linux is the tested host. `kubectl` is needed for the end-to-end client tests. These setup commands create only local demo services, not Kubernetes resources.

```bash
make build
make test
make demo-up
source .demo/env
export PATH="$PWD/bin:$PATH"
devctl login
```

The demo binds PostgreSQL to `127.0.0.1:54329`, Keycloak to `127.0.0.1:8081`, and the host backend/gateway to `https://127.0.0.1:9090`. The issuer is exactly `http://127.0.0.1:8081/realms/devctl`; validation is not rewritten to use a container hostname. Only the Keycloak issuer uses explicitly enabled loopback HTTP. The demo generates a development CA and server certificate under `.demo/tls`, configures backend HTTPS, and exports `DEVCTL_API_CA_FILE` so the CLI trusts that CA without disabling certificate verification. Gateway URLs use HTTPS even on loopback: client-go does not use exec credential authentication for an HTTP kubeconfig server. The Keycloak realm is packaged in a small image, so the demo also works with Docker daemons that cannot mount the workspace.

PostgreSQL reservations and Keycloak's development database use separate named volumes. Recreating the containers preserves user identity IDs and booking ownership. On the first upgrade from a demo without Keycloak storage, `make demo-up` stops Keycloak briefly, keeps a private backup under `.demo/keycloak-migration.*`, and copies its database into the new volume before recreating it. It refuses to overwrite unknown volume data. Already orphaned bookings belong to their original OIDC identities: an administrator must release them with `devctl admin release SESSION_ID --reason 'Identity provider was reset'`; matching usernames or email addresses do not transfer ownership.

After moving the repository, run `make demo-up` from its new directory and source `.demo/env` again. Startup updates the generated paths while preserving the saved database settings and encryption key. Keep `.demo` when moving an existing demo with registered clusters: its encryption key is required to read the saved credentials. Run `devctl login` and `devctl select SESSION_ID` again if the profile path changed, and rerun `devctl shell install` if previously installed so new shells use the new paths.

After updating an existing demo from port 8080, rerun `make demo-up` and `source .demo/env`. Log in again because local login profiles include the API URL. If shell integration was already installed, rerun `devctl shell install --shell bash` (or your shell) and reload it with `eval "$(devctl shell init --shell bash)"`. Existing database registrations and bookings remain intact; use `devctl select SESSION_ID` to reconnect an existing booking through the new port.

Development-only accounts:

| Username | Password | Group |
| --- | --- | --- |
| `alice` | `alice-dev-only` | developers |
| `bob` | `bob-dev-only` | developers |
| `admin` | `admin-dev-only` | administrators |
| `outsider` | `outsider-dev-only` | none; rejected by devctl |

Keycloak bootstrap console credentials are `bootstrap-admin` / `bootstrap-dev-only`. Never reuse demo credentials elsewhere.

The demo registry starts empty. Register a kubeconfig only when its owner has approved its use by the gateway for approved devctl developers. Registration reads the selected local context and encrypts it in the database; it does not call the Kubernetes API. Subsequent kubectl commands do contact the registered API through the gateway. None of the remote kubeconfigs discovered through `tenv` has been imported by this project's automated setup or tests.

```bash
# Log in as the development admin first.
devctl admin register --id dev-a --name 'Development A' \
  --kubeconfig /path/to/approved-kubeconfig --context CONTEXT_NAME \
  --label region=eu,type=integration

devctl logout
devctl login                         # choose alice
devctl whoami
devctl clusters
devctl start --cluster dev-a          # books and selects this session
# Or: devctl start --selector region=eu,type=integration
# Or: devctl start                     # chooses automatically

devctl sessions
devctl sessions --all
devctl status SESSION_ID
devctl share SESSION_ID               # holder permits one co-user by default
# devctl share SESSION_ID --off       # prevents additional joins

devctl select SESSION_ID              # select an existing active booking
```

## Use the selection in every shell

Install the shell integration once for the shell you use:

```bash
devctl shell install --shell bash
# Or: devctl shell install --shell zsh
# Or: devctl shell install --shell fish
```

The command adds an idempotent devctl block to that shell's startup file; `--rc-file FILE` can choose a specific startup file. Bash login shells must load the configured startup file as usual, for example by sourcing `.bashrc` from `.bash_profile`. It stores only nonsecret backend/profile/OIDC settings, the public CA file path when configured, and KUBECONFIG in the startup file; no token or private key is written there. Load it in the current Bash shell with:

```bash
eval "$(devctl shell init --shell bash)"
kubectl get pods --all-namespaces
```

New shells load the same active kubeconfig path automatically. `start` and `select` update that stable file atomically, so subsequent commands in all shells using the same profile use the newly selected session. Already-running commands retain their current connection until it completes or gateway authorization ends. This is intentionally a profile-wide selection, rather than a different automatic selection in each terminal. devctl does not overwrite `~/.kube/config`.

`devctl kubeconfig SESSION_ID` is still available for tools that require a path: it writes a separate **gateway-only** 0600 kubeconfig and prints only its absolute path, including with `--json`. It does not download the original kubeconfig. `devctl exec SESSION_ID -- kubectl get namespaces` runs a child with the chosen gateway-only config without changing the profile-wide selection.

An explicit session config invokes `devctl credential --session SESSION_ID`. That plugin refreshes existing devctl login when possible, checks the active owned booking, and returns only a `client.authentication.k8s.io/v1` ExecCredential document with the backend-intended OIDC access token and its expiry. This manual mode never opens a browser from inside kubectl. If login cannot be refreshed, run `devctl login` explicitly. The automatic setup above opts into interactive first-use login through `devctl credential --auto BINDING_ID`. Both tokens authenticate to devctl, not directly to Kubernetes.

```bash
devctl stop SESSION_ID
devctl logout
```

Logout replaces the selected metadata with an inactive config at the stable path. Stop does this only if the stopped session is selected. The shell integration stays installed and KUBECONFIG stays pointed at that path, so kubectl fails closed rather than switching back to a previously configured administrator context. Authentication and the backend booking check remain necessary even if someone copies the generated YAML.

For two local demo identities, use separate profiles before login and generate shell integration for each profile:

```bash
source .demo/env
export DEVCTL_CONFIG_DIR="$PWD/.demo/alice"  # use .demo/bob for Bob's profile
export PATH="$PWD/bin:$PATH"
devctl login
eval "$(devctl shell init --shell bash)"
```

Profiles isolate keyring entries, fallback token files, and active selections. Ownership uses issuer plus subject; email is display/contact information. On profile initialization, devctl replaces credential-bearing files from the former implementation at that profile's app-owned `s-UUID.yaml` and `active-kubeconfig` paths with inactive metadata. It refuses unsafe symlinks and oversized/malformed legacy records instead of guessing. Other profiles, unrelated files, backups, and `~/.kube/config` are untouched; changing the backend URL can select a different profile, so old profiles require separate cleanup and credential-revocation decisions. Shell startup files are modified only by an explicit `shell install` command; implementation tests use temporary startup files, not the user's real dotfiles.

## Optional leases, retries, and administration

```bash
devctl start --ttl 2h --idempotency-key MY_UNIQUE_REQUEST_KEY
devctl renew SESSION_ID --ttl 4h

devctl admin maintenance dev-a --reason 'Manual maintenance'
devctl admin maintenance dev-a --enabled=false --reason 'Maintenance complete'
devctl admin release SESSION_ID --reason 'Owner requested manual release'

# Optional native-kubectl credential management from the full CLI:
devctl token create --session SESSION_ID --name laptop --ttl 8h
# Prints only the path to a new 0600 PAT kubeconfig, never its contents.
devctl token list
devctl token revoke PAT_ID
# Administrators revoking another user's PAT must also supply --reason.
```

Retry with the same parameters and idempotency key to get the original reservation, including after it ends. A different request with that key is a conflict. The CLI prints its generated key to stderr so an interrupted request can be retried safely. Starting again without the key is a new request.

Maintenance prevents new bookings without evicting current holders. Administrative release ends gateway access for that booking; it does not clean the cluster or revoke credentials held outside devctl. Upstream credentials are excluded from cluster/session/connection responses, generated files, and audit records. The former raw-kubeconfig download endpoint is no longer available.

## Verification and teardown

```bash
make test             # unit tests; database/Keycloak suites skip without configuration
make test-db          # real PostgreSQL concurrency and API/gateway authorization tests
make demo-test        # real PostgreSQL + Keycloak + CLI/backend; disposable TLS API fixture
make browser-test     # isolated local Keycloak + browser SSO/PAT/native kubectl test
make demo-down        # only this project's containers, volumes and .demo directory
```

`demo-test` requires `demo-up` first. `browser-test` also uses the existing PostgreSQL service and local pinned Keycloak image, but starts a disposable identity-provider container on `127.0.0.1:18081` and a test gateway on `127.0.0.1:19090`; it removes that test container afterward and leaves the persistent demo realm untouched. Tests create uniquely named PostgreSQL schemas and delete only those schemas. End-to-end tests use the real Keycloak Authorization Code + PKCE flow and a disposable TLS test server representing the Kubernetes API. Gateway forwarding and kubectl integration tests do not modify a real Kubernetes cluster. Mock API transport tests do not prove real-cluster CNI, admission, scheduling, workload behavior, or all Kubernetes streaming implementations; the exact checks actually run are in [the verification record](docs/verification.md).

`make demo-down` intentionally deletes both demo databases, demo identities, private migration backups, and the encryption key. Use `docker compose stop` to pause the containers while preserving data; run `make demo-up` to resume. Other Docker projects and real clusters are untouched. See [security and operations](docs/security.md), [organisation OIDC checklist](docs/organisation-sso.md), [architecture decisions](docs/adr-001.md), [the gateway decision](docs/adr-002.md), and [OpenAPI](docs/openapi.json).

## Configuration

Backend:

| Variable | Meaning |
| --- | --- |
| `DATABASE_URL` | PostgreSQL URL; use verified TLS outside the local demo |
| `DEVCTL_MASTER_KEY` | Base64 encoding of exactly 32 random bytes; keep outside the database |
| `DEVCTL_LISTEN` | Default `127.0.0.1:9090` |
| `DEVCTL_PUBLIC_URL` | Developer-facing HTTPS gateway origin, used in generated configs. Required outside the local TLS-listener default; HTTP gateway URLs are rejected even on loopback |
| `DEVCTL_GATEWAY_CA_FILE` | Optional PEM CA bundle for developer-facing gateway TLS; only its public certificate data is returned to clients |
| `DEVCTL_GATEWAY_RECHECK_INTERVAL` | Authorization recheck interval for long requests; default `1s`, range `100ms` through `30s`. A stalled check fails closed after its `5s` timeout |
| `DEVCTL_TLS_CERT`, `DEVCTL_TLS_KEY` | HTTPS listener certificate/key; required for non-loopback binding |
| `DEVCTL_ISSUER` | Trusted OIDC issuer URL |
| `DEVCTL_OIDC_CONFIG` | JSON overrides of issuer, client ID, API audience, scopes, redirect, group mapping and access-token marker |
| `DEVCTL_WEB_CLIENT_ID` | Browser OIDC client; default `devctl-web`, separate from the native CLI/plugin client |
| `DEVCTL_WEB_CLIENT_SECRET` | Optional confidential browser-client secret; backend only |
| `DEVCTL_WEB_SESSION_TTL` | Absolute browser session duration, default `8h`, range `1m` through `168h` |
| `DEVCTL_DEV_HTTP=1` | Explicit development-only HTTP issuer allowance; never permits an HTTP gateway kubeconfig |

Developers need network access to the gateway and identity provider. The backend needs network access to each registered Kubernetes API and the identity provider, possibly through the company VPN. Normal gateway use does not require developers to reach the Kubernetes API directly. Both developer-facing gateway TLS and backend-to-cluster TLS are verified. The gateway intentionally uses HTTP/1.1 upstream so both WebSocket and SPDY upgrades work even when an API server advertises HTTP/2.

CLI also uses `DEVCTL_API` (or `--api`), `DEVCTL_API_CA_FILE` (optional public PEM CA added to system trust for backend requests), `DEVCTL_CONFIG_DIR`, and `DEVCTL_NO_BROWSER=1` (print login URL without starting a browser). Authentication tokens go to the OS credential store by default. `DEVCTL_DEV_TOKEN_FILE=1` explicitly permits the private-file development fallback used by the demo. Normal commands do not print tokens; the credential plugin intentionally sends its ExecCredential token only to kubectl through stdout. Never log or capture that output as routine diagnostics.

Exit codes: 0 success, 1 general/usage failure, 2 invalid `exec` usage, 3 authentication/authorization failure, 4 reservation conflict, 5 missing session/cluster. `exec` preserves child exit codes. `--json` returns JSON; diagnostics go to stderr. Session creation requires an authenticated access token and an `Idempotency-Key`.
