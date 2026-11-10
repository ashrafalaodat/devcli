# devctl

A Go backend and CLI for **booking existing Kubernetes clusters and using them through an authenticated API gateway**. PostgreSQL holds durable reservations, labels, participant identities, audit events, and encrypted upstream kubeconfigs. Experimental OIDC login uses a public CLI client and is tested with local Keycloak.

The original cluster kubeconfigs stay on the backend. A developer's local kubeconfig contains the gateway address, public TLS trust information, and an instruction to run the **devctl credential plugin**. It contains no upstream token or client private key. Kubectl runs locally and sends Kubernetes API requests through the gateway; the service does not execute arbitrary local shell commands.

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
- Sessions last until `stop` or `logout`. An optional `--ttl` from 1 minute through 168 hours expires a booking server-side. Closing a terminal does not log out; no CLI heartbeat is used.
- `logout` releases **all bookings for the authenticated identity**, clears the current local login/selection, and attempts refresh-token revocation. Other participants' bookings remain active.
- Unavailable requests fail immediately. This version does not queue requests; `wait` checks whether an existing booking is active.

Stop, expiry, logout, and administrator release prevent new requests through that booking's gateway route. Long-running requests are also subject to backend authorization rechecks; work already accepted by Kubernetes is not rolled back. No workloads or data are deleted. Existing unmanaged kubeconfigs and original credentials distributed by earlier devctl versions can still bypass the gateway and must be handled separately.

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

The generated config invokes `devctl credential --session SESSION_ID`. That plugin refreshes existing devctl login when possible, checks the active owned booking, and returns only a `client.authentication.k8s.io/v1` ExecCredential document with the backend-intended OIDC access token and its expiry. It never opens a browser from inside kubectl. If login cannot be refreshed, run `devctl login` explicitly. The token authenticates to devctl, not directly to Kubernetes.

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
```

Retry with the same parameters and idempotency key to get the original reservation, including after it ends. A different request with that key is a conflict. The CLI prints its generated key to stderr so an interrupted request can be retried safely. Starting again without the key is a new request.

Maintenance prevents new bookings without evicting current holders. Administrative release ends gateway access for that booking; it does not clean the cluster or revoke credentials held outside devctl. Upstream credentials are excluded from cluster/session/connection responses, generated files, and audit records. The former raw-kubeconfig download endpoint is no longer available.

## Verification and teardown

```bash
make test             # unit tests; database/Keycloak suites skip without configuration
make test-db          # real PostgreSQL concurrency and API/gateway authorization tests
make demo-test        # real PostgreSQL + Keycloak + CLI/backend; disposable TLS API fixture
make demo-down        # only this project's containers, volumes and .demo directory
```

`demo-test` requires `demo-up` first. Tests create uniquely named PostgreSQL schemas and delete only those schemas. End-to-end tests use the real Keycloak Authorization Code + PKCE flow and a disposable TLS test server representing the Kubernetes API. Gateway forwarding and kubectl integration tests do not modify a real Kubernetes cluster. Mock API transport tests do not prove real-cluster CNI, admission, scheduling, workload behavior, or all Kubernetes streaming implementations; the exact checks actually run are in [the verification record](docs/verification.md).

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
| `DEVCTL_DEV_HTTP=1` | Explicit development-only HTTP issuer allowance; never permits an HTTP gateway kubeconfig |

Developers need network access to the gateway and identity provider. The backend needs network access to each registered Kubernetes API and the identity provider, possibly through the company VPN. Normal gateway use does not require developers to reach the Kubernetes API directly. Both developer-facing gateway TLS and backend-to-cluster TLS are verified. The gateway intentionally uses HTTP/1.1 upstream so both WebSocket and SPDY upgrades work even when an API server advertises HTTP/2.

CLI also uses `DEVCTL_API` (or `--api`), `DEVCTL_API_CA_FILE` (optional public PEM CA added to system trust for backend requests), `DEVCTL_CONFIG_DIR`, and `DEVCTL_NO_BROWSER=1` (print login URL without starting a browser). Authentication tokens go to the OS credential store by default. `DEVCTL_DEV_TOKEN_FILE=1` explicitly permits the private-file development fallback used by the demo. Normal commands do not print tokens; the credential plugin intentionally sends its ExecCredential token only to kubectl through stdout. Never log or capture that output as routine diagnostics.

Exit codes: 0 success, 1 general/usage failure, 2 invalid `exec` usage, 3 authentication/authorization failure, 4 reservation conflict, 5 missing session/cluster. `exec` preserves child exit codes. `--json` returns JSON; diagnostics go to stderr. Session creation requires an authenticated access token and an `Idempotency-Key`.
