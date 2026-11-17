# Automatic cluster health monitoring

Status: implemented. This describes the current behavior; it supersedes the earlier opt-in rollout proposal. See [verification](verification.md) for executed tests and deployment limits.

## Default behavior

The single backend application runs the health worker alongside the API, gateway, expiry worker and lifecycle sender. Every live registered cluster is checked automatically. There is no monitoring enablement, rollout mode or environment switch. Migration11 removes the former `health_mode` column while preserving credentials and reservations. New registrations immediately receive a due observation row.

Health is a prerequisite for **new** reservations, including shared joins and automatic PAT booking. Unknown, recovering, failing, stale or configuration-mismatched observations fail closed. Existing reservations, primary selection and gateway access do not depend on subsequent health results; ordinary authorization, expiry and connection errors still apply. Maintenance and lifecycle holds are separate placement conditions.

The backend runs outside the clusters and needs network access to their registered Kubernetes endpoints, including any required VPN. Replicas must have equivalent network, proxy and CA access. Register only endpoints approved for these automatic read-only requests.

## Fixed probe profiles

The default `api-ready.v1` profile checks:

1. Verified TLS and a parseable Kubernetes version from `GET /version`.
2. API-server readiness using `GET /readyz`.
3. Current discovery for core/v1, apps/v1 and batch/v1 using `GET /api` and `GET /apis`.

The probe negotiates Kubernetes aggregated discovery v2 and checks freshness and required resources. For legacy discovery it follows the fixed `/api/v1`, `/apis/apps/v1` and `/apis/batch/v1` paths. A cycle makes at most seven GET requests. A stale or missing required discovery group fails the check; arbitrary extension API groups do not become implicit requirements.

An administrator may explicitly select `discovery-only.v1` if the approved identity cannot read readiness. That profile omits `/readyz` and always exposes that lower assurance. A403 does not cause an automatic downgrade or prove that the cluster is down. The fixed profiles are available through the cluster editor or the existing health-profile operation; they are not monitoring on/off settings.

The worker decrypts the original registered static kubeconfig in memory, uses the official client-go transport, preserves verified TLS, certificate identity and endpoint prefixes, and refuses redirects. No uploaded executable is run. Checks never create Kubernetes objects, namespaces, RBAC, reviews or workloads. Developer PATs and the public gateway are not used for probing. Passing public discovery does not prove the imported identity authenticated successfully or can deploy applications; `identity_verification` remains `NOT_CHECKED`.

## Timing and state

| Rule | Value |
| --- | --- |
| Normal interval |30s with ±20% jitter |
| Individual request budget |3s |
| Entire probe budget |10s |
| Database lease |20s |
| Maximum observation age |90s |
| Concurrent clusters |Four per backend instance |
| Recovery |Two consecutive passing cycles |

These values are fixed implementation defaults, not additional user settings. Response reads and decompressed sizes are bounded. Retries remain scheduled work, not an unbounded loop inside one API request.

A first failed required check immediately blocks new placement. Two consecutive successful cycles establish `PASSING`; the first is `RECOVERING`. Missing observations are `UNKNOWN`. Freshness is derived using database UTC time at the reservation decision, so a dead worker cannot leave a cluster indefinitely healthy. A stale gap resets the recovery counter. Checked-at and last-success timestamps describe observations, never developer activity.

Health and availability are distinct: a healthy cluster can be occupied, in maintenance or waiting for a lifecycle callback. A successful API check does not establish spare resources, Pod scheduling, storage, CNI enforcement or application readiness. A passing observation cannot guarantee the next request succeeds.

## Durable worker and transaction boundaries

One `cluster_health` row per cluster stores the latest bounded result, safe component outcomes, timing, recovery count, next check time and claim state. Raw upstream bodies, errors, URLs, headers and credentials are excluded.

The worker claims due rows in a short PostgreSQL `SKIP LOCKED` transaction. Each claim records a random lease token, increasing probe sequence, configuration generation and profile-policy revision. Network operations happen after that transaction commits. Publication takes the reservation lock, checks every claim fence and deadline, and stores only an accepted current result. Expired or superseded workers cannot overwrite a newer observation. Multiple backend instances coordinate through PostgreSQL rather than in-memory locks.

The normal reservation transaction reads the current observation before placing a booking. A shared scheduler predicate serves manual allocation and PAT fallback; fallback continues to later compatible healthy candidates. Existing idempotency keys still replay the original booking rather than allocating another one. Expected placement rejection commits valid expiry work without releasing a failed lifecycle hold.

Restarting preserves claims, reservations and fresh observations; expired claims are retried. Probes and status reads do not run reservation expiry, create a booking, extend inactivity, update PAT use or alter primary selection.

## Editing registered credentials

Migration12 adds `registry_version` for stale-editor protection. Administrators edit registration metadata and optionally replace the encrypted kubeconfig through the [versioned editor](adr-014.md). Runtime observations do not change that editor version.

A database trigger increments `configuration_generation` when credentials change and `health_policy_revision` when the fixed profile changes. Either change invalidates the old result, resets recovery, schedules a fresh check and fences every older claim. Deregistration removes the observation and prevents a delayed publisher from recreating it. No raw kubeconfig is included in health APIs.

Gateway connections pin the exact encrypted snapshot's configuration generation. Replacing credentials ends old streams within the existing authorization recheck interval and timeout. New requests use the new connection, preserving the reservation and authentication state. This does not revoke the old Kubernetes credential or undo already accepted operations.

## Lifecycle verification

A successful blocking lifecycle callback creates a fresh verification barrier: old health observations and in-flight claims cannot release its hold. Two passing cycles from the current configuration, started after that barrier, are required. Health always runs; a backend outage or cluster failure retains the hold. Multiple holds and manual maintenance remain independent. See [lifecycle automation](lifecycle-automations-architecture.md).

## API, CLI and GUI

Approved users can read `GET /v1/clusters/{id}/health` and safe cluster-list summaries. Administrators can request a coalesced check using `POST /v1/admin/clusters/{id}/health-check` with an audit reason. This queues work and never accepts an asserted passing result or caller-provided endpoint.

```bash
devctl clusters
devctl admin cluster status CLUSTER_ID --json
devctl admin cluster check CLUSTER_ID --reason 'Investigate connectivity' --wait --timeout 2m
devctl admin cluster profile CLUSTER_ID --profile discovery-only.v1 --reason 'Reviewed readiness permission exception'
```

A completed cycle may still be `RECOVERING`; CLI waiting does not promise passing health after one request. Failed checks return exit code4. The Slate registry shows Health separately from Placement and Holders. Its Health dialog shows timestamps, fixed diagnostic categories, component outcomes and assurance coverage. Current holders retain release, selection and contact controls during an outage. Browser mutations require authentication, administrator authorization, exact Origin and CSRF protection.

The public backend `/healthz` checks its process; `/readyz` checks PostgreSQL. Neither becomes dependent on remote cluster reachability.

## Validation and limitations

Unit and real PostgreSQL tests cover classification, legacy/aggregated discovery, bounded transport, default scheduling, claim races, current-version publication, staleness, recovery, concurrent reservation accounting, migration and preservation of activity. Integration uses the actual backend worker, verified-TLS disposable Kubernetes protocol fixtures and local Keycloak browser SSO. Native Kubernetes clients and the browser exercise placement, PAT fallback, credential edits and restart behavior.

Protocol fixtures do not establish real workload compatibility or network isolation. No cluster resources, RBAC or corporate identity systems are modified. Arbitrary probes, administrator-supplied URLs, per-cluster timers, health history, active identity/permission reviews, metrics exporters and multiple network-domain observations remain outside this implementation.
