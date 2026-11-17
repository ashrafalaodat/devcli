# Lifecycle events, webhooks and completion callbacks

Status: proposed architecture, not implemented. Based on the application at commit `bd7136c`. Examples below describe new interfaces and use fictional resources. This document does not authorize contacting a pipeline, modifying a real cluster or connecting a corporate identity provider.

## Recommended approach

Add **Events & Automations** to the existing Go backend and React administration UI. Administrators subscribe an HTTPS endpoint to selected application events, optionally filtered by cluster ID, registry labels or a bounded set of event fields. Deliver notifications asynchronously. For specifically supported resource transitions, create a workflow that holds the cluster out of placement until external work completes and local verification succeeds.

Use PostgreSQL for immutable event records, a transactional delivery outbox, operation state and independent placement holds. Run bounded workers inside `devctld`; do not introduce Redis, Kafka, another service or a general-purpose workflow language. Reinstallation is one configured integration, alongside notifications, inventory synchronization and other external actions.

The companion [cluster health architecture](cluster-health-architecture.md) supplies an independent observation gate. A successful pipeline callback is not evidence that its Kubernetes endpoint is usable. Conversely, a healthy Kubernetes endpoint must not bypass unfinished automation.

## Current application and integration points

| Existing code | Current behavior | Required extension |
| --- | --- | --- |
| [`internal/store/store.go`](../internal/store/store.go), `Store.update` | Serializes reservation changes with a PostgreSQL advisory transaction lock | Keep that lock for atomic business events, rule matching and placement holds |
| `Tx.stop`, `Store.Stop`, `Store.Logout` in the same file | Release a booking, repair primary/controller and audit; logout releases the owner's bookings but preserves PATs | Emit normalized ending events through one transaction helper |
| `Tx.expire` in the same file | Expires inactivity leases; also runs from reads and booking/gateway paths | Use the same final-participant transition as explicit release |
| [`internal/store/pat_booking.go`](../internal/store/pat_booking.go), `autoBookPAT` | Can allocate a free cluster when an opted-in PAT has no primary | Respect automation holds and fresh health in this path as well as manual booking |
| [`internal/store/cluster_update.go`](../internal/store/cluster_update.go) | Audited, transactional maintenance and registry-label changes | Publish structured before/after events and protect rule snapshots |
| [`internal/store/deregister.go`](../internal/store/deregister.go) | Refuses active bookings, archives registry metadata and removes encrypted credentials | Refuse unresolved destructive operations by default; never let callbacks revive retired clusters |
| [`internal/store/schema.sql`](../internal/store/schema.sql), `audit` | Stores actor/action/object/detail history | Keep audit history; add typed events and delivery state rather than parsing audit text |
| [`internal/api/gateway.go`](../internal/api/gateway.go) | Pins requests to a booking and primary version; monitor ends access after release/switch/authorization loss | Add observable draining before destructive external work; preserve normal credential and stream checks |
| [`cmd/devctld/main.go`](../cmd/devctld/main.go) | Runs API/gateway and periodic expiry work in one process | Start cancellable, bounded automation workers and lease recovery |

Today `clusters.maintenance` only prevents new placements. It does not end an active booking or prove that in-flight Kubernetes operations have stopped. At that original baseline there was no callback API, delivery worker, upstream credential replacement API or cluster health worker. Core opt-in health monitoring is now implemented as described in the companion document; the lifecycle automation interfaces here remain proposed.

## Event catalogue and dynamic subscriptions

Expose a versioned catalogue generated from explicit event definitions, with JSON schemas, allowed filters, sensitivity and whether a blocking workflow is permitted. Configuration changes do not require deployment. Adding a genuinely new business event or a new permitted state effect still requires code and tests.

Start with successful, committed business transitions:

| Proposed event | Existing action(s) it represents | Permitted mode |
| --- | --- | --- |
| `booking.created.v1` | `book`; optionally metadata identifying PAT fallback | Notification |
| `booking.ended.v1` | `release` or `expire`, with an explicit reason enum | Notification |
| `cluster.became_idle.v1` | Active participant count transitions from positive to zero | Notification or cluster-blocking workflow |
| `cluster.sharing_changed.v1` | `share` | Notification |
| `cluster.registered.v1`, `cluster.deregistered.v1` | `register`, `deregister` | Notification |
| `cluster.labels_changed.v1`, `cluster.maintenance_changed.v1` | Registry label update, manual maintenance change | Notification |
| `developer.primary_changed.v1`, `developer.booking_limit_changed.v1` | Primary selection/promotion, booking-limit changes | Notification |
| `credential.created.v1`, `credential.revoked.v1`, `credential.policy_changed.v1` | PAT lifecycle and automatic-booking policy | Notification; never include the credential |
| `application.inactivity_policy_changed.v1` | Administrator inactivity policy change | Notification |
| `identity.login_succeeded.v1` | An actual completed application login | Notification |

Do not treat every `identity` audit entry as a login: `/v1/whoami` also records identity reads. Gateway forwarding, polling, heartbeats and token lookups are high-volume activity, not business lifecycle transitions. Keep them out of the initial catalogue; optional diagnostic subscriptions need separate sampling, rate limits and retention. Failed authorization attempts, if exposed, are explicitly separate security events.

Use exact event selections, immutable cluster IDs and equality label selectors first. Filter cluster events against a recorded label snapshot; for label-change events, offer explicit `before` or `after` matching. Non-cluster events cannot use cluster filters. Reject unsupported combinations instead of silently matching everything. Do not add arbitrary SQL, shell scripts or expression evaluation to the rule editor.

Rules match at event commit. Persist the rule version, target version, filter result and relevant resource snapshot with each delivery/run. Later label edits, endpoint changes or rule deletion must not retarget retries or remove an existing hold. New rules do not replay historical events automatically. An explicit replay is audited, excludes destructive workflows by default and gets a new delivery identity linked to the original event.

## Notifications and workflows

**Notification** means an external system receives a committed event. Delivery failures appear in administration but do not block the developer action or change cluster availability. Delivery has a retry budget and can end in `DELIVERY_FAILED`.

**Workflow** means a supported lifecycle transition starts external work and creates a durable placement hold before any other request can allocate that cluster. In the first version, permit this only for `cluster.became_idle.v1`. Completion affects only that operation's hold, never arbitrary application state. Do not allow an administrator to attach a blocking cluster effect to a credential event merely by editing JSON.

For shared use, the controlling developer leaving is insufficient: the current implementation transfers control to the oldest remaining participant. Reinstall only after the last active participant leaves. Expiring several participants in one transaction must produce exactly one idle transition for their cluster, not one pipeline execution per expired booking. Process distinct affected clusters after all relevant endings are applied. A transaction that rolls back produces no event, hold or HTTP call.

All reasons for ending a booking—manual stop, admin release, logout and inactivity expiry—must use the same helper. It must also cover expiry discovered by snapshot, placement, primary or PAT gateway code; a timer-only integration would leave bypasses.

```mermaid
sequenceDiagram
    participant Developer
    participant API as devctld transaction
    participant PG as PostgreSQL
    participant Worker
    participant Pipeline
    Developer->>API: End booking
    API->>PG: End final participant + event + run + hold + outbox
    PG-->>API: Commit
    API-->>Developer: Booking ended; cluster awaiting automation
    Worker->>PG: Claim delivery lease; commit
    Worker->>Pipeline: Signed HTTPS trigger, stable operation ID
    Pipeline-->>Worker: Accepted, stable pipeline run ID
    Worker->>PG: Persist acceptance if lease/current run still match
    Pipeline->>API: Authenticated completion callback
    API->>PG: Record outcome for current operation; retain hold for verification
    Worker->>PG: Commit fresh verification result and release only this hold
```

The release response must not wait for the pipeline. If writing the required event/hold/outbox fails, roll back the release transaction. An automatic expiry performed before a failed allocation still needs to commit its event and hold. Make the distinction explicit in every affected entry point: commit successful housekeeping and return an expected allocation rejection afterward, while storage/invariant failures roll back. Some PAT code already uses a separate returned result error; do not assume every existing booking path has that behavior.

## Placement, access and destructive work

Treat placement conditions independently:

```text
new_booking_allowed =
    not deregistered
    AND not manual_maintenance
    AND no unresolved automation holds
    AND health permits new placement
    AND normal ownership/sharing/capacity/selector rules pass
```

Evaluate the same predicate transactionally in manual placement, explicit cluster selection for new booking and PAT fallback. Persisting an idle event and hold under the existing reservation lock prevents a release-to-maintenance booking gap. Multiple matching workflows create separate holds; placement resumes only when every required hold is resolved. A callback never flips the existing maintenance boolean.

Ending the booking already denies subsequent gateway access, but destructive work needs a drain barrier. Add expiring per-instance/per-request gateway operation leases, pinned to cluster configuration and primary versions. Register a lease atomically with authorization before dispatch; remove it on completion and renew bounded streaming leases. The automation worker first prevents new authorized dispatches, requests cancellation and waits for all applicable instance leases to drain or expire with an explicit safety margin. A crash must not leave an eternal lease; lease expiry must not be interpreted as proof an external Kubernetes action was rolled back.

The current default monitor interval is one second and checks can take five seconds; sleeping that long alone is not a reliable distributed drain mechanism. A request dispatched before release may still finish upstream. Detached Jobs and deployed workloads can remain after every connection closes. The reservation service cannot prove they are idle or stop unmanaged cluster credentials. The external integration owns its preflight and destructive-action policy; document its behavior, require explicit admin enablement, and never claim this is a hard security boundary. Cluster teardown permissions remain with the pipeline, not new developer RBAC.

## Durable data model and transaction boundaries

Add migrations with foreign keys, bounded status enums and UTC timestamps. The following is a logical schema, not ready-to-run migration SQL:

| Table/field | Purpose and important constraints |
| --- | --- |
| `automation_targets` and immutable target versions | Approved HTTPS endpoint, body adapter, safe static headers, secret references, network policy, enabled flag; credential values encrypted or externally referenced |
| `automation_rules` and immutable rule versions | Name, event set, filters, mode, target version, timeout/retry policy, actor and audit reason |
| `domain_events` | Immutable event ID, event/schema type, UTC time, resource ID and sequence, actor identity key, safe JSON payload, causation/correlation IDs; unique business transition key |
| `automation_runs` | Unique `(event_id, rule_version_id)`, cluster ID, lifecycle generation, execution generation, state, deadlines, pipeline run ID, verification barrier time, required configuration/policy versions and minimum future probe sequence |
| `automation_holds` | One independently resolvable hold per blocking run; reason and release decision audited |
| `webhook_deliveries` | Unique event/rule/target snapshot, immutable delivery ID, run ID if any, next attempt, attempt budget, lease owner/token/expiry and outcome |
| `webhook_attempts` | Timing, status category, HTTP status and bounded redacted diagnostics; no response bodies or secrets by default |
| `callback_receipts` and callback grant metadata | Receipt ID/body hash, run and execution generation, terminal outcome; token digest and expiry, with encrypted transport copy only when delivery retries require it |
| Cluster `configuration_generation`, `lifecycle_generation`, `event_sequence` | Separate fencing values for credential changes, destructive workflow epochs and ordered resource events |

Increment lifecycle generation for a new blocking idle-cycle operation group; runs within that group share it. Credentials/endpoint replacement increments configuration generation and invalidates old health samples, but does not silently cancel another run in the same lifecycle group. An expected, scoped credential update records the new configuration generation on that run; any unrelated generation change requires explicit revalidation rather than accepting a stale callback.

Use `Tx.emit(...)` with typed payload construction, not database triggers parsing human-readable `audit.detail`. Write business state, audit, event, matched runs/holds and delivery rows in the same transaction. Keep event payloads small and use allowlists for changes; free-form audit reasons can contain sensitive text and should not be exported by default.

PostgreSQL workers claim due delivery rows with `FOR UPDATE SKIP LOCKED`, set a lease token/expiry and commit immediately. HTTP occurs outside the transaction. Completion updates require the same lease token and current execution generation, so a late worker cannot overwrite another claim or a callback that already finished the run. Recover expired leases on restart. Transactions that can affect placement acquire the existing reservation advisory lock first, then cluster, run/hold and delivery rows in that order. A delivery-only claim transaction acquires only delivery rows and commits before any business transition; it never waits for the reservation lock while retaining a delivery lock. PostgreSQL specifically identifies queue-like consumers as a use for [`SKIP LOCKED`](https://www.postgresql.org/docs/current/sql-select.html).

This is a [transactional outbox](https://docs.aws.amazon.com/prescriptive-guidance/latest/cloud-design-patterns/transactional-outbox.html): the database state and intent commit together, while HTTP delivery is retried independently. It provides durable intent, not exactly-once external side effects.

## Delivery protocol and payload

Use one stable JSON envelope first. A native CI endpoint that expects a different body can use an explicitly selected, tested adapter or a small receiver service. Support bounded field mapping and allowlisted static fields if needed; no executable templates. A generic webhook cannot discover a pipeline's required branch, project or parameter schema automatically.

Example event and private delivery metadata:

```json
{
  "schema_version": 1,
  "event_id": "evt-example",
  "type": "cluster.became_idle.v1",
  "occurred_at": "2026-11-17T10:00:00Z",
  "resource": {"type": "cluster", "id": "cluster-example", "sequence": 42},
  "actor": {"type": "developer", "identity_key": "opaque-issuer-subject-key"},
  "data": {"reason": "holder_release", "participants_remaining": 0, "labels": {"reset": "required"}},
  "operation": {"id": "run-example", "lifecycle_generation": 7, "execution_generation": 1},
  "callback": {
    "url": "https://devctl.example.test/v1/automation/runs/run-example/completion",
    "expires_at": "2026-11-17T12:00:00Z"
  }
}
```

Never include upstream kubeconfigs, Kubernetes tokens, PAT values/digests, OAuth tokens, private keys, Secret contents or unneeded personal contact details. Display names are optional metadata; identity remains issuer plus subject through its application identity key. Event IDs and resource IDs are identifiers, not credentials. Callback URLs come from configured `DEVCTL_PUBLIC_URL`, not the incoming Host header or receiver input.

Send stable `Devctl-Event-ID`, `Devctl-Delivery-ID` and `Idempotency-Key` headers. For workflows, the idempotency key identifies `(operation_id, execution_generation)` and stays unchanged on transport retries. Sign the timestamp, delivery ID and exact raw body bytes with an integration-specific HMAC-SHA256 key. For example, sign `timestamp + "." + delivery_id + "." + raw_body`, advertise a key ID, and regenerate timestamp/signature per attempt. Receivers compare signatures in constant time, enforce a bounded clock window and persist delivery/operation identities. Use a separate configured bearer credential only when required by the receiver. Keep credentials in a secret reference or existing vault encryption with domain-separated associated data; never in target URLs or ordinary API responses. These choices follow established [webhook authentication and delivery practices](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks).

Initial defaults: five-second total trigger deadline; bounded response headers/body; four concurrent deliveries globally and one workflow trigger per cluster; up to eight attempts with jittered exponential backoff from 5 seconds to a 15-minute ceiling, bounded by the run's absolute deadline. Treat transport errors, 408, 429 and selected 5xx as retryable; honor a bounded `Retry-After`. Treat authentication/schema errors as configuration failures. Disable redirects. An administrator can tune validated bounds; subscription creation shows them explicitly.

Notifications complete on the configured accepted 2xx response. Workflows require the adapter's acceptance contract, preferably a stable pipeline run ID and status URL; a 2xx/202 only means accepted. Validate any stored status URL against configured display/link destinations and never fetch an arbitrary returned URL. Do not let a late acceptance response move `VERIFYING` or a terminal run back to `RUNNING` if the callback raced it.

Delivery is at least once. If a pipeline accepted the trigger but the response was lost, resend only with the same operation idempotency key. The receiving system must durably map that key to one execution. If a provider cannot deduplicate or query an existing execution, ambiguous acceptance becomes `OUTCOME_UNKNOWN` with its hold retained; blind automatic retriggering could reinstall twice. Exactly-once reinstallation cannot be promised by HTTP alone.

Preserve per-resource event sequence numbers. Do not promise global webhook delivery order: retries can arrive late. Receivers use sequence numbers where relevant. A blocking run fences later destructive executions for that cluster; notifications can continue independently. Multiple matching blocking rules run serially in an explicit stored order by default, with separate holds, so two reinstall-like actions never run concurrently accidentally. This is bounded sequencing, not arbitrary dependencies or a workflow graph.

## Callback authorization and operation state

Callbacks are a dedicated integration endpoint, not developer PAT or administrator API access. For the first version, issue a random, short-lived capability scoped to one run and execution generation, accepted only by that run's completion endpoint. Store its digest for verification; if trigger retries must resend it, keep a separately encrypted copy that expires with the run. Deliver the capability only as private authenticated integration metadata, such as a dedicated header, outside normal event history, logs and UI exports. The receiver must securely transfer it to the pipeline job. Do not put it in a query string.

Changing HTTP delivery attempts does not rotate the callback capability or start a new external execution. An explicit execution retry requires confirmation the previous external action stopped, increments execution generation, revokes the previous grant and creates a fresh scoped grant. Configure a distinct provider-signature verifier instead only where that provider can authenticate completion and bind the same run/generation; do not accept unsigned arbitrary provider JSON.

Example completion body:

```json
{
  "receipt_id": "receipt-example",
  "operation_id": "run-example",
  "execution_generation": 1,
  "pipeline_run_id": "build-123",
  "outcome": "succeeded"
}
```

In a short transaction, validate authenticated scope, body schema/size, receipt uniqueness/hash, current run/execution/lifecycle generation, pipeline identity and expected configuration generation. Identical duplicates return success without repeating transitions; contradictory duplicates or stale generations return conflict and audit the rejection. Only the matching operation can complete. A retired cluster stays retired. Callbacks cannot select a new cluster, toggle maintenance, set arbitrary labels or supply a replacement kubeconfig through this endpoint.

| Run state | Meaning | Placement hold |
| --- | --- | --- |
| `PENDING` / `DRAINING` | Durable intent; wait for gateway drain | Retained |
| `DELIVERING` / `RUNNING` | Trigger pending/accepted; waiting for completion | Retained |
| `VERIFYING` | Successful completion reported; require a passing health cycle started after this run's verification barrier | Retained |
| `SUCCEEDED` | Current-generation completion and required local verification passed | This run's hold resolved |
| `FAILED` / `TIMED_OUT` / `OUTCOME_UNKNOWN` | Work failed, deadline elapsed or execution cannot be determined | Retained pending audited recovery |
| `CANCEL_REQUESTED` | External cancellation requested but not confirmed | Retained |
| `CANCELLED` | External work is confirmed stopped; final placement decision reviewed | Hold retained unless separately, explicitly resolved |

Timeouts never imply successful cleanup. Late success after timeout is recorded but cannot automatically reopen placement; an administrator must reconcile the current run and external outcome. Disabling/deleting a rule prevents future matches, not unfinished work. Administrator retry/cancel/resolve operations require an audit reason and clear warnings about the external action's status. A mere HTTP delivery retry differs from restarting the pipeline. Manual resolution must not bypass another run, manual maintenance or fresh-health requirements.

## Credential replacement and verification after external work

A reinstall can rotate the Kubernetes endpoint, CA or client identity. Add a separate administrator-authenticated credential replacement endpoint; the current registry only inserts credentials. Reuse static portable kubeconfig validation, encryption and verified TLS requirements, with expected configuration generation and an audit reason. Keep raw credentials out of callbacks. For fully automated rotation, grant a separate machine identity permission only to update the named run's cluster configuration; the completion capability alone is insufficient.

Credential replacement atomically increments configuration generation, invalidates health and fences active transports/old observations. Do not resurrect earlier health just because the endpoint string is unchanged. If policy requires a post-reinstall identity/capability check beyond general health, store that requirement explicitly. No callback may manufacture a successful health observation.

On accepting a successful completion callback, move the run to `VERIFYING` and persist a verification barrier in the same reservation-locked transaction: database time, current configuration generation, current health policy revision and a minimum probe sequence beyond all cycles already started or claimed. Request the next post-barrier health cycle. Resolve this run's hold only after a passing, current-generation result whose probe **started after the barrier** and meets that minimum sequence. A still-fresh stored `PASSING` result is insufficient, even if the reinstall retained the same kubeconfig; a pre-callback probe finishing later is insufficient too. Do not satisfy verification by coalescing its refresh request onto an already-running pre-barrier cycle.

Count the required consecutive verification successes after this barrier: the proposed default is two complete passing cycles. An old global health-success counter cannot contribute. A failed cycle, a configuration/policy change or a gap exceeding the health freshness window resets this run's verification streak. Persist the accepted cycle identities and streak with the barrier so backend restart resumes the requirement instead of inventing a new successful observation or resetting valid normal-health timestamps.

If credentials, endpoint or health policy change during verification, invalidate the earlier verification requirement, move its barrier to the change's database time and require a new sequence for the new configuration/policy. The health worker may finish earlier work for diagnostics but cannot release the hold with it. Each serial blocking run establishes its own barrier after its own external completion; a result verifying an earlier run does not automatically verify later work. Hold resolution rechecks the run, barrier, accepted probe identity and all fencing versions transactionally, while other operation holds and manual maintenance remain independent.

## Network and application security

Only SSO administrators configure targets/rules or retry/resolve runs; browser changes retain Origin/CSRF protection and audit reasons. Developers can see safe workflow status for their clusters, not target secrets or internal response content. Integration callbacks use scoped non-cookie authentication and do not gain control API access.

Treat user-configured outbound endpoints as an SSRF surface even for trusted administrators. Require HTTPS, verified CA/hostname and a deployment-level destination allowlist independent of editable rules. Reject URL credentials, fragments, redirects and unexpected ports. Private pipeline destinations can be allowed explicitly; do not blanket-reject every private address because internal CI may need them. Always exclude loopback, link-local, metadata and unrelated protected infrastructure unless a narrowly documented development-only exception is needed for owned fixtures.

Validate resolved addresses at dispatch, bind the approved resolution to dialing while retaining the original TLS server name, and revalidate every new connection/retry to prevent DNS rebinding. Account for configured HTTP proxies at the actual egress layer; a locally checked hostname is not enough if a proxy resolves a different address. Enforce equivalent destination constraints at that proxy or reject the unsupported route; do not claim address controls that the transport can bypass. Apply equivalent controls to any adapter status lookup. Bound concurrent work, payload sizes and response reading; do not log request/response bodies or secret headers. Store only allowlisted response metadata and scrub provider errors.

Delivery/callback/rule-administration audit records are excluded from ordinary subscriptions by default. Track event causation and apply a hop limit so a callback or health-change notification cannot recursively trigger its own automation forever. Health probes do not count as developer activity and must never go through a PAT that could auto-book.

## API, GUI and CLI surface

All paths and commands here are proposed:

| Interface | Purpose |
| --- | --- |
| `GET /v1/admin/automation/event-types` | Catalogue, schemas, allowed filters and effects |
| `GET/POST/PATCH /v1/admin/automation/targets` and `/rules` | Validated, versioned configuration with stale-write protection; secret values write-only |
| `GET /v1/admin/automation/events`, `/deliveries`, `/runs` | Filtered history and safe diagnostics |
| `POST /v1/admin/automation/targets/{id}/test` | Preview a fixed signed fixture; sending requires an approved test receiver with an explicit no-op contract |
| `POST /v1/admin/automation/runs/{id}/retry`, `/cancel`, `/resolve` | Separate, reasoned delivery/execution/recovery operations with expected version |
| `POST /v1/automation/runs/{id}/completion` | Scoped integration callback; not SSO/PAT management access |
| `devctl admin automation …` | CLI equivalents for target/rule/history/recovery management |

The Slate **Events & Automations** view separates target configuration, rule creation and delivery/run history. Show event/filter summaries, notification versus blocking mode, timeout/retry policy, recent outcomes and secret-presence indicators. The cluster registry shows independent manual maintenance, automation holds and health, plus a safe pipeline link and progress/failure reason. An execution-retry confirmation names the cluster and external destructive action. Default target testing to a local signed-request preview. Only send a synthetic event to an explicitly approved receiver that supports no-op testing; posting a test to an arbitrary pipeline trigger could itself launch work even if devctl creates no operation. Preserve drafts on validation/conflict errors and require explicit reload after another admin edits the same version.

## Implementation order and acceptance tests

1. Add typed event definitions, schema migrations and transactional emission for a small set of business actions. Test rollback, idempotent booking retries and identical no-op updates producing no duplicate events.
2. Add immutable target/rule versions, bounded filters, outbox leasing and notification delivery. Verify authentication, backoff, worker crash recovery and provider acceptance ambiguity against owned HTTPS receivers.
3. Unify final-participant ending across stop/logout/expiry; add holds, lifecycle fencing and placement predicate reuse. Test manual and PAT allocation racing release; none may slip through the hold.
4. Add distributed drain visibility, supported blocking workflows, scoped callback grants, credential replacement and fresh-health verification. Use disposable pipeline/API fixtures; a real destructive integration requires separate explicit approval.
5. Add GUI/CLI, retention, metrics and admin recovery. Enable notification-only rules first; opt clusters into blocking behavior after recovery drills.

Required PostgreSQL-backed concurrency/recovery tests include: two shared participants ending concurrently; batch expiry; implicit expiry followed by failed booking; duplicate event generation; two workers claiming deliveries; callback racing acceptance; worker lease expiry; backend restart; subscription edits after event commit; two blocking rules with one failed hold; stale callback after explicit execution retry or credential replacement; callback against deregistered metadata; manual maintenance surviving workflow success; no-op/rollback audit consistency; and database failure never freeing a hold. Explicitly test an unchanged-kubeconfig reinstall with both an old green sample and a pre-callback probe still in flight: neither may release the hold. Only the required number of consecutive post-barrier cycles can do so; one new success plus an old global counter must not pass. Credential/policy changes must move the barrier, and a later serial run must require its own post-completion cycles.

Protocol tests use a real HTTP client and owned TLS fixtures for signature tampering, timestamp replay, scoped-token misuse/expiry, duplicate/contradictory callbacks, redirect/SSRF rejection, lost trigger acknowledgments, HTTP retry classes, bounded bodies and log redaction. Existing native kubectl, watch, exec, port-forward, primary-switch and logout regressions remain required. Drain tests must cover multiple backend instances, a crashed instance and operations already dispatched before release; document the limits rather than treating a mock zero-request counter as proof workloads stopped.

Observe pending age, delivery latency, lease expiry, repeated failures, callback rejection and unresolved holds. Audit state changes rather than every scheduler poll. Retain event/run identity long enough to deduplicate the maximum replay window; expire encrypted callback capabilities promptly and apply bounded history retention without deleting active holds.

## Completion boundary for this document

This is a reviewed implementation proposal. Creating this Markdown file performs no migration, enables no automation, sends no webhook and changes no cluster or identity state. Application implementation and its proposed acceptance tests remain future work. The source inspection and primary references explain the recommendation; they are not evidence that the described feature already works.
