# Lifecycle webhooks: implementation and operations

Status: implemented in a deliberately small form following the 2026-11-17 request for maintainability. This replaces the earlier, broader proposal. The [verification record](verification.md) distinguishes tested fixture behavior from deployment limits.

## The design in one page

An administrator creates a rule containing events, an HTTPS endpoint, optional cluster/label filters and whether the rule blocks new bookings. The existing audit transaction creates a delivery for each matching rule. One worker sends those deliveries. A blocking delivery holds its cluster until an authenticated completion and two new passing health cycles, or an explicitly audited administrator resolution.

There are **two new tables**:

| Table | Purpose |
| --- | --- |
| `webhooks` | Current rule, revision and encrypted signing secret |
| `webhook_deliveries` | Frozen event/receiver settings, queue lease, attempts, completion state and hold |

The existing `audit` row supplies the event identity. There is no separate event bus, target/version table, arbitrary action language, dependency graph or general pipeline runner.

## Code to maintain

| File | Responsibility |
| --- | --- |
| [`internal/store/webhooks.go`](../internal/store/webhooks.go) | Rule validation, audit subscriptions, delivery queue, callbacks, recovery and holds |
| [`internal/store/store.go`](../internal/store/store.go) | Audit entry point and last-participant detection for stop/logout/expiry |
| [`internal/store/schema.sql`](../internal/store/schema.sql) | Migration 10; defaults create no rules or external calls |
| [`internal/webhook/webhook.go`](../internal/webhook/webhook.go) | Fixed HTTP protocol, destination checks, signatures and callback-token derivation |
| [`internal/webhook/worker.go`](../internal/webhook/worker.go) | Serial leased delivery and reconciliation loop |
| [`internal/api/webhooks.go`](../internal/api/webhooks.go) | Administrator API and operation-scoped completion endpoint |
| [`frontend/src/pages/Webhooks.tsx`](../frontend/src/pages/Webhooks.tsx) | Slate rule editor, one-time secret, delivery history and recovery controls |
| [`internal/cli/admin_webhooks.go`](../internal/cli/admin_webhooks.go) | CLI equivalents; whole-rule JSON replacement keeps editing small |

Keep transport outside database transactions. Reuse the current PostgreSQL reservation lock and health worker instead of adding another synchronization mechanism.

## Rules and events

`GET /v1/admin/webhooks` is the authoritative event catalogue. Events use existing audit action names such as `book`, `release`, `expire`, `share`, `cluster_labels_update`, `maintenance`, `pat_revoke`, `browser_login` and policy changes. The additional `cluster_idle` event means the active participant count changed from positive to zero.

Read events, gateway requests, heartbeats and identity lookups are excluded. Webhook administration/delivery/callback audit entries are excluded to prevent recursive delivery. New event types require adding a small explicit catalogue entry; rule configuration itself needs no deployment.

Filters support an exact cluster ID and Kubernetes equality-label selectors. Non-cluster events cannot use cluster filters. Labels are captured at the event, so a later edit does not change queued matching. Payloads deliberately omit free-form audit detail, original kubeconfigs, PATs and Secret contents.

Example payload:

```json
{
  "id": "audit-123",
  "type": "cluster_idle",
  "at": "2026-11-17T12:00:00Z",
  "actor": "issuer-and-subject-identity-key",
  "object_id": "cluster-lab-a",
  "cluster_id": "cluster-lab-a",
  "labels": {"purpose": "development"}
}
```

Each `(rule, audit event)` creates at most one delivery. The delivery freezes its URL, encrypted signing secret, payload, blocking flag and absolute deadline. Editing or disabling a rule changes future events only. The implementation does not automatically replay historical events or rotate a queued delivery onto a new receiver.

## Notifications and blocking completion

A notification finishes when its receiver returns HTTP 2xx. Its failure does not block a cluster. Use this mode for most auditable actions, including inventory synchronization and notifications.

A blocking rule is permitted **only for `cluster_idle`**, and requires both enabled health monitoring and confirmation that the receiver deduplicates delivery IDs. When the last holder leaves, the same reservation transaction ends that booking and creates the delivery/hold. New manual/shared bookings, PAT fallback and deregistration respect unresolved holds. The first developer leaving a shared cluster never triggers a reset while another participant remains. Batch expiry emits one idle event per affected cluster, including expiry discovered through a later API request.

```mermaid
flowchart LR
    A[Last booking ends] --> B[Commit delivery and hold]
    B --> C[Signed HTTPS request]
    C --> D[Wait for completion]
    D --> E[Two new passing health cycles]
    E --> F[Resolve this delivery's hold]
```

An HTTP acceptance is not pipeline completion. A successful callback moves the job to `VERIFYING`, invalidates old health claims/results and requests new checks. A pre-callback green observation cannot release it. Recovery requires two passing cycles from the current configuration/profile after the callback barrier. Restarting preserves that requirement. Disabling health monitoring leaves the verification hold in place until monitoring resumes or an administrator resolves it after review.

Multiple blocking rules execute serially per cluster. All unresolved blocking deliveries continue holding placement, including failed or timed-out ones. Callbacks never change manual maintenance. Health Enforce, normal reservation limits and any other holds remain independent.

## Configure an integration

The operator first approves exact HTTPS origins on the backend and restarts it through the normal deployment procedure:

```bash
export DEVCTL_WEBHOOK_ALLOWED_ORIGINS='https://ci.example.test'
# Optional public CA bundle for a private receiver:
export DEVCTL_WEBHOOK_CA_FILE='/secure/public-ci-ca.pem'
```

An empty allowlist permits no outbound destination. Only an SSO administrator can configure rules. The GUI is **Administration → Events & automations**. New rules start disabled; save the one-time signing secret on the receiver before enabling the rule. There is no endpoint-test button that could accidentally launch a pipeline.

```bash
devctl admin webhooks list
devctl admin webhooks create --name 'Inventory notification' \
  --url https://ci.example.test/devctl --event cluster_labels_update \
  --selector purpose=development --reason 'Prepare approved inventory integration'
devctl admin webhooks update WEBHOOK_ID --file rule.json \
  --expected-version 1 --reason 'Enable the configured receiver'
devctl admin webhooks runs
devctl admin webhooks disable WEBHOOK_ID --reason 'Pause future events'
```

The update file is a full rule snapshot; use `list` to inspect its fields and revision. Updates retain the existing secret and use compare-and-swap revisions. If the operator removes an allowed origin, its unchanged rule can still be disabled. Changing it to another URL requires normal destination approval.

There is no secret-read or secret-rotation API in this small version. If a key must be replaced, disable the old rule and create a new one, then explicitly review pending work. Existing deliveries retain the old encrypted key and endpoint. Never put credentials in the endpoint URL or query string.

## Receiver protocol

The worker POSTs the frozen JSON with:

- `Idempotency-Key` and `X-Devctl-Delivery-ID`: the stable delivery ID, including retries.
- `X-Devctl-Timestamp`: Unix seconds.
- `X-Devctl-Signature`: `sha256=` followed by a hexadecimal HMAC-SHA256.
- For blocking work, `X-Devctl-Callback-URL` and `X-Devctl-Callback-Token`.

The HMAC input is `delivery_id + "\n" + timestamp + "\n" + raw_request_body`. **Use the displayed secret's UTF-8 text as the key; do not base64-decode it.** Verify the timestamp against a small clock-skew window, compare signatures in constant time and durably deduplicate the delivery ID. Return 2xx only after durably accepting the work. Response bodies are not a provider-specific acceptance contract and are discarded with a bounded read.

The receiver must return promptly, run its external work separately, then call the supplied completion URL:

```http
POST /v1/webhooks/deliveries/DELIVERY_ID/complete
Authorization: Bearer OPERATION_CALLBACK_TOKEN
Content-Type: application/json

{"outcome":"succeeded"}
```

Use `failed` for a failed external action. This credential authenticates only the named delivery; developer PATs, browser cookies and administrator API access do not authorize completion. Matching repeated outcomes are idempotent; contradictory or no-longer-acceptable completion returns conflict. Callback credentials and signing secrets must not enter logs. The per-rule receiver is trusted: possession of its signing key also compromises that rule's callback capabilities.

## Failure, retry and administrator recovery

The worker is serial within each backend; PostgreSQL leases coordinate replicas. It uses a five-second HTTP budget bounded by the earlier job/lease deadline, verified TLS and no redirects. Retryable connection errors, 408, 429 and 5xx get at most five attempts with bounded exponential backoff. All attempts use the same delivery ID. No exactly-once execution is claimed; a blocking receiver must deduplicate even when an acknowledgement was lost.

The default completion budget is one hour, configurable per rule from five minutes through 24 hours. It starts when the event commits and includes queueing, external execution and health verification. Expiry or delivery failure never frees a blocking reservation.

| State | Meaning |
| --- | --- |
| `PENDING` | Queued, retrying or leased for HTTP delivery |
| `AWAITING_CALLBACK` | Accepted; external completion pending |
| `VERIFYING` | Success reported; fresh health required |
| `SUCCEEDED` | Notification accepted or workflow verified; this hold is resolved |
| `FAILED` / `TIMED_OUT` | Failed/unknown outcome; blocking hold remains |
| `RESOLVED` | Administrator explicitly reviewed and resolved this delivery |

The GUI and CLI distinguish retrying delivery from restarting a pipeline. Retry preserves the job ID, settings and deadline; it does not create a new external execution. Expired jobs and an explicitly failed pipeline are not blindly retriggered. Resolution requires a current expected state, audit reason and confirmation that external work has stopped. It does not cancel a pipeline or bypass another hold, manual maintenance or Enforce health policy.

```bash
devctl admin webhooks retry DELIVERY_ID --expected-state FAILED \
  --reason 'Receiver connectivity restored; same idempotency key'
devctl admin webhooks resolve DELIVERY_ID --expected-state TIMED_OUT \
  --confirmed-stopped --reason 'External owner confirmed the job stopped; cluster reviewed'
```

## Security and deliberate limits

Destinations must match the operator's exact HTTPS origins. DNS addresses are validated and bound to dialing; protected loopback/link-local/metadata destinations are rejected, including documented [AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) and [Google Cloud](https://docs.cloud.google.com/compute/docs/metadata/overview) IPv6 metadata addresses. Private CI addresses still require explicit origin approval. No outbound proxy support is claimed: a configured proxy route is rejected rather than bypassing address policy. Optional private CA trust never disables hostname/certificate verification.

`DEVCTL_DEV_WEBHOOK_LOOPBACK=1` is only for owned local fixtures and requires a loopback backend listener plus `DEVCTL_DEV_HTTP=1`. It does not enable HTTP receivers. Do not enable this exception for a real deployment.

Release denies subsequent gateway access and existing monitors close streams. It does **not** prove that already accepted Kubernetes requests, detached Jobs or unmanaged credentials stopped. The external integration owns drain/preflight and destructive-action policy. This version deliberately has no distributed gateway drain protocol, pipeline cancellation, arbitrary workflow graph, native CI-provider adapter or automatic Kubernetes credential replacement. A reinstall that changes credentials may fail verification and retain the hold until separately handled. These are explicit limits, not reasons to add a larger engine to the MVP.

Safe delivery history contains state, event/cluster identity, attempt count, timing and a fixed reason category. It omits receiver credentials, raw bodies and callback tokens. The GUI shows the latest 100 deliveries; long-term retention and bulk history management are future operational additions. The [security notes](security.md), [OpenAPI](openapi.json) and [verification record](verification.md) cover API access and executed checks.
