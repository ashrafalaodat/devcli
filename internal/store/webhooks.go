package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"devctl.local/devctl/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type WebhookEventType struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Cluster     bool   `json:"cluster"`
	Blocking    bool   `json:"blocking"`
}

var webhookEvents = []WebhookEventType{
	{"book", "Booking created", true, false}, {"release", "Booking released", true, false}, {"expire", "Booking expired", true, false},
	{"cluster_idle", "Last booking ended", true, true}, {"share", "Sharing changed", true, false}, {"primary_select", "Primary selected", true, false},
	{"register", "Cluster registered", true, false}, {"deregister", "Cluster deregistered", true, false}, {"maintenance", "Maintenance changed", true, false},
	{"cluster_update", "Cluster registration changed", true, false}, {"cluster_labels_update", "Registry labels changed", true, false}, {"cluster_health_transition", "Cluster health changed", true, false},
	{"cluster_health_profile", "Health profile changed", true, false},
	{"pat_create", "Personal token created", false, false}, {"pat_revoke", "Personal token revoked", false, false}, {"pat_booking_update", "Token preferences changed", false, false},
	{"booking_default_limit", "Default booking limit changed", false, false}, {"developer_booking_limit", "Developer booking limit changed", false, false},
	{"inactivity_grace_period", "Inactivity policy changed", false, false}, {"browser_login", "Browser login completed", false, false}, {"logout", "Developer signed out", false, false},
}

func WebhookEvents() []WebhookEventType { return append([]WebhookEventType(nil), webhookEvents...) }
func webhookEvent(name string) (WebhookEventType, bool) {
	for _, e := range webhookEvents {
		if e.Name == name {
			return e, true
		}
	}
	return WebhookEventType{}, false
}

type Webhook struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	URL              string            `json:"url"`
	Events           []string          `json:"events"`
	Selector         map[string]string `json:"selector"`
	ClusterID        string            `json:"cluster_id,omitempty"`
	Blocking         bool              `json:"blocking"`
	Enabled          bool              `json:"enabled"`
	Idempotent       bool              `json:"idempotent"`
	TimeoutSeconds   int               `json:"timeout_seconds"`
	Version          int64             `json:"version"`
	SecretPresent    bool              `json:"secret_present"`
	SecretCiphertext []byte            `json:"-"`
}
type WebhookDelivery struct {
	ID               string          `json:"id"`
	WebhookID        string          `json:"webhook_id"`
	EventID          int64           `json:"event_id"`
	EventType        string          `json:"event_type"`
	ClusterID        string          `json:"cluster_id,omitempty"`
	State            string          `json:"state"`
	ReasonCode       string          `json:"reason_code,omitempty"`
	Blocking         bool            `json:"blocking"`
	Attempts         int             `json:"attempts"`
	HTTPStatus       int             `json:"http_status,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
	Deadline         time.Time       `json:"deadline"`
	URL              string          `json:"-"`
	SecretCiphertext []byte          `json:"-"`
	Body             json.RawMessage `json:"-"`
	LeaseToken       string          `json:"-"`
	LeaseUntil       *time.Time      `json:"-"`
}

func ValidateWebhook(h Webhook) error {
	if strings.TrimSpace(h.ID) == "" || len(h.ID) > 100 || strings.TrimSpace(h.Name) == "" || len(h.Name) > 100 || (strings.TrimSpace(h.URL) == "" || len(h.URL) > 2048) || h.TimeoutSeconds < 300 || h.TimeoutSeconds > 86400 || len(h.Events) == 0 || len(h.Events) > len(webhookEvents) {
		return fmt.Errorf("%w: name, endpoint, events and timeout (300 through 86400 seconds) required", ErrConflict)
	}
	if err := model.ValidateLabels(h.Selector); err != nil {
		return fmt.Errorf("%w: invalid label selector", ErrConflict)
	}
	seen := map[string]bool{}
	for _, name := range h.Events {
		e, ok := webhookEvent(name)
		if !ok || seen[name] || h.Blocking && !e.Blocking || !e.Cluster && (h.ClusterID != "" || len(h.Selector) > 0) {
			return fmt.Errorf("%w: invalid event/filter combination; only cluster_idle can block placement", ErrConflict)
		}
		seen[name] = true
	}
	if h.Blocking && !h.Idempotent {
		return fmt.Errorf("%w: blocking receiver must support the stable Idempotency-Key", ErrConflict)
	}
	return nil
}
func webhookReason(reason string) error {
	if strings.TrimSpace(reason) == "" || len(reason) > 1000 {
		return fmt.Errorf("%w: audit reason of 1 through 1000 bytes required", ErrConflict)
	}
	return nil
}

const hookColumns = `id,name,url,events,selector,cluster_id,blocking,enabled,idempotent,timeout_seconds,version,secret_ciphertext`

func scanHook(row pgx.Row) (Webhook, error) {
	var h Webhook
	var raw []byte
	err := row.Scan(&h.ID, &h.Name, &h.URL, &h.Events, &raw, &h.ClusterID, &h.Blocking, &h.Enabled, &h.Idempotent, &h.TimeoutSeconds, &h.Version, &h.SecretCiphertext)
	if err == nil {
		err = json.Unmarshal(raw, &h.Selector)
	}
	h.SecretPresent = len(h.SecretCiphertext) > 0
	return h, err
}
func (s *Store) Webhooks(ctx context.Context, admin model.Identity) ([]Webhook, error) {
	if !admin.Admin {
		return nil, ErrForbidden
	}
	rows, err := s.Pool.Query(ctx, "SELECT "+hookColumns+" FROM webhooks ORDER BY name,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Webhook{}
	for rows.Next() {
		h, e := scanHook(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
func (s *Store) SaveWebhook(ctx context.Context, admin model.Identity, h Webhook, expectedVersion int64, reason string) (Webhook, error) {
	if !admin.Admin {
		return Webhook{}, ErrForbidden
	}
	if expectedVersion < 0 {
		return Webhook{}, fmt.Errorf("%w: expected version must be nonnegative", ErrConflict)
	}
	if err := ValidateWebhook(h); err != nil {
		return Webhook{}, err
	}
	if err := webhookReason(reason); err != nil {
		return Webhook{}, err
	}
	sort.Strings(h.Events)
	if h.Selector == nil {
		h.Selector = map[string]string{}
	}
	h.Name = strings.TrimSpace(h.Name)
	err := s.update(ctx, func(t *Tx) error {
		var previous Webhook
		if expectedVersion > 0 {
			var err error
			previous, err = scanHook(t.QueryRow(ctx, "SELECT "+hookColumns+" FROM webhooks WHERE id=$1 FOR UPDATE", h.ID))
			if err != nil {
				return err
			}
			if previous.Version != expectedVersion {
				return fmt.Errorf("%w: webhook changed; reload before saving", ErrConflict)
			}
			if len(h.SecretCiphertext) == 0 {
				h.SecretCiphertext = previous.SecretCiphertext
			}
		}
		if len(h.SecretCiphertext) == 0 {
			return fmt.Errorf("%w: signing secret required", ErrConflict)
		}
		labels, _ := json.Marshal(h.Selector)
		if expectedVersion == 0 {
			h.Version = 1
			_, err := t.Exec(ctx, `INSERT INTO webhooks(id,name,url,events,selector,cluster_id,blocking,enabled,idempotent,timeout_seconds,secret_ciphertext) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, h.ID, h.Name, h.URL, h.Events, labels, h.ClusterID, h.Blocking, h.Enabled, h.Idempotent, h.TimeoutSeconds, h.SecretCiphertext)
			if err != nil {
				return err
			}
		} else {
			h.Version = expectedVersion + 1
			_, err := t.Exec(ctx, `UPDATE webhooks SET name=$2,url=$3,events=$4,selector=$5,cluster_id=$6,blocking=$7,enabled=$8,idempotent=$9,timeout_seconds=$10,version=$11,secret_ciphertext=$12 WHERE id=$1`, h.ID, h.Name, h.URL, h.Events, labels, h.ClusterID, h.Blocking, h.Enabled, h.Idempotent, h.TimeoutSeconds, h.Version, h.SecretCiphertext)
			if err != nil {
				return err
			}
		}
		return t.audit(ctx, admin.Key(), "webhook_saved", h.ID, strings.TrimSpace(reason))
	})
	h.SecretPresent = len(h.SecretCiphertext) > 0
	return h, err
}

// Only catalogued business events are exported. Free-form audit detail is never
// sent, and webhook administration/delivery events cannot trigger themselves.
func (t *Tx) enqueueWebhooks(ctx context.Context, eventID int64, at time.Time, actor, action, object string) error {
	event, ok := webhookEvent(action)
	if !ok {
		return nil
	}
	cluster := ""
	labels := map[string]string{}
	if event.Cluster {
		query := "SELECT id,labels FROM clusters WHERE id=$1"
		switch action {
		case "book", "release", "expire", "share", "primary_select":
			query = "SELECT c.id,c.labels FROM clusters c JOIN sessions s ON s.cluster_id=c.id WHERE s.id=$1"
		}
		var raw []byte
		err := t.QueryRow(ctx, query, object).Scan(&cluster, &raw)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && json.Unmarshal(raw, &labels) != nil {
			return errors.New("invalid cluster event labels")
		}
	}
	payload := map[string]any{"id": fmt.Sprintf("audit-%d", eventID), "type": action, "at": at.UTC(), "actor": actor, "object_id": object}
	if cluster != "" {
		payload["cluster_id"] = cluster
		payload["labels"] = labels
	}
	body, _ := json.Marshal(payload)
	rows, err := t.Query(ctx, "SELECT "+hookColumns+" FROM webhooks WHERE enabled AND $1=ANY(events) ORDER BY id", action)
	if err != nil {
		return err
	}
	hooks := []Webhook{}
	for rows.Next() {
		h, e := scanHook(rows)
		if e != nil {
			rows.Close()
			return e
		}
		hooks = append(hooks, h)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, h := range hooks {
		if h.ClusterID != "" && h.ClusterID != cluster {
			continue
		}
		matches := true
		for k, v := range h.Selector {
			if value, present := labels[k]; !present || value != v {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		if h.Blocking && cluster == "" {
			continue
		}
		_, err = t.Exec(ctx, `INSERT INTO webhook_deliveries(id,webhook_id,event_id,event_type,cluster_id,blocking,url,secret_ciphertext,body,deadline) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(webhook_id,event_id) DO NOTHING`, "wd-"+uuid.NewString(), h.ID, eventID, action, cluster, h.Blocking, h.URL, h.SecretCiphertext, body, at.Add(time.Duration(h.TimeoutSeconds)*time.Second))
		if err != nil {
			return err
		}
	}
	return nil
}
func (t *Tx) clusterIdle(ctx context.Context, actor, cluster string) error {
	var active bool
	if err := t.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM sessions WHERE cluster_id=$1 AND state='ACTIVE')", cluster).Scan(&active); err != nil {
		return err
	}
	if active {
		return nil
	}
	return t.audit(ctx, actor, "cluster_idle", cluster, "last developer booking ended; managed placement held when blocking webhook configured")
}
func (t *Tx) webhookHolds(ctx context.Context, id string) (int, error) {
	var count int
	err := t.QueryRow(ctx, "SELECT count(*) FROM webhook_deliveries WHERE cluster_id=$1 AND blocking AND state NOT IN ('SUCCEEDED','RESOLVED')", id).Scan(&count)
	return count, err
}

const deliveryColumns = `id,webhook_id,event_id,event_type,cluster_id,state,reason_code,blocking,attempts,http_status,created_at,updated_at,deadline,url,secret_ciphertext,body,COALESCE(lease_token,''),lease_until`

func scanDelivery(row pgx.Row) (WebhookDelivery, error) {
	var d WebhookDelivery
	err := row.Scan(&d.ID, &d.WebhookID, &d.EventID, &d.EventType, &d.ClusterID, &d.State, &d.ReasonCode, &d.Blocking, &d.Attempts, &d.HTTPStatus, &d.CreatedAt, &d.UpdatedAt, &d.Deadline, &d.URL, &d.SecretCiphertext, &d.Body, &d.LeaseToken, &d.LeaseUntil)
	return d, err
}
func (s *Store) GetWebhookDelivery(ctx context.Context, id string) (WebhookDelivery, error) {
	return scanDelivery(s.Pool.QueryRow(ctx, "SELECT "+deliveryColumns+" FROM webhook_deliveries WHERE id=$1", id))
}
func (s *Store) WebhookDeliveries(ctx context.Context, admin model.Identity, limit int) ([]WebhookDelivery, error) {
	if !admin.Admin {
		return nil, ErrForbidden
	}
	if limit < 1 || limit > 100 {
		limit = 100
	}
	rows, err := s.Pool.Query(ctx, "SELECT "+deliveryColumns+" FROM webhook_deliveries ORDER BY created_at DESC,id LIMIT $1", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WebhookDelivery{}
	for rows.Next() {
		d, e := scanDelivery(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func (s *Store) ClaimWebhookDeliveries(ctx context.Context, limit int) ([]WebhookDelivery, error) {
	if limit < 1 || limit > 4 {
		limit = 1
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `WITH picked AS (
 SELECT q.id FROM webhook_deliveries q
 WHERE q.state='PENDING' AND q.deadline>clock_timestamp()
 AND q.next_attempt_at<=clock_timestamp() AND (q.lease_until IS NULL OR q.lease_until<=clock_timestamp())
 AND (NOT q.blocking OR NOT EXISTS(
  SELECT 1 FROM webhook_deliveries earlier WHERE earlier.blocking AND earlier.cluster_id=q.cluster_id AND earlier.state NOT IN ('SUCCEEDED','RESOLVED') AND (earlier.created_at,earlier.id)<(q.created_at,q.id)))
 ORDER BY q.created_at,q.id LIMIT $1 FOR UPDATE OF q SKIP LOCKED
) UPDATE webhook_deliveries d SET lease_token=$2,lease_until=clock_timestamp()+interval '20 seconds',attempts=attempts+1,updated_at=clock_timestamp()
 FROM picked p WHERE d.id=p.id RETURNING `+`d.id,d.webhook_id,d.event_id,d.event_type,d.cluster_id,d.state,d.reason_code,d.blocking,d.attempts,d.http_status,d.created_at,d.updated_at,d.deadline,d.url,d.secret_ciphertext,d.body,COALESCE(d.lease_token,''),d.lease_until`, limit, uuid.NewString())
	if err != nil {
		return nil, err
	}
	out := []WebhookDelivery{}
	for rows.Next() {
		d, e := scanDelivery(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Store) FinishWebhookDelivery(ctx context.Context, claim WebhookDelivery, status int, retryable bool, reasonCode string) error {
	switch reasonCode {
	case "", "accepted", "http_failed", "request_failed", "endpoint_blocked", "secret_unavailable", "tls_failed", "request_timeout", "response_too_large", "destination_blocked", "proxy_unsupported", "configuration_invalid", "credentials_unavailable", "connection_failed", "response_unavailable", "receiver_rejected", "payload_invalid", "dns_failed":
	default:
		reasonCode = "request_failed"
	}
	return s.update(ctx, func(t *Tx) error {
		var d WebhookDelivery
		var err error
		d, err = scanDelivery(t.QueryRow(ctx, "SELECT "+deliveryColumns+" FROM webhook_deliveries WHERE id=$1 FOR UPDATE", claim.ID))
		if err != nil {
			return err
		}
		now, err := t.now(ctx)
		if err != nil {
			return err
		}
		if d.LeaseToken != claim.LeaseToken || d.LeaseUntil == nil || !d.LeaseUntil.After(now) || d.State != "PENDING" {
			return nil
		}
		state := "FAILED"
		delay := time.Duration(0)
		if status >= 200 && status < 300 {
			state = "SUCCEEDED"
			reasonCode = "accepted"
			if d.Blocking {
				state = "AWAITING_CALLBACK"
			}
		} else if retryable && d.Attempts < 5 && d.Deadline.After(now) {
			state = "PENDING"
			delay = time.Duration(5*(1<<uint(d.Attempts-1))) * time.Second
		}
		_, err = t.Exec(ctx, `UPDATE webhook_deliveries SET state=$2,reason_code=$3,http_status=$4,next_attempt_at=clock_timestamp()+make_interval(secs=>$5),lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp() WHERE id=$1`, d.ID, state, reasonCode, status, delay.Seconds())
		if err != nil {
			return err
		}
		return t.audit(ctx, "system", "webhook_delivery", d.ID, "state="+state+"; category="+reasonCode)
	})
}
func (s *Store) CompleteWebhook(ctx context.Context, id string, success bool) (WebhookDelivery, error) {
	var out WebhookDelivery
	err := s.update(ctx, func(t *Tx) error {
		d, err := scanDelivery(t.QueryRow(ctx, "SELECT "+deliveryColumns+" FROM webhook_deliveries WHERE id=$1 FOR UPDATE", id))
		if err != nil {
			return err
		}
		if !d.Blocking {
			return fmt.Errorf("%w: delivery does not accept workflow completion", ErrConflict)
		}
		if success && (d.State == "VERIFYING" || d.State == "SUCCEEDED") {
			out = d
			return nil
		}
		if !success && d.State == "FAILED" && d.ReasonCode == "callback_failed" {
			out = d
			return nil
		}
		now, err := t.now(ctx)
		if err != nil {
			return err
		}
		if d.Attempts == 0 || !d.Deadline.After(now) || (d.State != "PENDING" && d.State != "AWAITING_CALLBACK") {
			return fmt.Errorf("%w: workflow no longer accepts completion", ErrConflict)
		}
		state := "FAILED"
		code := "callback_failed"
		if success {
			state = "VERIFYING"
			code = "awaiting_health"
			var live bool
			if err = t.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND deregistered_at IS NULL)", d.ClusterID).Scan(&live); err != nil {
				return err
			}
			if !live {
				return ErrNotFound
			}
			if _, err = t.Exec(ctx, `UPDATE cluster_health SET observed_state='UNKNOWN',reason_code='verification_required',result='{}',checked_at=NULL,consecutive_successes=0,lease_token=NULL,lease_until=NULL,probe_sequence=probe_sequence+1,next_check_at=clock_timestamp() WHERE cluster_id=$1`, d.ClusterID); err != nil {
				return err
			}
		}
		_, err = t.Exec(ctx, `UPDATE webhook_deliveries SET state=$2,reason_code=$3,verify_after=clock_timestamp(),verify_sequence=COALESCE((SELECT probe_sequence+1 FROM cluster_health WHERE cluster_id=$4),0),lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp() WHERE id=$1`, id, state, code, d.ClusterID)
		if err != nil {
			return err
		}
		if err = t.audit(ctx, "integration", "webhook_callback", id, "state="+state); err != nil {
			return err
		}
		out, err = scanDelivery(t.QueryRow(ctx, "SELECT "+deliveryColumns+" FROM webhook_deliveries WHERE id=$1", id))
		return err
	})
	return out, err
}
func (s *Store) ResolveWebhook(ctx context.Context, admin model.Identity, id, expectedState, reason string) (WebhookDelivery, error) {
	var out WebhookDelivery
	if !admin.Admin {
		return out, ErrForbidden
	}
	if err := webhookReason(reason); err != nil {
		return out, err
	}
	err := s.update(ctx, func(t *Tx) error {
		d, err := scanDelivery(t.QueryRow(ctx, "SELECT "+deliveryColumns+" FROM webhook_deliveries WHERE id=$1 FOR UPDATE", id))
		if err != nil {
			return err
		}
		now, err := t.now(ctx)
		if err != nil {
			return err
		}
		if d.State == "PENDING" && d.LeaseUntil != nil && d.LeaseUntil.After(now) {
			return fmt.Errorf("%w: delivery is in flight; wait before resolving", ErrConflict)
		}
		if d.State != expectedState || d.State == "SUCCEEDED" || d.State == "RESOLVED" {
			return fmt.Errorf("%w: delivery state changed; reload before resolving", ErrConflict)
		}
		if _, err = t.Exec(ctx, "UPDATE webhook_deliveries SET state='RESOLVED',reason_code='admin_resolved',lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp() WHERE id=$1", id); err != nil {
			return err
		}
		if err = t.audit(ctx, admin.Key(), "webhook_resolved", id, strings.TrimSpace(reason)); err != nil {
			return err
		}
		out, err = scanDelivery(t.QueryRow(ctx, "SELECT "+deliveryColumns+" FROM webhook_deliveries WHERE id=$1", id))
		return err
	})
	return out, err
}
func (s *Store) ReconcileWebhooks(ctx context.Context) error {
	return s.update(ctx, func(t *Tx) error {
		rows, err := t.Query(ctx, `SELECT id FROM webhook_deliveries WHERE state IN ('PENDING','AWAITING_CALLBACK','VERIFYING') AND deadline<=clock_timestamp() ORDER BY id`)
		if err != nil {
			return err
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, id := range ids {
			if _, err = t.Exec(ctx, "UPDATE webhook_deliveries SET state='TIMED_OUT',reason_code='deadline_elapsed',lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp() WHERE id=$1", id); err != nil {
				return err
			}
			if err = t.audit(ctx, "system", "webhook_timeout", id, "workflow or delivery deadline elapsed; blocking hold retained"); err != nil {
				return err
			}
		}
		rows, err = t.Query(ctx, `SELECT d.id,d.cluster_id FROM webhook_deliveries d JOIN cluster_health h ON h.cluster_id=d.cluster_id JOIN clusters c ON c.id=d.cluster_id WHERE d.state='VERIFYING' AND c.deregistered_at IS NULL AND h.observed_state='PASSING' AND h.checked_at>d.verify_after AND h.checked_at<=clock_timestamp() AND h.checked_at>clock_timestamp()-interval '90 seconds' AND h.started_at>=d.verify_after AND h.probe_sequence>=d.verify_sequence AND h.observed_configuration_generation=c.configuration_generation AND h.observed_policy_revision=c.health_policy_revision ORDER BY d.id`)
		if err != nil {
			return err
		}
		ids = nil
		for rows.Next() {
			var id, cluster string
			if err = rows.Scan(&id, &cluster); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, id := range ids {
			if _, err = t.Exec(ctx, "UPDATE webhook_deliveries SET state='SUCCEEDED',reason_code='verified',updated_at=clock_timestamp() WHERE id=$1", id); err != nil {
				return err
			}
			if err = t.audit(ctx, "system", "webhook_verified", id, "post-callback health checks passed; only this hold released"); err != nil {
				return err
			}
		}
		return nil
	})
}

// RetryWebhook redelivers the same immutable event and idempotency key. It does
// not reset an expired workflow budget or create a second pipeline operation.
func (s *Store) RetryWebhook(ctx context.Context, admin model.Identity, id, expectedState, reason string) (WebhookDelivery, error) {
	var out WebhookDelivery
	if !admin.Admin {
		return out, ErrForbidden
	}
	if err := webhookReason(reason); err != nil {
		return out, err
	}
	err := s.update(ctx, func(t *Tx) error {
		d, err := scanDelivery(t.QueryRow(ctx, "SELECT "+deliveryColumns+" FROM webhook_deliveries WHERE id=$1 FOR UPDATE", id))
		if err != nil {
			return err
		}
		now, err := t.now(ctx)
		if err != nil {
			return err
		}
		if d.State != expectedState || d.State != "FAILED" || !d.Deadline.After(now) || d.ReasonCode == "callback_failed" {
			return fmt.Errorf("%w: only a failed unexpired delivery can be redelivered; pipeline failure requires reconciliation", ErrConflict)
		}
		if _, err = t.Exec(ctx, "UPDATE webhook_deliveries SET state='PENDING',attempts=0,reason_code='admin_retry',next_attempt_at=clock_timestamp(),lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp() WHERE id=$1", id); err != nil {
			return err
		}
		if err = t.audit(ctx, admin.Key(), "webhook_retry", id, strings.TrimSpace(reason)); err != nil {
			return err
		}
		out, err = scanDelivery(t.QueryRow(ctx, "SELECT "+deliveryColumns+" FROM webhook_deliveries WHERE id=$1", id))
		return err
	})
	return out, err
}
