package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"devctl.local/devctl/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type HealthClaim struct {
	ClusterID               string
	Token                   string
	Sequence                int64
	ConfigurationGeneration int64
	PolicyRevision          int64
	Profile                 model.HealthProfile
	Ciphertext              []byte
	StartedAt               time.Time
	LeaseUntil              time.Time
}

type HealthCheckRequest struct {
	ID      string              `json:"id"`
	Pending bool                `json:"pending"`
	Health  model.ClusterHealth `json:"health"`
}

type healthQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readHealth(ctx context.Context, q healthQuerier, id string) (model.ClusterHealth, error) {
	var h model.ClusterHealth
	var raw []byte
	var now time.Time
	h.MaxAgeSeconds = int(model.HealthMaxAge / time.Second)
	h.IdentityVerification = "NOT_CHECKED"
	err := q.QueryRow(ctx, `SELECT a.health_mode,c.health_profile,c.configuration_generation,c.health_policy_revision,
 COALESCE(h.observed_state,'UNKNOWN'),COALESCE(h.reason_code,'not_checked'),COALESCE(h.result,'{}'),
 COALESCE(h.observed_configuration_generation,0),COALESCE(h.observed_policy_revision,0),
 h.checked_at,h.last_success_at,COALESCE(h.consecutive_successes,0),h.next_check_at,
 COALESCE(h.lease_until>clock_timestamp(),false) OR COALESCE(h.next_check_at<=clock_timestamp(),false),clock_timestamp()
 FROM clusters c CROSS JOIN application_settings a LEFT JOIN cluster_health h ON h.cluster_id=c.id
 WHERE c.id=$1 AND c.deregistered_at IS NULL`, id).Scan(
		&h.Mode, &h.Profile, &h.ConfigurationGeneration, &h.PolicyRevision, &h.State, &h.ReasonCode, &raw,
		&h.ObservedConfigurationGeneration, &h.ObservedPolicyRevision, &h.CheckedAt, &h.LastSuccessAt,
		&h.ConsecutiveSuccesses, &h.NextCheckAt, &h.CheckPending, &now)
	if err != nil {
		return h, err
	}
	var r model.HealthResult
	if err = json.Unmarshal(raw, &r); err != nil {
		return h, errors.New("invalid stored health observation")
	}
	h.DurationMS = r.DurationMS
	h.ReadinessConfirmed = r.ReadinessConfirmed
	h.DiscoveryCoverage = r.DiscoveryCoverage
	h.Components = r.Components
	if h.Components == nil {
		h.Components = []model.HealthComponent{}
	}
	if h.DiscoveryCoverage == "" {
		h.DiscoveryCoverage = "not_completed"
	}
	if h.Mode == model.HealthModeDisabled {
		h.CheckPending = false
	}
	h.EvaluatedAt = now
	return h.Effective(now), nil
}

// GetHealth is a read-only observation lookup: it neither expires nor renews
// reservations and never obtains Kubernetes credentials or starts network work.
func (s *Store) GetHealth(ctx context.Context, id string) (model.ClusterHealth, error) {
	return readHealth(ctx, s.Pool, id)
}

func (s *Store) SetHealthMode(ctx context.Context, admin model.Identity, mode model.HealthMode, reason string) error {
	if !admin.Admin {
		return ErrForbidden
	}
	if !model.ValidHealthMode(mode) {
		return fmt.Errorf("%w: health mode must be disabled, observe or enforce", ErrConflict)
	}
	if err := healthReason(reason); err != nil {
		return err
	}
	return s.update(ctx, func(t *Tx) error {
		var current model.HealthMode
		if err := t.QueryRow(ctx, "SELECT health_mode FROM application_settings WHERE singleton").Scan(&current); err != nil {
			return err
		}
		if current == mode {
			return nil
		}
		if _, err := t.Exec(ctx, "UPDATE application_settings SET health_mode=$1 WHERE singleton", mode); err != nil {
			return err
		}
		// Fencing every mode transition prevents a disabled/re-enabled worker from
		// publishing its old claim. Existing fresh observations remain observations.
		if _, err := t.Exec(ctx, `UPDATE cluster_health SET lease_token=NULL,lease_until=NULL,
   probe_sequence=probe_sequence+1,next_check_at=clock_timestamp()`); err != nil {
			return err
		}
		return t.audit(ctx, admin.Key(), "cluster_health_mode", "settings", fmt.Sprintf("health mode %s -> %s; existing bookings unchanged; reason: %s", current, mode, strings.TrimSpace(reason)))
	})
}

func healthReason(reason string) error {
	if len(reason) > 1000 || strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%w: an audit reason of 1 through 1000 bytes is required", ErrConflict)
	}
	return nil
}

func (s *Store) SetHealthProfile(ctx context.Context, admin model.Identity, id string, profile model.HealthProfile, expectedRevision int64, reason string) error {
	if !admin.Admin {
		return ErrForbidden
	}
	if !model.ValidHealthProfile(profile) || expectedRevision < 1 {
		return fmt.Errorf("%w: valid health profile and expected policy revision required", ErrConflict)
	}
	if err := healthReason(reason); err != nil {
		return err
	}
	return s.update(ctx, func(t *Tx) error {
		var current model.HealthProfile
		var revision int64
		if err := t.QueryRow(ctx, "SELECT health_profile,health_policy_revision FROM clusters WHERE id=$1 AND deregistered_at IS NULL FOR UPDATE", id).Scan(&current, &revision); err != nil {
			return err
		}
		if revision != expectedRevision {
			return fmt.Errorf("%w: health profile changed; reload and review", ErrConflict)
		}
		if current == profile {
			return nil
		}
		// Trigger advances the policy revision and invalidates observations/claims.
		if _, err := t.Exec(ctx, "UPDATE clusters SET health_profile=$2 WHERE id=$1", id, profile); err != nil {
			return err
		}
		return t.audit(ctx, admin.Key(), "cluster_health_profile", id, fmt.Sprintf("profile %s -> %s; reason: %s", current, profile, strings.TrimSpace(reason)))
	})
}

func (s *Store) RequestHealthCheck(ctx context.Context, admin model.Identity, id, reason string) (HealthCheckRequest, error) {
	var out HealthCheckRequest
	if !admin.Admin {
		return out, ErrForbidden
	}
	if err := healthReason(reason); err != nil {
		return out, err
	}
	err := s.update(ctx, func(t *Tx) error {
		var mode model.HealthMode
		if err := t.QueryRow(ctx, "SELECT health_mode FROM application_settings WHERE singleton").Scan(&mode); err != nil {
			return err
		}
		if mode == model.HealthModeDisabled {
			return fmt.Errorf("%w: enable health monitoring before requesting a check", ErrConflict)
		}
		var live bool
		if err := t.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND deregistered_at IS NULL)", id).Scan(&live); err != nil {
			return err
		}
		if !live {
			return ErrNotFound
		}
		if _, err := t.Exec(ctx, "INSERT INTO cluster_health(cluster_id) VALUES($1) ON CONFLICT DO NOTHING", id); err != nil {
			return err
		}
		var previous *time.Time
		var request *string
		var leased bool
		var now time.Time
		if err := t.QueryRow(ctx, `SELECT requested_at,request_id,COALESCE(lease_until>clock_timestamp(),false),clock_timestamp()
   FROM cluster_health WHERE cluster_id=$1 FOR UPDATE`, id).Scan(&previous, &request, &leased, &now); err != nil {
			return err
		}
		// Coalesce requests while a cycle runs or in the refresh debounce window.
		if request != nil && (leased || previous != nil && now.Sub(*previous) < 10*time.Second) {
			out.ID = *request
		} else {
			out.ID = "hc-" + uuid.NewString()
			if _, err := t.Exec(ctx, `UPDATE cluster_health SET request_id=$2,requested_at=clock_timestamp(),
    next_check_at=LEAST(next_check_at,clock_timestamp()) WHERE cluster_id=$1`, id, out.ID); err != nil {
				return err
			}
			if err := t.audit(ctx, admin.Key(), "cluster_health_check", id, "queued fixed read-only health check; reason: "+strings.TrimSpace(reason)); err != nil {
				return err
			}
		}
		var err error
		out.Health, err = readHealth(ctx, t, id)
		out.Pending = out.Health.CheckPending
		return err
	})
	return out, err
}

// ClaimHealthChecks uses only short queue row locks. It never waits for the
// reservation advisory lock while retaining a queue lock or performs HTTP.
func (s *Store) ClaimHealthChecks(ctx context.Context, limit int) ([]HealthClaim, error) {
	if limit < 1 || limit > 64 {
		return nil, fmt.Errorf("health claim limit must be 1 through 64")
	}
	t, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer t.Rollback(ctx)
	rows, err := t.Query(ctx, `WITH picked AS (
  SELECT h.cluster_id FROM cluster_health h JOIN clusters c ON c.id=h.cluster_id
  WHERE c.deregistered_at IS NULL AND (SELECT health_mode FROM application_settings WHERE singleton)<>'disabled'
   AND h.next_check_at<=clock_timestamp() AND (h.lease_until IS NULL OR h.lease_until<=clock_timestamp())
  ORDER BY h.next_check_at,h.cluster_id LIMIT $1 FOR UPDATE OF h SKIP LOCKED
 ) UPDATE cluster_health h SET probe_sequence=h.probe_sequence+1,lease_token=$2,
  lease_until=clock_timestamp()+interval '20 seconds',started_at=clock_timestamp()
 FROM picked p,clusters c WHERE h.cluster_id=p.cluster_id AND c.id=p.cluster_id
 RETURNING h.cluster_id,h.lease_token,h.probe_sequence,c.configuration_generation,c.health_policy_revision,
  c.health_profile,c.kubeconfig_ciphertext,h.started_at,h.lease_until`, limit, uuid.NewString())
	if err != nil {
		return nil, err
	}
	out := []HealthClaim{}
	for rows.Next() {
		var c HealthClaim
		if err = rows.Scan(&c.ClusterID, &c.Token, &c.Sequence, &c.ConfigurationGeneration, &c.PolicyRevision, &c.Profile, &c.Ciphertext, &c.StartedAt, &c.LeaseUntil); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err = t.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

var healthReasons = map[string]bool{
	"checks_passed": true, "configuration_invalid": true, "credentials_unavailable": true, "dns_failed": true,
	"connect_timeout": true, "request_timeout": true, "connection_refused": true, "connection_failed": true, "tls_untrusted": true,
	"tls_expired": true, "tls_hostname_mismatch": true, "tls_failed": true, "unauthorized": true,
	"permission_blocked": true, "api_not_ready": true, "upstream_failed": true, "redirect_blocked": true,
	"response_too_large": true, "response_invalid": true, "discovery_invalid": true, "discovery_stale": true,
	"rate_limited": true, "cancelled": true,
}

func validHealthResult(r model.HealthResult) bool {
	if !healthReasons[r.ReasonCode] || r.DurationMS < 0 || r.DurationMS > 20000 || len(r.Components) > 7 || r.RetryAfterSeconds < 0 || r.RetryAfterSeconds > 300 {
		return false
	}
	if r.DiscoveryCoverage != "" && r.DiscoveryCoverage != "not_completed" && r.DiscoveryCoverage != "baseline" && r.DiscoveryCoverage != "aggregated" {
		return false
	}
	if r.Passed != (r.ReasonCode == "checks_passed") {
		return false
	}
	names := map[string]bool{"version": true, "readiness": true, "core_discovery": true, "group_discovery": true, "core_resources": true, "application_resources": true, "job_resources": true}
	for _, c := range r.Components {
		if !names[c.Name] {
			return false
		}
		if len(c.Name) > 64 || strings.ContainsAny(c.Name, "?\n\r") || c.State != "PASSING" && c.State != "FAILING" || c.DurationMS < 0 || c.DurationMS > 20000 || c.HTTPStatus < 0 || c.HTTPStatus > 599 {
			return false
		}
		if c.ReasonCode != "" && !healthReasons[c.ReasonCode] {
			return false
		}
	}
	return true
}

// PublishHealthCheck fences expired, replaced and disabled workers under the
// same reservation lock that creates bookings. No network call occurs here.
func (s *Store) PublishHealthCheck(ctx context.Context, claim HealthClaim, result model.HealthResult, nextDelay time.Duration) (bool, error) {
	if !validHealthResult(result) {
		return false, errors.New("invalid classified health result")
	}
	if nextDelay < time.Second || nextDelay > 5*time.Minute {
		return false, errors.New("health delay must be between 1s and 5m")
	}
	var accepted bool
	err := s.update(ctx, func(t *Tx) error {
		var mode model.HealthMode
		var generation, revision int64
		err := t.QueryRow(ctx, `SELECT a.health_mode,c.configuration_generation,c.health_policy_revision
   FROM clusters c CROSS JOIN application_settings a WHERE c.id=$1 AND c.deregistered_at IS NULL`, claim.ClusterID).Scan(&mode, &generation, &revision)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if mode == model.HealthModeDisabled || generation != claim.ConfigurationGeneration || revision != claim.PolicyRevision {
			return nil
		}
		var token *string
		var sequence int64
		var until, checked *time.Time
		var successes int
		var oldState string
		var now time.Time
		if err = t.QueryRow(ctx, `SELECT lease_token,probe_sequence,lease_until,checked_at,consecutive_successes,observed_state,clock_timestamp()
   FROM cluster_health WHERE cluster_id=$1 FOR UPDATE`, claim.ClusterID).Scan(&token, &sequence, &until, &checked, &successes, &oldState, &now); err != nil {
			return err
		}
		if token == nil || *token != claim.Token || sequence != claim.Sequence || until == nil || !until.After(now) {
			return nil
		}
		if checked == nil || !checked.Before(now) || now.Sub(*checked) >= model.HealthMaxAge {
			successes = 0
		}
		state := "FAILING"
		if result.Passed {
			successes++
			state = "RECOVERING"
			if successes >= 2 {
				state = "PASSING"
			}
		} else {
			successes = 0
		}
		raw, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if _, err = t.Exec(ctx, `UPDATE cluster_health SET observed_state=$2,reason_code=$3,result=$4,
   observed_configuration_generation=$5,observed_policy_revision=$6,checked_at=$7,
   last_success_at=CASE WHEN $8 THEN $7 ELSE last_success_at END,consecutive_successes=$9,
   next_check_at=$7+make_interval(secs=>$10),lease_token=NULL,lease_until=NULL WHERE cluster_id=$1`,
			claim.ClusterID, state, result.ReasonCode, raw, generation, revision, now, result.Passed, successes, nextDelay.Seconds()); err != nil {
			return err
		}
		accepted = true
		if state != oldState {
			return t.audit(ctx, "system", "cluster_health_transition", claim.ClusterID, fmt.Sprintf("%s -> %s; category=%s", oldState, state, result.ReasonCode))
		}
		return nil
	})
	return accepted, err
}
