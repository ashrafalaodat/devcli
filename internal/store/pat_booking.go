package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/scheduler"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func normalizeAutoBookingPolicy(policy model.AutoBookingPolicy) model.AutoBookingPolicy {
	selector := make(map[string]string, len(policy.Selector))
	for key, value := range policy.Selector {
		selector[key] = value
	}
	policy.Selector = selector
	return policy
}

func mustSelectorJSON(selector map[string]string) []byte {
	// String maps always marshal. Normalization ensures {} rather than null.
	raw, _ := json.Marshal(selector)
	return raw
}

// PAT fetches one safe metadata record without listing or exposing its digest.
func (s *Store) PAT(ctx context.Context, u model.Identity, id string) (PAT, error) {
	var out PAT
	var selectorJSON []byte
	err := s.Pool.QueryRow(ctx, `SELECT id,owner_id,name,scope,created_at,expires_at,revoked_at,last_used_at,
 auto_booking_enabled,auto_booking_selector FROM personal_access_tokens WHERE id=$1`, id).Scan(
		&out.ID, &out.Owner, &out.Name, &out.Scope, &out.CreatedAt, &out.ExpiresAt,
		&out.RevokedAt, &out.LastUsedAt, &out.AutoBooking.Enabled, &selectorJSON)
	if err != nil {
		return PAT{}, err
	}
	if out.Owner != u.Key() && !u.Admin {
		return PAT{}, ErrForbidden
	}
	if err = json.Unmarshal(selectorJSON, &out.AutoBooking.Selector); err != nil {
		return PAT{}, err
	}
	return out, nil
}

// UpdatePATBooking edits only metadata. It never rotates the credential, extends
// its expiry, changes an existing primary or allocates a reservation.
func (s *Store) UpdatePATBooking(ctx context.Context, u model.Identity, id string, policy model.AutoBookingPolicy, reason string) (PAT, error) {
	var out PAT
	if err := model.ValidateAutoBookingPolicy(policy); err != nil {
		return out, fmt.Errorf("%w: %s", ErrConflict, err)
	}
	policy = normalizeAutoBookingPolicy(policy)
	reason = strings.TrimSpace(reason)
	if len(reason) > 1000 {
		return out, fmt.Errorf("%w: audit reason must be at most 1000 bytes", ErrConflict)
	}
	err := s.update(ctx, func(t *Tx) error {
		var previousSelector []byte
		if err := t.QueryRow(ctx, `SELECT id,owner_id,name,scope,created_at,expires_at,revoked_at,last_used_at,
 auto_booking_enabled,auto_booking_selector FROM personal_access_tokens WHERE id=$1`, id).Scan(
			&out.ID, &out.Owner, &out.Name, &out.Scope, &out.CreatedAt, &out.ExpiresAt,
			&out.RevokedAt, &out.LastUsedAt, &out.AutoBooking.Enabled, &previousSelector); err != nil {
			return err
		}
		if out.Owner != u.Key() {
			if !u.Admin {
				return ErrForbidden
			}
			if reason == "" {
				return fmt.Errorf("%w: administrator changes to another developer's credential require an audit reason", ErrConflict)
			}
		}
		now, err := t.now(ctx)
		if err != nil {
			return err
		}
		if out.Scope != "kubernetes:primary" || out.RevokedAt != nil || !out.ExpiresAt.After(now) {
			return fmt.Errorf("%w: expired, revoked or retired credentials cannot be edited", ErrConflict)
		}
		if reason == "" {
			reason = "owner updated automatic-booking preferences"
		}
		if _, err := t.Exec(ctx, `UPDATE personal_access_tokens SET auto_booking_enabled=$2,auto_booking_selector=$3 WHERE id=$1`, id, policy.Enabled, mustSelectorJSON(policy.Selector)); err != nil {
			return err
		}
		out.AutoBooking = policy
		return t.audit(ctx, u.Key(), "pat_booking_update", id, fmt.Sprintf("automatic booking enabled=%t; selector=%s; existing primary and token expiry unchanged; reason: %s", policy.Enabled, mustSelectorJSON(policy.Selector), reason))
	})
	if err != nil {
		return PAT{}, err
	}
	return out, nil
}

// PrimaryPATConfig revalidates the credential and makes fallback allocation in
// the same database transaction as primary resolution. Multiple gateway
// requests and independent backend processes therefore create only one hold.
func (s *Store) PrimaryPATConfig(ctx context.Context, raw string) (model.Session, int64, string, []byte, error) {
	var session model.Session
	var version int64
	var encrypted []byte
	if !validPAT.MatchString(raw) {
		return session, version, "", nil, ErrForbidden
	}
	digest := sha256.Sum256([]byte(raw))
	var resultErr error
	err := s.update(ctx, func(t *Tx) error {
		var id, owner string
		var identityJSON, selectorJSON []byte
		var policy model.AutoBookingPolicy
		var expiry time.Time
		err := t.QueryRow(ctx, `SELECT id,owner_id,identity,expires_at,auto_booking_enabled,auto_booking_selector
 FROM personal_access_tokens WHERE token_digest=$1 AND scope='kubernetes:primary'
 AND revoked_at IS NULL AND expires_at>clock_timestamp()`, digest[:]).Scan(&id, &owner, &identityJSON, &expiry, &policy.Enabled, &selectorJSON)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrForbidden
		}
		if err != nil {
			return err
		}
		var u model.Identity
		if err = json.Unmarshal(identityJSON, &u); err != nil {
			return errors.New("invalid stored credential identity")
		}
		if u.Key() != owner {
			return ErrForbidden
		}
		u.Admin = false
		u.TokenExpiresAt = expiry.UTC()
		if err = json.Unmarshal(selectorJSON, &policy.Selector); err != nil {
			return errors.New("invalid stored automatic-booking preferences")
		}
		if err = model.ValidateAutoBookingPolicy(policy); err != nil {
			return fmt.Errorf("%w: invalid stored automatic-booking preferences", ErrConflict)
		}
		if err = t.expire(ctx); err != nil {
			return err
		}
		session, version, resultErr = t.primary(ctx, u)
		if errors.Is(resultErr, ErrNoPrimary) && policy.Enabled {
			resultErr = t.autoBookPAT(ctx, u, id, policy)
			if resultErr == nil {
				session, version, resultErr = t.primary(ctx, u)
			}
		}
		if resultErr != nil {
			if errors.Is(resultErr, ErrNoPrimary) || errors.Is(resultErr, scheduler.ErrUnavailable) || errors.Is(resultErr, ErrBookingLimit) {
				// Commit expiry and primary repair even when capacity is absent.
				return nil
			}
			return resultErr
		}
		session, err = t.recordPrimaryActivity(ctx, u, session.ID, version)
		if err != nil {
			return err
		}
		if err = t.QueryRow(ctx, "SELECT kubeconfig_ciphertext FROM clusters WHERE id=$1 AND deregistered_at IS NULL", session.Cluster).Scan(&encrypted); err != nil {
			return err
		}
		// The credential may reach its absolute expiry during transaction work.
		// Roll back the allocation as well as access if that boundary passed.
		var stillValid bool
		if err = t.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM personal_access_tokens
 WHERE id=$1 AND token_digest=$2 AND owner_id=$3 AND scope='kubernetes:primary'
 AND revoked_at IS NULL AND expires_at>clock_timestamp())`, id, digest[:], owner).Scan(&stillValid); err != nil {
			return err
		}
		if !stillValid {
			return ErrForbidden
		}
		if _, err = t.Exec(ctx, `UPDATE personal_access_tokens SET last_used_at=clock_timestamp() WHERE id=$1
 AND (last_used_at IS NULL OR last_used_at<clock_timestamp()-interval '30 seconds')`, id); err != nil {
			return err
		}
		return t.audit(ctx, u.Key(), "gateway", session.ID, "loaded current primary upstream credentials for server-side PAT forwarding")
	})
	if err == nil {
		err = resultErr
	}
	return session, version, session.Cluster, encrypted, err
}

func (t *Tx) autoBookPAT(ctx context.Context, u model.Identity, patID string, policy model.AutoBookingPolicy) error {
	sessions, err := t.sessions(ctx)
	if err != nil {
		return err
	}
	clusters, err := t.clusters(ctx, sessions)
	if err != nil {
		return err
	}
	for _, cluster := range clusters { // clusters is ordered by immutable ID.
		if cluster.Maintenance || len(cluster.Participants) != 0 || !model.Match(cluster, model.Booking{Selector: policy.Selector}) {
			continue
		}
		booking, _, err := t.book(ctx, u, model.Booking{Cluster: cluster.ID, Selector: policy.Selector}, "pat-auto-"+uuid.NewString())
		if err != nil {
			return err
		}
		return t.audit(ctx, u.Key(), "pat_auto_book", booking.ID, fmt.Sprintf("PAT %s requested an exclusive fallback booking; selector=%s; existing primary absent", patID, mustSelectorJSON(policy.Selector)))
	}
	return fmt.Errorf("%w: automatic booking needs an unused cluster matching the saved PAT selector", scheduler.ErrUnavailable)
}
