package store

import (
	"context"
	"errors"
	"time"

	"devctl.local/devctl/internal/model"
	"github.com/jackc/pgx/v5"
)

const AutomaticIdleWindow = 2 * time.Minute

type PrimaryAccess struct {
	Session                model.Session `json:"session"`
	SelectionVersion       int64         `json:"selection_version"`
	AuthorizationExpiresAt time.Time     `json:"authorization_expires_at"`
}

func (t *Tx) primaryAccess(ctx context.Context, u model.Identity, authorize, heartbeat bool) (PrimaryAccess, error) {
	var out PrimaryAccess
	if err := t.expire(ctx); err != nil {
		return out, err
	}
	var err error
	out.Session, out.SelectionVersion, err = t.primary(ctx, u)
	if err != nil {
		return out, err
	}
	var expiry *time.Time
	var authorizedVersion *int64
	if err = t.QueryRow(ctx, "SELECT authorization_expires_at,authorization_version FROM developers WHERE owner_id=$1", u.Key()).Scan(&expiry, &authorizedVersion); err != nil {
		return out, err
	}
	if expiry != nil && authorizedVersion != nil && *authorizedVersion == out.SelectionVersion {
		out.AuthorizationExpiresAt = *expiry
	}
	if !authorize {
		return out, nil
	}
	now, err := t.now(ctx)
	if err != nil {
		return out, err
	}
	if u.TokenExpiresAt.IsZero() || !u.TokenExpiresAt.After(now) {
		return out, ErrForbidden
	}
	if heartbeat && (out.Session.LastActivityAt == nil || out.Session.LastActivityAt.Before(now.Add(-AutomaticIdleWindow))) {
		return out, ErrConflict
	}
	if u.TokenExpiresAt.After(out.AuthorizationExpiresAt) {
		out.AuthorizationExpiresAt = u.TokenExpiresAt.UTC()
	}
	// Authentication validity is independent of a booking's moving inactivity
	// deadline. Gateway checks enforce both on each request and during streams.
	_, err = t.Exec(ctx, "UPDATE developers SET authorization_expires_at=$2,authorization_version=$3 WHERE owner_id=$1", u.Key(), out.AuthorizationExpiresAt, out.SelectionVersion)
	return out, err
}

func (s *Store) PrimaryAccess(ctx context.Context, u model.Identity) (PrimaryAccess, error) {
	return s.runPrimaryAccess(ctx, u, false, false)
}
func (s *Store) AuthorizePrimary(ctx context.Context, u model.Identity) (PrimaryAccess, error) {
	return s.runPrimaryAccess(ctx, u, true, false)
}
func (s *Store) HeartbeatPrimary(ctx context.Context, u model.Identity) (PrimaryAccess, error) {
	return s.runPrimaryAccess(ctx, u, true, true)
}

func (s *Store) runPrimaryAccess(ctx context.Context, u model.Identity, authorize, heartbeat bool) (PrimaryAccess, error) {
	var out PrimaryAccess
	var resultErr error
	err := s.update(ctx, func(t *Tx) error {
		out, resultErr = t.primaryAccess(ctx, u, authorize, heartbeat)
		if errors.Is(resultErr, ErrNoPrimary) {
			return nil
		}
		return resultErr
	})
	if err == nil {
		err = resultErr
	}
	return out, err
}

func (s *Store) CheckGatewayAuthorization(ctx context.Context, u model.Identity, sessionID string, version int64) error {
	var allowed bool
	err := s.Pool.QueryRow(ctx, `SELECT COALESCE(d.selection_version=$3 AND d.authorization_version=$3
 AND d.authorization_expires_at>clock_timestamp() AND s.owner_id=$1 AND s.state='ACTIVE'
 AND (s.expires_at IS NULL OR s.expires_at>clock_timestamp()),false)
 FROM developers d JOIN sessions s ON s.id=d.primary_session_id WHERE d.owner_id=$1 AND s.id=$2`, u.Key(), sessionID, version).Scan(&allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if !allowed {
		return ErrConflict
	}
	return nil
}

const ActivityThrottle = 15 * time.Second

func (t *Tx) inactivityGrace(ctx context.Context) (time.Duration, error) {
	var seconds int64
	err := t.QueryRow(ctx, "SELECT inactivity_grace_seconds FROM application_settings WHERE singleton").Scan(&seconds)
	return time.Duration(seconds) * time.Second, err
}

// recordPrimaryActivity is called only for authenticated, real activity. It must
// run under update's database lock, which serializes it with release and expiry.
// The exact selection version prevents stale tabs or streams from keeping a
// different booking alive after the developer switches clusters.
func (t *Tx) recordPrimaryActivity(ctx context.Context, u model.Identity, sessionID string, version int64) (model.Session, error) {
	session, currentVersion, err := t.primary(ctx, u)
	if errors.Is(err, ErrNoPrimary) {
		return model.Session{}, ErrConflict
	}
	if err != nil {
		return model.Session{}, err
	}
	if session.ID != sessionID || currentVersion != version || session.Owner != u.Key() {
		return model.Session{}, ErrConflict
	}
	now, err := t.now(ctx)
	if err != nil {
		return model.Session{}, err
	}
	if session.ExpiresAt == nil || !session.ExpiresAt.After(now) {
		return model.Session{}, ErrConflict
	}
	if session.LastActivityAt != nil && now.Sub(*session.LastActivityAt) < ActivityThrottle {
		return session, nil
	}
	grace, err := t.inactivityGrace(ctx)
	if err != nil {
		return model.Session{}, err
	}
	deadline := now.Add(grace)
	result, err := t.Exec(ctx, `UPDATE sessions SET last_activity_at=$2,expires_at=$3
 WHERE id=$1 AND state='ACTIVE' AND expires_at>clock_timestamp()`, session.ID, now, deadline)
	if err != nil {
		return model.Session{}, err
	}
	if result.RowsAffected() != 1 {
		return model.Session{}, ErrConflict
	}
	session.LastActivityAt, session.ExpiresAt = &now, &deadline
	return session, nil
}

func (s *Store) RecordPrimaryActivity(ctx context.Context, u model.Identity, sessionID string, version int64) (model.Session, error) {
	var session model.Session
	var resultErr error
	err := s.update(ctx, func(t *Tx) error {
		if err := t.expire(ctx); err != nil {
			return err
		}
		session, resultErr = t.recordPrimaryActivity(ctx, u, sessionID, version)
		if errors.Is(resultErr, ErrConflict) {
			// Persist expiry/primary repair even when a stale heartbeat fails.
			return t.expire(ctx)
		}
		return resultErr
	})
	if err == nil {
		err = resultErr
	}
	return session, err
}
