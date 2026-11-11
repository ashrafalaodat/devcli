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
	if end := out.Session.ExpiresAt; end != nil && end.Before(out.AuthorizationExpiresAt) {
		out.AuthorizationExpiresAt = end.UTC()
	}
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

func (s *Store) TouchActivity(ctx context.Context, u model.Identity, sessionID string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE sessions SET last_activity_at=clock_timestamp()
 WHERE id=$1 AND owner_id=$2 AND state='ACTIVE'
 AND (expires_at IS NULL OR expires_at>clock_timestamp())
 AND (last_activity_at IS NULL OR last_activity_at<clock_timestamp()-interval '30 seconds')`, sessionID, u.Key())
	return err
}
