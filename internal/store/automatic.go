package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"devctl.local/devctl/internal/model"
	"github.com/jackc/pgx/v5"
)

// AutomaticIdleWindow bounds a client's renewal heartbeat. Only Kubernetes
// traffic and already authorized open streams update activity.
const AutomaticIdleWindow = 2 * time.Minute

var automaticBindingID = regexp.MustCompile(`^a-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func ValidAutomaticBinding(id string) bool { return automaticBindingID.MatchString(id) }

type AutomaticAccess struct {
	Session                model.Session `json:"session"`
	AuthorizationExpiresAt time.Time     `json:"authorization_expires_at"`
}

func validateAutomaticInput(binding string, b model.Booking) error {
	if !ValidAutomaticBinding(binding) {
		return errors.New("invalid automatic binding ID")
	}
	if b.TTL != "" {
		ttl, err := time.ParseDuration(b.TTL)
		if err != nil || ttl < time.Minute || ttl > 7*24*time.Hour {
			return errors.New("TTL must be between 1m and 168h")
		}
	}
	return nil
}

func automaticExpiry(u model.Identity, session model.Session, now time.Time) (time.Time, error) {
	if u.TokenExpiresAt.IsZero() || !u.TokenExpiresAt.After(now) {
		return time.Time{}, ErrForbidden
	}
	expiry := u.TokenExpiresAt.UTC()
	if session.ExpiresAt != nil && session.ExpiresAt.Before(expiry) {
		expiry = session.ExpiresAt.UTC()
	}
	if session.State != "ACTIVE" || !expiry.After(now) {
		return time.Time{}, fmt.Errorf("%w: booking ended; explicitly configure a new booking", ErrConflict)
	}
	return expiry, nil
}

func (t *Tx) automatic(ctx context.Context, u model.Identity, binding string) (AutomaticAccess, string, error) {
	var out AutomaticAccess
	var sessionID, hash string
	err := t.QueryRow(ctx, "SELECT session_id,request_hash,authorization_expires_at FROM automatic_bindings WHERE owner_id=$1 AND binding_id=$2", u.Key(), binding).Scan(&sessionID, &hash, &out.AuthorizationExpiresAt)
	if err != nil {
		return out, "", err
	}
	ss, err := t.sessions(ctx)
	if err != nil {
		return out, "", err
	}
	for _, session := range ss {
		if session.ID == sessionID {
			if session.Owner != u.Key() {
				return out, "", ErrForbidden
			}
			out.Session = session
			return out, hash, nil
		}
	}
	return out, "", ErrNotFound
}

// EnsureAutomatic binds a client to an existing compatible own booking, or
// creates one using the regular scheduler. Both binding and reservation are
// committed under the same PostgreSQL allocation lock. Ended bindings are never
// silently moved to another session or cluster.
func (s *Store) EnsureAutomatic(ctx context.Context, u model.Identity, binding string, b model.Booking) (AutomaticAccess, error) {
	var out AutomaticAccess
	if err := validateAutomaticInput(binding, b); err != nil {
		return out, err
	}
	err := s.update(ctx, func(t *Tx) error {
		if err := t.expire(ctx); err != nil {
			return err
		}
		now, err := t.now(ctx)
		if err != nil {
			return err
		}
		// Check before allocating any capacity.
		if u.TokenExpiresAt.IsZero() || !u.TokenExpiresAt.After(now) {
			return ErrForbidden
		}
		previous, hash, err := t.automatic(ctx, u, binding)
		if err == nil {
			if hash != bookingHash(b) {
				return ErrKey
			}
			expiry, err := automaticExpiry(u, previous.Session, now)
			if err != nil {
				return err
			}
			out = previous
			if expiry.After(previous.AuthorizationExpiresAt) {
				if _, err = t.Exec(ctx, "UPDATE automatic_bindings SET authorization_expires_at=$3 WHERE owner_id=$1 AND binding_id=$2", u.Key(), binding, expiry); err != nil {
					return err
				}
				out.AuthorizationExpiresAt = expiry
				return t.audit(ctx, u.Key(), "authorize", out.Session.ID, "fresh access token renewed automatic gateway authorization; booking unchanged")
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		ss, err := t.sessions(ctx)
		if err != nil {
			return err
		}
		cs, err := t.clusters(ctx, ss)
		if err != nil {
			return err
		}
		// sessions() has stable created_at,id ordering. Existing ownership wins
		// over creating another reservation on a free cluster.
		for _, session := range ss {
			if session.Owner != u.Key() || session.State != "ACTIVE" {
				continue
			}
			for _, cluster := range cs {
				if cluster.ID == session.Cluster && model.Match(cluster, b) {
					out.Session = session
					break
				}
			}
			if out.Session.ID != "" {
				break
			}
		}
		if out.Session.ID == "" {
			out.Session, _, err = t.book(ctx, u, b, "kubectl-auto:"+binding)
			if err != nil {
				return err
			}
		}
		out.AuthorizationExpiresAt, err = automaticExpiry(u, out.Session, now)
		if err != nil {
			return err
		}
		_, err = t.Exec(ctx, "INSERT INTO automatic_bindings(owner_id,binding_id,session_id,request_hash,authorization_expires_at) VALUES($1,$2,$3,$4,$5)", u.Key(), binding, out.Session.ID, bookingHash(b), out.AuthorizationExpiresAt)
		if err != nil {
			return err
		}
		return t.audit(ctx, u.Key(), "automatic_bind", out.Session.ID, "automatic client pinned to recorded booking; no cluster resources changed")
	})
	return out, err
}

func (s *Store) Automatic(ctx context.Context, u model.Identity, binding string) (AutomaticAccess, error) {
	var out AutomaticAccess
	if !ValidAutomaticBinding(binding) {
		return out, ErrNotFound
	}
	err := s.update(ctx, func(t *Tx) error {
		var err error
		out, _, err = t.automatic(ctx, u, binding)
		if err != nil {
			return err
		}
		now, err := t.now(ctx)
		if err != nil {
			return err
		}
		if out.Session.State != "ACTIVE" || out.Session.ExpiresAt != nil && !out.Session.ExpiresAt.After(now) {
			return fmt.Errorf("%w: automatic booking ended; explicitly configure a new booking", ErrConflict)
		}
		return nil
	})
	return out, err
}

// HeartbeatAutomatic accepts only a freshly validated identity's real expiry.
// It does not count as work and therefore cannot keep an idle client alive by
// itself. The 2 minute window exceeds the 30 second stream activity interval.
func (s *Store) HeartbeatAutomatic(ctx context.Context, u model.Identity, binding string) (AutomaticAccess, error) {
	var out AutomaticAccess
	if !ValidAutomaticBinding(binding) {
		return out, ErrNotFound
	}
	err := s.update(ctx, func(t *Tx) error {
		var err error
		out, _, err = t.automatic(ctx, u, binding)
		if err != nil {
			return err
		}
		now, err := t.now(ctx)
		if err != nil {
			return err
		}
		expiry, err := automaticExpiry(u, out.Session, now)
		if err != nil {
			return err
		}
		if out.Session.LastActivityAt == nil || out.Session.LastActivityAt.Before(now.Add(-AutomaticIdleWindow)) {
			return fmt.Errorf("%w: no recent Kubernetes activity; renewal stopped", ErrConflict)
		}
		if expiry.After(out.AuthorizationExpiresAt) {
			if _, err = t.Exec(ctx, "UPDATE automatic_bindings SET authorization_expires_at=$3 WHERE owner_id=$1 AND binding_id=$2", u.Key(), binding, expiry); err != nil {
				return err
			}
			out.AuthorizationExpiresAt = expiry
			return t.audit(ctx, u.Key(), "authorize", out.Session.ID, "active automatic client renewed gateway authorization with a fresh access token")
		}
		return nil
	})
	return out, err
}

func (s *Store) AutomaticSession(ctx context.Context, u model.Identity, binding string) (string, error) {
	var sessionID string
	err := s.Pool.QueryRow(ctx, "SELECT session_id FROM automatic_bindings WHERE owner_id=$1 AND binding_id=$2", u.Key(), binding).Scan(&sessionID)
	if err != nil {
		return "", err
	}
	if err = s.CheckAutomaticAccess(ctx, u, binding, sessionID); err != nil {
		return "", err
	}
	return sessionID, nil
}

// CheckAutomaticAccess binds a stream to its initial exact booking and a current
// authorization lease. Only an endpoint authenticated by a fresh valid JWT can
// extend that lease; the stream's original bearer is never accepted for new calls
// after its actual expiry.
func (s *Store) CheckAutomaticAccess(ctx context.Context, u model.Identity, binding, sessionID string) error {
	var active bool
	err := s.Pool.QueryRow(ctx, `SELECT s.owner_id=$1 AND s.state='ACTIVE'
 AND (s.expires_at IS NULL OR s.expires_at>clock_timestamp())
 AND b.authorization_expires_at>clock_timestamp()
 FROM automatic_bindings b JOIN sessions s ON s.id=b.session_id
 WHERE b.owner_id=$1 AND b.binding_id=$2 AND b.session_id=$3`, u.Key(), binding, sessionID).Scan(&active)
	if err != nil {
		return err
	}
	if !active {
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
