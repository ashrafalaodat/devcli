package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"devctl.local/devctl/internal/model"
	"github.com/google/uuid"
)

const DefaultPATDuration = 8 * time.Hour
const MaximumPATDuration = 7 * 24 * time.Hour

var validPAT = regexp.MustCompile(`^dcpat_[A-Za-z0-9_-]{43}$`)

// PAT is public metadata. The digest and one-time secret are never part of it.
// A PAT grants Kubernetes gateway access to exactly one recorded session. It
// cannot authenticate to the control API, carry administrator rights or renew.
type PAT struct {
	ID         string     `json:"id"`
	Owner      string     `json:"owner"`
	SessionID  string     `json:"session_id"`
	Name       string     `json:"name"`
	Scope      string     `json:"scope"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

func (s *Store) CreatePAT(ctx context.Context, u model.Identity, sessionID, name string, ttl time.Duration) (PAT, string, error) {
	var out PAT
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return out, "", fmt.Errorf("%w: credential name must be 1 through 100 bytes", ErrConflict)
	}
	if ttl == 0 {
		ttl = DefaultPATDuration
	}
	if ttl < time.Minute || ttl > MaximumPATDuration {
		return out, "", fmt.Errorf("%w: credential TTL must be 1m through 168h", ErrConflict)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return out, "", errors.New("credential randomness unavailable")
	}
	raw := "dcpat_" + base64.RawURLEncoding.EncodeToString(secret)
	digest := sha256.Sum256([]byte(raw))
	err := s.update(ctx, func(t *Tx) error {
		if err := t.expire(ctx); err != nil {
			return err
		}
		var owner, state string
		var expiry *time.Time
		if err := t.QueryRow(ctx, "SELECT owner_id,state,expires_at FROM sessions WHERE id=$1", sessionID).Scan(&owner, &state, &expiry); err != nil {
			return err
		}
		if owner != u.Key() {
			return ErrForbidden
		}
		now, err := t.now(ctx)
		if err != nil {
			return err
		}
		if state != "ACTIVE" || expiry != nil && !expiry.After(now) {
			return ErrConflict
		}
		end := now.Add(ttl)
		if expiry != nil && expiry.Before(end) {
			end = *expiry
		}
		out = PAT{ID: "p-" + uuid.NewString(), Owner: u.Key(), SessionID: sessionID, Name: name, Scope: "kubernetes:session", CreatedAt: now, ExpiresAt: end}
		identity := u
		identity.Admin = false
		identity.TokenExpiresAt = time.Time{}
		identityJSON, err := json.Marshal(identity)
		if err != nil {
			return err
		}
		if _, err = t.Exec(ctx, "INSERT INTO personal_access_tokens(id,owner_id,session_id,name,token_digest,identity,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", out.ID, out.Owner, out.SessionID, out.Name, digest[:], identityJSON, out.CreatedAt, out.ExpiresAt); err != nil {
			return err
		}
		return t.audit(ctx, u.Key(), "pat_create", out.ID, "one-time gateway credential issued for session "+sessionID+"; no control API or administrator access")
	})
	if err != nil {
		return PAT{}, "", err
	}
	return out, raw, nil
}

func (s *Store) PATs(ctx context.Context, u model.Identity, all bool) ([]PAT, error) {
	if all && !u.Admin {
		return nil, ErrForbidden
	}
	rows, err := s.Pool.Query(ctx, "SELECT id,owner_id,session_id,name,created_at,expires_at,revoked_at,last_used_at FROM personal_access_tokens WHERE ($1 OR owner_id=$2) ORDER BY created_at DESC,id LIMIT 500", all, u.Key())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PAT{}
	for rows.Next() {
		v := PAT{Scope: "kubernetes:session"}
		if err := rows.Scan(&v.ID, &v.Owner, &v.SessionID, &v.Name, &v.CreatedAt, &v.ExpiresAt, &v.RevokedAt, &v.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) RevokePAT(ctx context.Context, u model.Identity, id, reason string) error {
	return s.update(ctx, func(t *Tx) error {
		var owner string
		if err := t.QueryRow(ctx, "SELECT owner_id FROM personal_access_tokens WHERE id=$1", id).Scan(&owner); err != nil {
			return err
		}
		if owner != u.Key() {
			if !u.Admin {
				return ErrForbidden
			}
			if strings.TrimSpace(reason) == "" {
				return fmt.Errorf("%w: administrator revocation requires an audit reason", ErrConflict)
			}
		}
		if len(reason) > 1000 {
			return fmt.Errorf("%w: audit reason must be at most 1000 bytes", ErrConflict)
		}
		if reason == "" {
			reason = "owner revoked gateway credential"
		}
		if _, err := t.Exec(ctx, "UPDATE personal_access_tokens SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE id=$1", id); err != nil {
			return err
		}
		return t.audit(ctx, u.Key(), "pat_revoke", id, reason)
	})
}

// VerifyPAT is used only by the Kubernetes gateway. It rechecks the exact
// session, expiry and revocation for new requests and existing streams. The
// secret is never persisted, returned or passed upstream.
func (s *Store) VerifyPAT(ctx context.Context, raw, sessionID string) (model.Identity, error) {
	var u model.Identity
	if !validPAT.MatchString(raw) {
		return u, ErrForbidden
	}
	digest := sha256.Sum256([]byte(raw))
	var id, owner string
	var identityJSON []byte
	err := s.Pool.QueryRow(ctx, `SELECT p.id,p.owner_id,p.identity,p.expires_at
FROM personal_access_tokens p JOIN sessions s ON s.id=p.session_id
WHERE p.token_digest=$1 AND p.session_id=$2 AND p.revoked_at IS NULL
 AND p.expires_at>clock_timestamp() AND s.owner_id=p.owner_id
 AND s.state='ACTIVE' AND (s.expires_at IS NULL OR s.expires_at>clock_timestamp())`, digest[:], sessionID).Scan(&id, &owner, &identityJSON, &u.TokenExpiresAt)
	if err != nil {
		return model.Identity{}, err
	}
	if err = json.Unmarshal(identityJSON, &u); err != nil {
		return model.Identity{}, errors.New("invalid stored credential identity")
	}
	if u.Key() != owner {
		return model.Identity{}, ErrForbidden
	}
	u.Admin = false
	if _, err = s.Pool.Exec(ctx, "UPDATE personal_access_tokens SET last_used_at=clock_timestamp() WHERE id=$1 AND (last_used_at IS NULL OR last_used_at<clock_timestamp()-interval '30 seconds')", id); err != nil {
		return model.Identity{}, err
	}
	return u, nil
}

type AuditEvent struct {
	ID       int64     `json:"id"`
	At       time.Time `json:"at"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	ObjectID string    `json:"object_id"`
	Detail   string    `json:"detail"`
}

func (s *Store) AuditEvents(ctx context.Context, u model.Identity, limit int) ([]AuditEvent, error) {
	if !u.Admin {
		return nil, ErrForbidden
	}
	if limit < 1 || limit > 500 {
		return nil, fmt.Errorf("%w: audit limit must be 1 through 500", ErrConflict)
	}
	rows, err := s.Pool.Query(ctx, "SELECT id,at,actor,action,object_id,detail FROM audit ORDER BY id DESC LIMIT $1", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEvent{}
	for rows.Next() {
		var v AuditEvent
		if err = rows.Scan(&v.ID, &v.At, &v.Actor, &v.Action, &v.ObjectID, &v.Detail); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
