package store

import (
	"context"
	"time"
)

// WebSession stores only a cookie digest and an authenticated, encrypted payload.
// OAuth credentials never become part of identity/session API responses.
type WebSession struct {
	ID, Owner  string
	Ciphertext []byte
	ExpiresAt  time.Time
	Version    int64
}

func (s *Store) SaveWebLogin(ctx context.Context, state, cookie string, encrypted []byte) error {
	_, e := s.Pool.Exec(ctx, `INSERT INTO web_login_attempts(state_hash,cookie_hash,payload_ciphertext,expires_at) VALUES($1,$2,$3,clock_timestamp()+interval '10 minutes')`, state, cookie, encrypted)
	return e
}

// ConsumeWebLogin binds the one-time authorization response to the initiating
// browser. A wrong cookie cannot consume another browser's pending attempt.
func (s *Store) ConsumeWebLogin(ctx context.Context, state, cookie string) ([]byte, error) {
	var raw []byte
	e := s.Pool.QueryRow(ctx, `DELETE FROM web_login_attempts WHERE state_hash=$1 AND cookie_hash=$2 AND expires_at>clock_timestamp() RETURNING payload_ciphertext`, state, cookie).Scan(&raw)
	return raw, e
}

func (s *Store) CreateWebSession(ctx context.Context, v WebSession) error {
	_, e := s.Pool.Exec(ctx, `INSERT INTO web_sessions(id_hash,owner_id,payload_ciphertext,expires_at) VALUES($1,$2,$3,$4)`, v.ID, v.Owner, v.Ciphertext, v.ExpiresAt)
	return e
}

func (s *Store) WebSession(ctx context.Context, id string) (WebSession, error) {
	var v WebSession
	e := s.Pool.QueryRow(ctx, `SELECT id_hash,owner_id,payload_ciphertext,expires_at,version FROM web_sessions WHERE id_hash=$1 AND expires_at>clock_timestamp()`, id).Scan(&v.ID, &v.Owner, &v.Ciphertext, &v.ExpiresAt, &v.Version)
	return v, e
}

// The short compare-and-swap lease serializes rotating refresh grants across
// backend instances without keeping a database transaction open over HTTP.
func (s *Store) ClaimWebRefresh(ctx context.Context, id string, version int64, lease string) (bool, error) {
	r, e := s.Pool.Exec(ctx, `UPDATE web_sessions SET refresh_id=$3,refresh_until=clock_timestamp()+interval '30 seconds' WHERE id_hash=$1 AND version=$2 AND expires_at>clock_timestamp() AND (refresh_until IS NULL OR refresh_until<clock_timestamp())`, id, version, lease)
	return r.RowsAffected() == 1, e
}
func (s *Store) CompleteWebRefresh(ctx context.Context, id, lease string, raw []byte) (bool, error) {
	r, e := s.Pool.Exec(ctx, `UPDATE web_sessions SET payload_ciphertext=$3,version=version+1,refresh_id=NULL,refresh_until=NULL WHERE id_hash=$1 AND refresh_id=$2 AND expires_at>clock_timestamp()`, id, lease, raw)
	return r.RowsAffected() == 1, e
}
func (s *Store) DeleteWebSession(ctx context.Context, id string) error {
	_, e := s.Pool.Exec(ctx, `DELETE FROM web_sessions WHERE id_hash=$1`, id)
	return e
}

func (s *Store) PruneWebSessions(ctx context.Context) error {
	_, e := s.Pool.Exec(ctx, `WITH old_logins AS (DELETE FROM web_login_attempts WHERE expires_at<clock_timestamp()) DELETE FROM web_sessions WHERE expires_at<clock_timestamp()`)
	return e
}
