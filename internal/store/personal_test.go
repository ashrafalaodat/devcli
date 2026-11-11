package store_test

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
)

func TestPATDeveloperScopeDigestAndRecovery(t *testing.T) {
	s, dsn := testutil.Database(t)
	alice, bob := identity("alice"), identity("bob")
	alice.Admin = true
	p, raw, err := s.CreatePAT(ctx, alice, "laptop", 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.Owner != alice.Key() || p.Scope != "kubernetes:primary" || p.ExpiresAt.Sub(p.CreatedAt) != store.DefaultPATDuration {
		t.Fatal("incorrect developer PAT lifetime/scope")
	}
	if _, _, err = s.Primary(ctx, alice); !errors.Is(err, store.ErrNoPrimary) {
		t.Fatal("credential issuance booked a cluster", err)
	}
	var digest, identityJSON []byte
	if err = s.Pool.QueryRow(ctx, "SELECT token_digest,identity FROM personal_access_tokens WHERE id=$1", p.ID).Scan(&digest, &identityJSON); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(raw))
	if string(digest) != string(want[:]) || strings.Contains(string(identityJSON), raw) || strings.Contains(string(identityJSON), `"admin":true`) {
		t.Fatal("secret persisted or administrator privilege retained")
	}
	u, err := s.VerifyPAT(ctx, raw)
	if err != nil || u.Key() != alice.Key() || u.Admin || !u.TokenExpiresAt.Equal(p.ExpiresAt) {
		t.Fatal("invalid verified developer PAT", err)
	}
	register(t, s, "a")
	a, _, err := s.Book(ctx, alice, model.Booking{}, "a")
	if err != nil {
		t.Fatal(err)
	}
	if !p.ExpiresAt.After(*a.ExpiresAt) {
		t.Fatal("developer PAT incorrectly tied to booking lease")
	}
	if err = s.Stop(ctx, alice, a.ID, "test", false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.VerifyPAT(ctx, raw); err != nil {
		t.Fatal("stopping booking revoked reusable developer credential", err)
	}
	b, _, err := s.Book(ctx, alice, model.Booking{}, "b")
	if err != nil {
		t.Fatal(err)
	}
	if b.ID == a.ID || !b.Primary {
		t.Fatal("explicit rebooking did not become primary")
	}
	restarted, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Pool.Close()
	if _, err = restarted.VerifyPAT(ctx, raw); err != nil {
		t.Fatal("restart revoked developer PAT", err)
	}
	if err = s.RevokePAT(ctx, bob, p.ID, ""); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("foreign revocation allowed", err)
	}
	if _, err = s.PATs(ctx, bob, true); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("developer listed everyone", err)
	}
	rows, err := s.PATs(ctx, alice, true)
	if err != nil || len(rows) != 1 || rows[0].LastUsedAt == nil {
		t.Fatal("PAT metadata listing failed", err)
	}
	encoded, _ := json.Marshal(rows)
	if strings.Contains(string(encoded), raw) || strings.Contains(string(encoded), "token_digest") || strings.Contains(string(encoded), "session_id") {
		t.Fatal("old session scope or secret in public metadata")
	}
	if err = s.RevokePAT(ctx, alice, p.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.VerifyPAT(ctx, raw); err == nil {
		t.Fatal("revoked PAT accepted")
	}
}

func TestPATExpiryAndAdminRevocation(t *testing.T) {
	for _, end := range []string{"expiry", "admin"} {
		t.Run(end, func(t *testing.T) {
			s, _ := testutil.Database(t)
			u, admin := identity("alice"), identity("admin")
			admin.Admin = true
			p, raw, err := s.CreatePAT(ctx, u, "test", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			switch end {
			case "expiry":
				_, err = s.Pool.Exec(ctx, "UPDATE personal_access_tokens SET created_at=clock_timestamp()-interval '2h',expires_at=clock_timestamp()-interval '1h' WHERE id=$1", p.ID)
			case "admin":
				if err = s.RevokePAT(ctx, admin, p.ID, ""); err == nil {
					t.Fatal("administrator omitted reason")
				}
				err = s.RevokePAT(ctx, admin, p.ID, "lost laptop")
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.VerifyPAT(ctx, raw); err == nil {
				t.Fatal("ended credential accepted")
			}
		})
	}
}

func TestLogoutPreservesPATsAndReleasesBookings(t *testing.T) {
	s, _ := testutil.Database(t)
	alice, bob := identity("alice"), identity("bob")
	register(t, s, "a")
	register(t, s, "b")
	a, _, err := s.Book(ctx, alice, model.Booking{Cluster: "a"}, "alice-before-logout")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := s.Book(ctx, bob, model.Booking{Cluster: "b"}, "bob-before-logout")
	if err != nil {
		t.Fatal(err)
	}
	live := make(map[string]string)
	for _, name := range []string{"laptop", "workstation"} {
		p, raw, err := s.CreatePAT(ctx, alice, name, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		live[p.ID] = raw
	}
	revoked, revokedSecret, err := s.CreatePAT(ctx, alice, "revoked", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RevokePAT(ctx, alice, revoked.ID, "owner explicit revocation"); err != nil {
		t.Fatal(err)
	}
	expired, expiredSecret, err := s.CreatePAT(ctx, alice, "expired", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Pool.Exec(ctx, "UPDATE personal_access_tokens SET created_at=clock_timestamp()-interval '2h',expires_at=clock_timestamp()-interval '1h' WHERE id=$1", expired.ID); err != nil {
		t.Fatal(err)
	}
	_, bobSecret, err := s.CreatePAT(ctx, bob, "bob laptop", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.PATs(ctx, alice, false)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = s.Logout(ctx, alice); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Access(ctx, alice, a.ID); err == nil {
		t.Fatal("logout kept the old reservation active")
	}
	if _, _, err = s.Primary(ctx, alice); !errors.Is(err, store.ErrNoPrimary) {
		t.Fatal("logout retained a primary booking", err)
	}
	if primary, _, err := s.Primary(ctx, bob); err != nil || primary.ID != b.ID {
		t.Fatal("another developer's booking was changed", err)
	}
	if _, err = s.VerifyPAT(ctx, bobSecret); err != nil {
		t.Fatal("another developer's PAT changed", err)
	}
	after, err := s.PATs(ctx, alice, false)
	if err != nil || len(after) != len(before) {
		t.Fatal("logout changed credential metadata", err)
	}
	for i, p := range after {
		old := before[i]
		if p.ID != old.ID || !p.CreatedAt.Equal(old.CreatedAt) || !p.ExpiresAt.Equal(old.ExpiresAt) ||
			(p.RevokedAt == nil) != (old.RevokedAt == nil) ||
			(p.RevokedAt != nil && !p.RevokedAt.Equal(*old.RevokedAt)) {
			t.Fatal("logout changed credential lifetime or revocation")
		}
		if raw, ok := live[p.ID]; ok {
			u, err := s.VerifyPAT(ctx, raw)
			if err != nil || u.Key() != alice.Key() || !u.TokenExpiresAt.Equal(old.ExpiresAt) {
				t.Fatal("logout invalidated or extended a live PAT", err)
			}
		}
	}
	for _, raw := range []string{revokedSecret, expiredSecret} {
		if _, err = s.VerifyPAT(ctx, raw); err == nil {
			t.Fatal("logout revived an expired or explicitly revoked credential")
		}
	}
	newBooking, _, err := s.Book(ctx, alice, model.Booking{Cluster: "a"}, "alice-after-logout")
	if err != nil || newBooking.ID == a.ID {
		t.Fatal("explicit rebooking failed", err)
	}
	for _, raw := range live {
		u, err := s.VerifyPAT(ctx, raw)
		if err != nil {
			t.Fatal("saved PAT no longer authenticates", err)
		}
		primary, _, err := s.Primary(ctx, u)
		if err != nil || primary.ID != newBooking.ID {
			t.Fatal("saved PAT cannot use the later primary booking", err)
		}
	}
}

func TestPATValidationAndLifetime(t *testing.T) {
	s, _ := testutil.Database(t)
	u := identity("alice")
	for _, ttl := range []time.Duration{-time.Second, time.Second, store.MaximumPATDuration + time.Second} {
		if _, _, err := s.CreatePAT(ctx, u, "test", ttl); err == nil {
			t.Fatal("invalid TTL accepted")
		}
	}
	for _, name := range []string{"", " ", strings.Repeat("a", 101)} {
		if _, _, err := s.CreatePAT(ctx, u, name, time.Hour); err == nil {
			t.Fatal("invalid name accepted")
		}
	}
	_, raw, err := s.CreatePAT(ctx, u, "test", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{raw + "x", "dcpat_" + strings.Repeat("A", 43), ""} {
		if _, err = s.VerifyPAT(ctx, bad); err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
}
