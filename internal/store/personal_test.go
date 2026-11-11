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
	a, _, err := s.Book(ctx, alice, model.Booking{TTL: "1m"}, "a")
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

func TestPATExpiryLogoutAndAdminRevocation(t *testing.T) {
	for _, end := range []string{"expiry", "logout", "admin"} {
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
			case "logout":
				err = s.Logout(ctx, u)
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
