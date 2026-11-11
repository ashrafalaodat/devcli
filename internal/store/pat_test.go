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

func TestPATDigestScopeOwnershipAndRecovery(t *testing.T) {
	s, dsn := testutil.Database(t)
	register(t, s, "a")
	register(t, s, "b")
	alice, bob := identity("alice"), identity("bob")
	alice.Admin = true // Even administrators receive developer-only PATs.
	a, _, err := s.Book(ctx, alice, model.Booking{Cluster: "a", TTL: "1h"}, "a")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := s.Book(ctx, bob, model.Booking{Cluster: "b"}, "b")
	if err != nil {
		t.Fatal(err)
	}
	metadata, secret, err := s.CreatePAT(ctx, alice, a.ID, "laptop", 0)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Owner != alice.Key() || metadata.SessionID != a.ID || metadata.Scope != "kubernetes:session" || !metadata.ExpiresAt.Equal(*a.ExpiresAt) || !strings.HasPrefix(secret, "dcpat_") {
		t.Fatal("PAT scope or capped lease incorrect")
	}
	var digest, rawIdentity []byte
	if err = s.Pool.QueryRow(ctx, "SELECT token_digest,identity FROM personal_access_tokens WHERE id=$1", metadata.ID).Scan(&digest, &rawIdentity); err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256([]byte(secret))
	if string(digest) != string(expected[:]) || strings.Contains(string(rawIdentity), secret) || strings.Contains(string(rawIdentity), `"admin":true`) {
		t.Fatal("secret persisted or privileges retained")
	}
	if _, _, err = s.CreatePAT(ctx, bob, a.ID, "stolen", time.Hour); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("foreign issuance allowed", err)
	}
	if _, err = s.VerifyPAT(ctx, secret, b.ID); err == nil {
		t.Fatal("credential used for another session")
	}
	u, err := s.VerifyPAT(ctx, secret, a.ID)
	if err != nil || u.Key() != alice.Key() || u.Admin || !u.TokenExpiresAt.Equal(metadata.ExpiresAt) {
		t.Fatal("verified identity invalid", err)
	}
	rows, err := s.PATs(ctx, bob, false)
	if err != nil || len(rows) != 0 {
		t.Fatal("foreign credential metadata leaked", err)
	}
	if _, err = s.PATs(ctx, bob, true); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("developer listed all credentials", err)
	}
	rows, err = s.PATs(ctx, alice, true)
	if err != nil || len(rows) != 1 || rows[0].LastUsedAt == nil {
		t.Fatal("administrator listing failed", err)
	}
	encoded, _ := json.Marshal(rows)
	if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "digest") {
		t.Fatal("list leaked secret material")
	}
	restarted, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Pool.Close()
	if _, err = restarted.VerifyPAT(ctx, secret, a.ID); err != nil {
		t.Fatal("restart lost credential", err)
	}
	if err = s.RevokePAT(ctx, bob, metadata.ID, ""); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("foreign revocation allowed", err)
	}
	if err = s.RevokePAT(ctx, alice, metadata.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.VerifyPAT(ctx, secret, a.ID); err == nil {
		t.Fatal("revoked credential accepted")
	}
}

func TestPATExpiryStopLogoutAndAdminRevocation(t *testing.T) {
	for _, end := range []string{"pat-expiry", "session-expiry", "stop", "logout", "admin"} {
		t.Run(end, func(t *testing.T) {
			s, _ := testutil.Database(t)
			register(t, s, "a")
			alice, admin := identity("alice"), identity("admin")
			admin.Admin = true
			a, _, err := s.Book(ctx, alice, model.Booking{}, "a")
			if err != nil {
				t.Fatal(err)
			}
			p, raw, err := s.CreatePAT(ctx, alice, a.ID, "test", time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			switch end {
			case "pat-expiry":
				_, err = s.Pool.Exec(ctx, "UPDATE personal_access_tokens SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1", p.ID)
			case "session-expiry":
				_, err = s.Pool.Exec(ctx, "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", a.ID)
			case "stop":
				err = s.Stop(ctx, alice, a.ID, "test", false)
			case "logout":
				err = s.Logout(ctx, alice)
			case "admin":
				if err = s.RevokePAT(ctx, admin, p.ID, ""); err == nil {
					t.Fatal("administrator revocation had no audit reason")
				}
				err = s.RevokePAT(ctx, admin, p.ID, "owner reported lost laptop")
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.VerifyPAT(ctx, raw, a.ID); err == nil {
				t.Fatal("ended credential accepted")
			}
			if end == "logout" {
				rows, err := s.PATs(ctx, alice, false)
				if err != nil || len(rows) != 1 || rows[0].RevokedAt == nil {
					t.Fatal("logout failed to persist revocation", err)
				}
			}
		})
	}
}

func TestPATValidationAndBoundedLifetime(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	u := identity("alice")
	a, _, err := s.Book(ctx, u, model.Booking{}, "a")
	if err != nil {
		t.Fatal(err)
	}
	for _, duration := range []time.Duration{-time.Second, time.Second, store.MaximumPATDuration + time.Second} {
		if _, _, err = s.CreatePAT(ctx, u, a.ID, "laptop", duration); err == nil {
			t.Fatal("invalid TTL accepted", duration)
		}
	}
	for _, name := range []string{"", "  ", strings.Repeat("a", 101)} {
		if _, _, err = s.CreatePAT(ctx, u, a.ID, name, time.Hour); err == nil {
			t.Fatal("invalid name accepted")
		}
	}
	p, secret, err := s.CreatePAT(ctx, u, a.ID, "laptop", 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.ExpiresAt.Sub(p.CreatedAt) != store.DefaultPATDuration {
		t.Fatal("default PAT lifetime incorrect")
	}
	if _, err = s.VerifyPAT(ctx, secret+"x", a.ID); err == nil {
		t.Fatal("malformed credential accepted")
	}
	if _, err = s.VerifyPAT(ctx, "dcpat_"+strings.Repeat("A", 43), a.ID); err == nil {
		t.Fatal("unknown credential accepted")
	}
}
