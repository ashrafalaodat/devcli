package store_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/scheduler"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
)

func registerLabelled(t *testing.T, s *store.Store, id string, labels map[string]string) {
	t.Helper()
	if err := s.Register(ctx, adminIdentity(), model.Cluster{ID: id, Name: id, Labels: labels, MaxParticipants: 2}, []byte("encrypted-fixture-"+id)); err != nil {
		t.Fatal(err)
	}
}

func TestPATBookingPolicyEditsPreserveCredentialsAndCurrentPrimary(t *testing.T) {
	s, _ := testutil.Database(t)
	u, bob, admin := identity("alice"), identity("bob"), adminIdentity()
	registerLabelled(t, s, "a", map[string]string{"region": "eu"})
	registerLabelled(t, s, "b", map[string]string{"region": "us"})
	p, raw, err := s.CreatePAT(ctx, u, "laptop", time.Hour)
	if err != nil || p.AutoBooking.Enabled || p.AutoBooking.Selector == nil {
		t.Fatal("existing PAT default changed", err)
	}
	if _, _, _, _, err = s.PrimaryPATConfig(ctx, raw); !errors.Is(err, store.ErrNoPrimary) {
		t.Fatal("manual-only PAT allocated a cluster", err)
	}
	policy := model.AutoBookingPolicy{Enabled: true, Selector: map[string]string{"region": "eu"}}
	if _, err = s.UpdatePATBooking(ctx, bob, p.ID, policy, "forged owner"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("foreign identity edited preferences", err)
	}
	if _, err = s.PAT(ctx, bob, p.ID); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("foreign metadata readable", err)
	}
	if _, err = s.UpdatePATBooking(ctx, admin, p.ID, policy, ""); !errors.Is(err, store.ErrConflict) {
		t.Fatal("administrator changed another owner without reason", err)
	}
	if _, err = s.UpdatePATBooking(ctx, u, "missing", policy, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unknown credential not rejected", err)
	}
	updated, err := s.UpdatePATBooking(ctx, u, p.ID, policy, "")
	if err != nil || !updated.AutoBooking.Enabled || updated.AutoBooking.Selector["region"] != "eu" || !updated.CreatedAt.Equal(p.CreatedAt) || !updated.ExpiresAt.Equal(p.ExpiresAt) || updated.Name != p.Name || updated.ID != p.ID {
		t.Fatal("editing changed token identity or lifetime", err)
	}
	var storedDigest []byte
	if err = s.Pool.QueryRow(ctx, "SELECT token_digest FROM personal_access_tokens WHERE id=$1", p.ID).Scan(&storedDigest); err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256([]byte(raw))
	if !bytes.Equal(storedDigest, wantDigest[:]) {
		t.Fatal("editing replaced credential")
	}
	a, version, _, encrypted, err := s.PrimaryPATConfig(ctx, raw)
	if err != nil || a.Cluster != "a" || !a.Primary || a.LastActivityAt == nil || version < 1 || len(encrypted) == 0 {
		t.Fatal("opt-in gateway request failed to allocate a primary", a, err)
	}
	policy.Selector["region"] = "us"
	if _, err = s.UpdatePATBooking(ctx, admin, p.ID, policy, "approved preference change"); err != nil {
		t.Fatal(err)
	}
	still, sameVersion, _, _, err := s.PrimaryPATConfig(ctx, raw)
	if err != nil || still.ID != a.ID || sameVersion != version {
		t.Fatal("selector edit switched an active primary", err)
	}
	if err = s.Stop(ctx, u, a.ID, "next fallback", false); err != nil {
		t.Fatal(err)
	}
	b, _, _, _, err := s.PrimaryPATConfig(ctx, raw)
	if err != nil || b.Cluster != "b" || b.ID == a.ID {
		t.Fatal("same credential did not use edited selector at next booking", err)
	}
	// Disabling future allocation does not affect an existing primary.
	if _, err = s.UpdatePATBooking(ctx, u, p.ID, model.AutoBookingPolicy{}, "disable fallback"); err != nil {
		t.Fatal(err)
	}
	if still, _, _, _, err = s.PrimaryPATConfig(ctx, raw); err != nil || still.ID != b.ID {
		t.Fatal("disabling fallback stopped an active reservation", err)
	}
	if err = s.Stop(ctx, u, b.ID, "done", false); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err = s.PrimaryPATConfig(ctx, raw); !errors.Is(err, store.ErrNoPrimary) {
		t.Fatal("disabled fallback rebooked", err)
	}
	var changes, allocations int
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='pat_booking_update' AND object_id=$1", p.ID).Scan(&changes); err != nil || changes != 3 {
		t.Fatal("policy updates not audited", changes, err)
	}
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='pat_auto_book'").Scan(&allocations); err != nil || allocations != 2 {
		t.Fatal("fallback allocations not audited", allocations, err)
	}
}

func TestPATFallbackIsExclusiveAndUsesExactAvailableLabels(t *testing.T) {
	s, _ := testutil.Database(t)
	registerLabelled(t, s, "a-missing", map[string]string{"region": "eu"})
	registerLabelled(t, s, "b-maintenance", map[string]string{"marker": "", "region": "eu"})
	registerLabelled(t, s, "c-shared", map[string]string{"marker": "", "region": "eu"})
	registerLabelled(t, s, "d-retired", map[string]string{"marker": "", "region": "eu"})
	registerLabelled(t, s, "e-selected", map[string]string{"marker": "", "region": "eu"})
	registerLabelled(t, s, "f-outside", map[string]string{"marker": "", "region": "us"})
	if err := s.Maintain(ctx, adminIdentity(), "b-maintenance", true, "test"); err != nil {
		t.Fatal(err)
	}
	bob := identity("bob")
	held, _, err := s.Book(ctx, bob, model.Booking{Cluster: "c-shared"}, "held")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Share(ctx, bob, held.ID, true); err != nil {
		t.Fatal(err)
	}
	if err = s.Deregister(ctx, adminIdentity(), "d-retired", "test"); err != nil {
		t.Fatal(err)
	}
	u := identity("alice")
	_, raw, err := s.CreatePATWithPolicy(ctx, u, "test", time.Hour, model.AutoBookingPolicy{Enabled: true, Selector: map[string]string{"marker": "", "region": "eu"}})
	if err != nil {
		t.Fatal(err)
	}
	selected, _, _, _, err := s.PrimaryPATConfig(ctx, raw)
	if err != nil || selected.Cluster != "e-selected" {
		t.Fatal("fallback ignored exact labels, maintenance, sharing or retirement", selected, err)
	}
	if _, err = s.VerifyPAT(ctx, raw); err != nil {
		t.Fatal(err)
	}
	other := identity("carol")
	_, otherRaw, err := s.CreatePATWithPolicy(ctx, other, "nomatch", time.Hour, model.AutoBookingPolicy{Enabled: true, Selector: map[string]string{"marker": "", "region": "eu"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err = s.PrimaryPATConfig(ctx, otherRaw); !errors.Is(err, scheduler.ErrUnavailable) {
		t.Fatal("fallback joined a shared cluster or chose outside labels", err)
	}
	profile, err := s.Profile(ctx, other)
	if err != nil || profile.ActiveBookings != 0 || profile.PrimarySession != nil {
		t.Fatal("failed placement left a reservation", err)
	}
}

func TestConcurrentPATFallbackCreatesOneBookingAcrossStores(t *testing.T) {
	s, dsn := testutil.Database(t)
	for _, id := range []string{"a", "b", "c"} {
		register(t, s, id)
	}
	other, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Pool.Close()
	u := identity("alice")
	allowBookings(t, s, u, 3)
	_, raw, err := s.CreatePATWithPolicy(ctx, u, "race", time.Hour, model.AutoBookingPolicy{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	const requests = 24
	start := make(chan struct{})
	results := make(chan string, requests)
	failures := make(chan error, requests)
	var wg sync.WaitGroup
	for i := range requests {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			connection := s
			if i%2 == 0 {
				connection = other
			}
			got, _, _, _, err := connection.PrimaryPATConfig(ctx, raw)
			results <- got.ID
			failures <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	unique := map[string]bool{}
	for id := range results {
		unique[id] = true
	}
	_, sessions, err := s.Snapshot(ctx)
	if err != nil || len(unique) != 1 || len(sessions) != 1 || sessions[0].Cluster != "a" {
		t.Fatal("concurrent requests duplicated or misplaced bookings", len(unique), len(sessions), err)
	}
	profile, err := s.Profile(ctx, u)
	if err != nil || profile.ActiveBookings != 1 || profile.MaxBookings != 3 {
		t.Fatal("fallback booking counts invalid", err)
	}
}

func TestEndedPATsCannotEditOrAutomaticallyBook(t *testing.T) {
	for _, end := range []string{"revoked", "expired", "retired", "invalid"} {
		t.Run(end, func(t *testing.T) {
			s, _ := testutil.Database(t)
			register(t, s, "a")
			u := identity("alice")
			policy := model.AutoBookingPolicy{Enabled: true}
			p, raw, err := s.CreatePATWithPolicy(ctx, u, "test", time.Hour, policy)
			if err != nil {
				t.Fatal(err)
			}
			switch end {
			case "revoked":
				err = s.RevokePAT(ctx, u, p.ID, "test")
			case "expired":
				_, err = s.Pool.Exec(ctx, "UPDATE personal_access_tokens SET created_at=clock_timestamp()-interval '2h',expires_at=clock_timestamp()-interval '1h' WHERE id=$1", p.ID)
			case "retired":
				_, err = s.Pool.Exec(ctx, "UPDATE personal_access_tokens SET scope='kubernetes:session' WHERE id=$1", p.ID)
			case "invalid":
				raw = "dcpat_invalid"
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, _, err = s.PrimaryPATConfig(ctx, raw); !errors.Is(err, store.ErrForbidden) {
				t.Fatal("ended PAT allocated", err)
			}
			if end != "invalid" {
				if _, err = s.UpdatePATBooking(ctx, u, p.ID, policy, "try to restore"); !errors.Is(err, store.ErrConflict) {
					t.Fatal("ended PAT metadata editable", err)
				}
			}
			_, sessions, err := s.Snapshot(ctx)
			if err != nil || len(sessions) != 0 {
				t.Fatal("rejected credential left a booking", err)
			}
		})
	}
}

func TestPATPolicyMigrationRestartAndLogoutFallback(t *testing.T) {
	s, dsn := testutil.Database(t)
	register(t, s, "a")
	u := identity("alice")
	p, raw, err := s.CreatePAT(ctx, u, "before upgrade", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Pool.Exec(ctx, `ALTER TABLE personal_access_tokens DROP COLUMN auto_booking_enabled;
 ALTER TABLE personal_access_tokens DROP COLUMN auto_booking_selector;
 DELETE FROM schema_version WHERE version=8`)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Pool.Close()
	metadata, err := restarted.PAT(ctx, u, p.ID)
	if err != nil || metadata.AutoBooking.Enabled || len(metadata.AutoBooking.Selector) != 0 || !metadata.ExpiresAt.Equal(p.ExpiresAt) {
		t.Fatal("upgrade widened existing PAT or changed expiry", metadata, err)
	}
	if _, _, _, _, err = restarted.PrimaryPATConfig(ctx, raw); !errors.Is(err, store.ErrNoPrimary) {
		t.Fatal("upgraded old PAT allocated", err)
	}
	if _, err = restarted.UpdatePATBooking(ctx, u, p.ID, model.AutoBookingPolicy{Enabled: true}, "enable fallback"); err != nil {
		t.Fatal(err)
	}
	first, _, _, _, err := restarted.PrimaryPATConfig(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.Logout(ctx, u); err != nil {
		t.Fatal(err)
	}
	second, _, _, _, err := restarted.PrimaryPATConfig(ctx, raw)
	if err != nil || second.ID == first.ID {
		t.Fatal("explicitly opted-in PAT did not remain capable after logout", err)
	}
	if err = restarted.Stop(ctx, u, second.ID, "restart check", false); err != nil {
		t.Fatal(err)
	}
	again, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Pool.Close()
	if metadata, err = again.PAT(ctx, u, p.ID); err != nil || !metadata.AutoBooking.Enabled {
		t.Fatal("restart lost edited policy", err)
	}
	third, _, _, _, err := again.PrimaryPATConfig(ctx, raw)
	if err != nil || third.ID == second.ID {
		t.Fatal("same saved PAT failed after restart", err)
	}
}

func TestPATBookingPolicyValidationDoesNotChangeCredential(t *testing.T) {
	s, _ := testutil.Database(t)
	u := identity("alice")
	p, _, err := s.CreatePAT(ctx, u, "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	invalid := model.AutoBookingPolicy{Enabled: true, Selector: map[string]string{"bad/key/again": "test"}}
	if _, _, err = s.CreatePATWithPolicy(ctx, u, "invalid", time.Hour, invalid); !errors.Is(err, store.ErrConflict) {
		t.Fatal("invalid creation selector accepted", err)
	}
	if _, err = s.UpdatePATBooking(ctx, u, p.ID, invalid, "invalid"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("invalid edit selector accepted", err)
	}
	if _, err = s.UpdatePATBooking(ctx, u, p.ID, model.AutoBookingPolicy{Enabled: true}, strings.Repeat("r", 1001)); !errors.Is(err, store.ErrConflict) {
		t.Fatal("unbounded reason accepted", err)
	}
	metadata, err := s.PAT(ctx, u, p.ID)
	if err != nil || metadata.AutoBooking.Enabled || !metadata.ExpiresAt.Equal(p.ExpiresAt) {
		t.Fatal("invalid edit changed metadata", err)
	}
	for i := range 3 {
		if _, _, err = s.CreatePATWithPolicy(ctx, u, fmt.Sprintf("empty-selector-%d", i), time.Hour, model.AutoBookingPolicy{Enabled: true}); err != nil {
			t.Fatal("explicit any-unused-cluster policy rejected", err)
		}
	}
}
