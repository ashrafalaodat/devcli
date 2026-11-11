package store_test

import (
	"context"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

var ctx = context.Background()

func identity(name string) model.Identity {
	return model.Identity{Issuer: "https://issuer.test", Subject: name, Name: name, DisplayName: name + " Developer", Email: name + "@example.test"}
}
func register(t *testing.T, s *store.Store, id string) {
	t.Helper()
	u := identity("admin")
	u.Admin = true
	if e := s.Register(ctx, u, model.Cluster{ID: id, Name: id, Labels: map[string]string{"type": "test"}, MaxParticipants: 2}, []byte("encrypted-placeholder")); e != nil {
		t.Fatal(e)
	}
}
func TestConcurrentExclusiveAndIdempotency(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, _, e := s.Book(ctx, identity(fmt.Sprint(i)), model.Booking{Cluster: "a"}, fmt.Sprint(i)); e == nil {
				successes.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("exclusive double-booked: %d", successes.Load())
	}
	_, ss, e := s.Snapshot(ctx)
	if e != nil || len(ss) != 1 {
		t.Fatal(ss, e)
	}
	register(t, s, "b")
	u := identity("retry")
	successes.Store(0)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, e := s.Book(ctx, u, model.Booking{Cluster: "b"}, "same-key"); e == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 24 {
		t.Fatal("idempotent retries failed")
	}
	_, ss, _ = s.Snapshot(ctx)
	if len(ss) != 2 {
		t.Fatal("duplicate reservation", len(ss))
	}
	if _, _, e = s.Book(ctx, u, model.Booking{}, "same-key"); !errors.Is(e, store.ErrKey) {
		t.Fatal("mismatched key accepted", e)
	}
}
func TestSharingOwnershipTransferLogoutAndRecovery(t *testing.T) {
	s, dsn := testutil.Database(t)
	register(t, s, "a")
	register(t, s, "b")
	alice, bob, charlie := identity("alice"), identity("bob"), identity("charlie")
	a, _, e := s.Book(ctx, alice, model.Booking{Cluster: "a"}, "a")
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Book(ctx, bob, model.Booking{Cluster: "a"}, "b"); e == nil {
		t.Fatal("private booking joined")
	}
	if e = s.Share(ctx, bob, a.ID, true); !errors.Is(e, store.ErrForbidden) {
		t.Fatal("non-owner share", e)
	}
	if e = s.Share(ctx, alice, a.ID, true); e != nil {
		t.Fatal(e)
	}
	b, _, e := s.Book(ctx, bob, model.Booking{Cluster: "a"}, "b")
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Book(ctx, charlie, model.Booking{Cluster: "a"}, "c"); e == nil {
		t.Fatal("third holder accepted")
	}
	if e = s.Share(ctx, bob, b.ID, false); e == nil {
		t.Fatal("participant changed controller setting")
	}
	if _, _, e = s.Config(ctx, bob, a.ID); !errors.Is(e, store.ErrForbidden) {
		t.Fatal("foreign credentials", e)
	}
	if e = s.Stop(ctx, bob, a.ID, "invalid", false); !errors.Is(e, store.ErrForbidden) {
		t.Fatal("foreign stop", e)
	}
	if e = s.Share(ctx, alice, a.ID, false); e != nil {
		t.Fatal(e)
	}
	_, ss, _ := s.Snapshot(ctx)
	if len(ss) != 2 || ss[1].State != "ACTIVE" {
		t.Fatal("disable sharing evicted existing holder")
	}
	// A second process opens the same database and sees durable reservations.
	restarted, e := store.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Pool.Close()
	cs, _, e := restarted.Snapshot(ctx)
	if e != nil || len(cs[0].Participants) != 2 {
		t.Fatal("restart lost reservations", e)
	}
	if e = s.Logout(ctx, alice); e != nil {
		t.Fatal(e)
	}
	cs, _, _ = s.Snapshot(ctx)
	if cs[0].ControllerSession != b.ID || cs[0].Shareable {
		t.Fatal("controller transfer must reset sharing", cs[0])
	}
	if _, _, e = s.Config(ctx, alice, a.ID); !errors.Is(e, store.ErrConflict) {
		t.Fatal("released config downloadable", e)
	}
	if e = s.Share(ctx, bob, b.ID, true); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Book(ctx, charlie, model.Booking{Cluster: "a"}, "c"); e != nil {
		t.Fatal(e)
	}
	if e = s.Logout(ctx, bob); e != nil {
		t.Fatal(e)
	}
	if e = s.Logout(ctx, charlie); e != nil {
		t.Fatal(e)
	}
	cs, _, _ = s.Snapshot(ctx)
	if !cs[0].Available || cs[0].Shareable || cs[0].ControllerSession != "" {
		t.Fatal("empty cluster not reset", cs[0])
	}
}
func TestExpiryMaintenanceAndAutomaticFallback(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	register(t, s, "b")
	a, _, e := s.Book(ctx, identity("a"), model.Booking{}, "a")
	if e != nil || a.Cluster != "a" {
		t.Fatal(a, e)
	}
	b, _, e := s.Book(ctx, identity("b"), model.Booking{}, "b")
	if e != nil || b.Cluster != "b" {
		t.Fatal(b, e)
	}
	if _, _, e = s.Book(ctx, identity("c"), model.Booking{}, "c"); e == nil {
		t.Fatal("full registry accepted booking")
	}
	if _, e = s.Pool.Exec(ctx, "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", a.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.Expire(ctx); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Config(ctx, identity("a"), a.ID); !errors.Is(e, store.ErrConflict) {
		t.Fatal("expired delivery permitted", e)
	}
	admin := identity("admin")
	admin.Admin = true
	if e = s.Maintain(ctx, admin, "a", true, "testing"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Book(ctx, identity("c"), model.Booking{}, "c"); e == nil {
		t.Fatal("maintenance ignored")
	}
	if e = s.Maintain(ctx, admin, "a", false, "done"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Book(ctx, identity("c"), model.Booking{Selector: map[string]string{"type": "test"}}, "c"); e != nil {
		t.Fatal(e)
	}
	if b.ExpiresAt == nil {
		t.Fatal("booking missing inactivity release deadline")
	}
}
func TestConcurrentSharedLimit(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	u := identity("first")
	a, _, e := s.Book(ctx, u, model.Booking{}, "first")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Share(ctx, u, a.ID, true); e != nil {
		t.Fatal(e)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, _, e := s.Book(ctx, identity(fmt.Sprint(i)), model.Booking{}, fmt.Sprint(i)); e == nil {
				successes.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("shared capacity exceeded: %d", successes.Load())
	}
}
