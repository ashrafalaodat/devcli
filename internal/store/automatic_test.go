package store_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
	"github.com/google/uuid"
)

func automaticIdentity(name string) model.Identity {
	u := identity(name)
	u.TokenExpiresAt = time.Now().Add(time.Hour).UTC()
	return u
}

func TestAutomaticConcurrentReuseAndDurablePinning(t *testing.T) {
	s, dsn := testutil.Database(t)
	register(t, s, "a")
	register(t, s, "b")
	u := automaticIdentity("alice")
	manual, _, err := s.Book(ctx, u, model.Booking{Cluster: "b"}, "manual")
	if err != nil {
		t.Fatal(err)
	}
	binding := "a-" + uuid.NewString()
	const requests = 32
	results := make(chan store.AutomaticAccess, requests)
	errorsOut := make(chan error, requests)
	var workers sync.WaitGroup
	for i := 0; i < requests; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			access, err := s.EnsureAutomatic(ctx, u, binding, model.Booking{})
			results <- access
			errorsOut <- err
		}()
	}
	workers.Wait()
	close(results)
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	for access := range results {
		if access.Session.ID != manual.ID || access.Session.Cluster != "b" {
			t.Fatal("automatic retries changed the existing developer's cluster")
		}
	}
	_, sessions, err := s.Snapshot(ctx)
	if err != nil || len(sessions) != 1 {
		t.Fatal("concurrent automatic requests created extra reservations", err)
	}
	if _, err := s.EnsureAutomatic(ctx, u, binding, model.Booking{Cluster: "a"}); !errors.Is(err, store.ErrKey) {
		t.Fatal("binding parameters changed without an explicit new binding", err)
	}
	restarted, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Pool.Close()
	persisted, err := restarted.EnsureAutomatic(ctx, u, binding, model.Booking{})
	if err != nil || persisted.Session.ID != manual.ID {
		t.Fatal("restart lost automatic binding", err)
	}
	other := automaticIdentity("bob")
	if _, err := s.Automatic(ctx, other, binding); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("another identity could read an automatic binding", err)
	}
	if _, err := s.AutomaticSession(ctx, other, binding); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("another identity could route through an automatic binding", err)
	}
	if err := s.Stop(ctx, u, manual.ID, "developer stopped the booking", false); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.EnsureAutomatic(ctx, u, binding, model.Booking{}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("ended binding automatically booked a different environment", err)
	}
	_, sessions, _ = s.Snapshot(ctx)
	if len(sessions) != 1 {
		t.Fatal("ended binding allocated another session")
	}
	reactivated, err := s.EnsureAutomatic(ctx, u, "a-"+uuid.NewString(), model.Booking{})
	if err != nil || reactivated.Session.ID == manual.ID || reactivated.Session.Cluster != "a" {
		t.Fatal("explicit new binding failed to create a fresh booking", err)
	}
}

func TestAutomaticConcurrentOwnersCannotDoubleBook(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	const requests = 24
	var workers sync.WaitGroup
	errorsOut := make(chan error, requests)
	for i := 0; i < requests; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			_, err := s.EnsureAutomatic(ctx, automaticIdentity(fmt.Sprint(i)), "a-"+uuid.NewString(), model.Booking{})
			errorsOut <- err
		}(i)
	}
	workers.Wait()
	close(errorsOut)
	successes := 0
	for err := range errorsOut {
		if err == nil {
			successes++
		}
	}
	_, sessions, err := s.Snapshot(ctx)
	if err != nil || successes != 1 || len(sessions) != 1 {
		t.Fatalf("automatic exclusive allocation double-booked: successes=%d sessions=%d err=%v", successes, len(sessions), err)
	}
}

func TestAutomaticRenewalRequiresActivityAndVerifiedExpiry(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	u := automaticIdentity("alice")
	u.TokenExpiresAt = time.Now().Add(time.Minute).UTC().Truncate(time.Microsecond)
	binding := "a-" + uuid.NewString()
	access, err := s.EnsureAutomatic(ctx, u, binding, model.Booking{TTL: "1h"})
	if err != nil || !access.AuthorizationExpiresAt.Equal(u.TokenExpiresAt) {
		t.Fatal("initial lease was not bounded by the verified access token", err)
	}
	if _, err := s.HeartbeatAutomatic(ctx, u, binding); !errors.Is(err, store.ErrConflict) {
		t.Fatal("a heartbeat without any workload activity was accepted", err)
	}
	if err := s.TouchActivity(ctx, u, access.Session.ID); err != nil {
		t.Fatal(err)
	}
	fresh := u
	fresh.TokenExpiresAt = time.Now().Add(2 * time.Hour)
	renewed, err := s.HeartbeatAutomatic(ctx, fresh, binding)
	if err != nil || renewed.Session.ExpiresAt == nil || !renewed.AuthorizationExpiresAt.Equal(*renewed.Session.ExpiresAt) {
		t.Fatal("authorization did not respect the booking expiry", err)
	}
	if renewed.Session.LastActivityAt == nil {
		t.Fatal("real client activity was not recorded")
	}
	firstActivity := *renewed.Session.LastActivityAt
	if err := s.TouchActivity(ctx, u, access.Session.ID); err != nil {
		t.Fatal(err)
	}
	read, err := s.Automatic(ctx, u, binding)
	if err != nil || read.Session.LastActivityAt == nil || !read.Session.LastActivityAt.Equal(firstActivity) {
		t.Fatal("activity writes were not throttled", err)
	}
	if _, err := s.Pool.Exec(ctx, "UPDATE sessions SET last_activity_at=clock_timestamp()-interval '3 minutes' WHERE id=$1", access.Session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HeartbeatAutomatic(ctx, fresh, binding); !errors.Is(err, store.ErrConflict) {
		t.Fatal("heartbeat kept an idle client alive", err)
	}
	read, err = s.Automatic(ctx, u, binding)
	if err != nil || read.Session.LastActivityAt == nil || !read.Session.LastActivityAt.Before(time.Now().Add(-2*time.Minute)) {
		t.Fatal("control-plane queries incorrectly counted as workload activity", err)
	}
	missing := u
	missing.TokenExpiresAt = time.Time{}
	if _, err := s.EnsureAutomatic(ctx, missing, "a-"+uuid.NewString(), model.Booking{}); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("automatic access accepted an identity without verified expiry", err)
	}
	if _, err := s.HeartbeatAutomatic(ctx, missing, binding); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("heartbeat accepted an identity without verified expiry", err)
	}
	if _, err := s.Pool.Exec(ctx, "UPDATE automatic_bindings SET authorization_expires_at=clock_timestamp()-interval '1 second' WHERE owner_id=$1 AND binding_id=$2", u.Key(), binding); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckAutomaticAccess(ctx, u, binding, access.Session.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatal("expired authorization continued permitting a stream", err)
	}
	if err := s.TouchActivity(ctx, fresh, access.Session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HeartbeatAutomatic(ctx, fresh, binding); err != nil {
		t.Fatal("a fresh authenticated heartbeat did not reauthorize active work", err)
	}
	if err := s.Logout(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckAutomaticAccess(ctx, fresh, binding, access.Session.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatal("a valid authorization lease bypassed logout", err)
	}
}
