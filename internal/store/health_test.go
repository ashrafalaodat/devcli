package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/scheduler"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
)

func healthAdmin() model.Identity { u := identity("admin"); u.Admin = true; return u }
func dueHealth(t *testing.T, s *store.Store, id string) {
	t.Helper()
	if _, e := s.Pool.Exec(t.Context(), "UPDATE cluster_health SET next_check_at=clock_timestamp() WHERE cluster_id=$1", id); e != nil {
		t.Fatal(e)
	}
}
func claimHealth(t *testing.T, s *store.Store, id string) store.HealthClaim {
	t.Helper()
	dueHealth(t, s, id)
	claims, e := s.ClaimHealthChecks(t.Context(), 64)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range claims {
		if c.ClusterID == id {
			return c
		}
	}
	t.Fatal("expected health claim", id)
	return store.HealthClaim{}
}
func passedHealth() model.HealthResult {
	return model.HealthResult{Passed: true, ReasonCode: "checks_passed", ReadinessConfirmed: true, DiscoveryCoverage: "baseline", Components: []model.HealthComponent{{Name: "version", State: "PASSING", HTTPStatus: 200}}}
}
func publishHealth(t *testing.T, s *store.Store, c store.HealthClaim, r model.HealthResult) {
	t.Helper()
	accepted, e := s.PublishHealthCheck(t.Context(), c, r, 30*time.Second)
	if e != nil || !accepted {
		t.Fatal("publication failed", accepted, e)
	}
}
func healthy(t *testing.T, s *store.Store, id string) {
	t.Helper()
	for range 2 {
		publishHealth(t, s, claimHealth(t, s, id), passedHealth())
	}
}

func TestHealthDefaultAndPermissionBoundaries(t *testing.T) {
	s, _ := testutil.Database(t)
	registerUnobserved(t, s, "a")
	h, e := s.GetHealth(t.Context(), "a")
	if e != nil || h.State != "UNKNOWN" || !h.CheckPending {
		t.Fatal(h, e)
	}
	if _, _, e = s.Book(t.Context(), identity("alice"), model.Booking{Cluster: "a"}, "unobserved"); !errors.Is(e, scheduler.ErrUnavailable) {
		t.Fatal("default monitoring admitted unobserved cluster", e)
	}
	claims, e := s.ClaimHealthChecks(t.Context(), 4)
	if e != nil || len(claims) != 1 {
		t.Fatal("default monitoring did not schedule live cluster", claims, e)
	}
	if _, e = s.RequestHealthCheck(t.Context(), identity("alice"), "a", "unauthorized"); !errors.Is(e, store.ErrForbidden) {
		t.Fatal(e)
	}
	if e = s.SetHealthProfile(t.Context(), identity("alice"), "a", model.HealthProfileDiscoveryOnly, 1, "unauthorized"); !errors.Is(e, store.ErrForbidden) {
		t.Fatal(e)
	}
	if _, e = s.RequestHealthCheck(t.Context(), healthAdmin(), "a", ""); !errors.Is(e, store.ErrConflict) {
		t.Fatal(e)
	}
	if _, e = s.RequestHealthCheck(t.Context(), healthAdmin(), "a", "check automatically monitored cluster"); e != nil {
		t.Fatal(e)
	}
	var columns int
	if e = s.Pool.QueryRow(t.Context(), "SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='application_settings' AND column_name='health_mode'").Scan(&columns); e != nil || columns != 0 {
		t.Fatal("old monitoring setting remains", columns, e)
	}
}

func TestHealthRecoveryGateStalenessAndExistingBooking(t *testing.T) {
	s, _ := testutil.Database(t)
	registerUnobserved(t, s, "a")
	if _, _, e := s.Book(t.Context(), identity("alice"), model.Booking{Cluster: "a"}, "book"); !errors.Is(e, scheduler.ErrUnavailable) {
		t.Fatal("unknown health admitted", e)
	}
	// A missing row must still hydrate UNKNOWN and fail closed, rather than a nil
	// optional Health pointer bypassing enforcement.
	if _, e := s.Pool.Exec(t.Context(), "DELETE FROM cluster_health WHERE cluster_id='a'"); e != nil {
		t.Fatal(e)
	}
	if _, _, e := s.Book(t.Context(), identity("alice"), model.Booking{Cluster: "a"}, "missing"); !errors.Is(e, scheduler.ErrUnavailable) {
		t.Fatal("missing health admitted", e)
	}
	if _, e := s.RequestHealthCheck(t.Context(), healthAdmin(), "a", "restore missing queue row"); e != nil {
		t.Fatal(e)
	}
	publishHealth(t, s, claimHealth(t, s, "a"), passedHealth())
	h, e := s.GetHealth(t.Context(), "a")
	if e != nil || h.State != "RECOVERING" || h.ConsecutiveSuccesses != 1 {
		t.Fatal(h, e)
	}
	if _, _, e = s.Book(t.Context(), identity("alice"), model.Booking{Cluster: "a"}, "one-pass"); !errors.Is(e, scheduler.ErrUnavailable) {
		t.Fatal("one pass admitted", e)
	}
	publishHealth(t, s, claimHealth(t, s, "a"), passedHealth())
	held, _, e := s.Book(t.Context(), identity("alice"), model.Booking{Cluster: "a"}, "book")
	if e != nil {
		t.Fatal(e)
	}
	publishHealth(t, s, claimHealth(t, s, "a"), model.HealthResult{ReasonCode: "connect_timeout"})
	replay, created, e := s.Book(t.Context(), identity("alice"), model.Booking{Cluster: "a"}, "book")
	if e != nil || created || replay.ID != held.ID {
		t.Fatal("failure changed successful retry identity", replay, created, e)
	}
	var state string
	if e = s.Pool.QueryRow(t.Context(), "SELECT state FROM sessions WHERE id=$1", held.ID).Scan(&state); e != nil || state != "ACTIVE" {
		t.Fatal("health evicted existing booking", state, e)
	}
	if e = s.Access(t.Context(), identity("alice"), held.ID); e != nil {
		t.Fatal("health became access control", e)
	}
	healthy(t, s, "a")
	if _, e = s.Pool.Exec(t.Context(), "UPDATE cluster_health SET checked_at=clock_timestamp()-interval '91 seconds' WHERE cluster_id='a'"); e != nil {
		t.Fatal(e)
	}
	h, e = s.GetHealth(t.Context(), "a")
	if e != nil || h.State != "STALE" {
		t.Fatal("dead worker left green", h, e)
	}
	publishHealth(t, s, claimHealth(t, s, "a"), passedHealth())
	h, e = s.GetHealth(t.Context(), "a")
	if e != nil || h.State != "RECOVERING" || h.ConsecutiveSuccesses != 1 {
		t.Fatal("stale streak reused", h, e)
	}
}

func TestHealthLeasesAndGenerationFencing(t *testing.T) {
	s, _ := testutil.Database(t)
	registerUnobserved(t, s, "a")
	var wg sync.WaitGroup
	var mu sync.Mutex
	all := []store.HealthClaim{}
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := s.ClaimHealthChecks(context.Background(), 1)
			mu.Lock()
			defer mu.Unlock()
			if e != nil {
				t.Error(e)
			}
			all = append(all, v...)
		}()
	}
	wg.Wait()
	if len(all) != 1 {
		t.Fatal("concurrent workers double claimed", len(all))
	}
	old := all[0]
	if _, e := s.Pool.Exec(t.Context(), "UPDATE cluster_health SET lease_until=clock_timestamp()-interval '1 second',next_check_at=clock_timestamp() WHERE cluster_id='a'"); e != nil {
		t.Fatal(e)
	}
	successor := claimHealth(t, s, "a")
	if ok, e := s.PublishHealthCheck(t.Context(), old, passedHealth(), 30*time.Second); e != nil || ok {
		t.Fatal("old lease published", ok, e)
	}
	publishHealth(t, s, successor, passedHealth())
	old = claimHealth(t, s, "a")
	if e := s.SetHealthProfile(t.Context(), healthAdmin(), "a", model.HealthProfileDiscoveryOnly, 1, "explicit readiness exception"); e != nil {
		t.Fatal(e)
	}
	if ok, e := s.PublishHealthCheck(t.Context(), old, passedHealth(), 30*time.Second); e != nil || ok {
		t.Fatal("old profile published", ok, e)
	}
	h, e := s.GetHealth(t.Context(), "a")
	if e != nil || h.State != "UNKNOWN" || h.PolicyRevision != 2 {
		t.Fatal(h, e)
	}
	if e = s.SetHealthProfile(t.Context(), healthAdmin(), "a", model.HealthProfileAPIReady, 1, "stale editor"); !errors.Is(e, store.ErrConflict) {
		t.Fatal(e)
	}
	old = claimHealth(t, s, "a")
	if _, e = s.Pool.Exec(t.Context(), "UPDATE clusters SET kubeconfig_ciphertext=$1 WHERE id='a'", []byte("replacement")); e != nil {
		t.Fatal(e)
	}
	if ok, e := s.PublishHealthCheck(t.Context(), old, passedHealth(), 30*time.Second); e != nil || ok {
		t.Fatal("old credentials published", ok, e)
	}
	old = claimHealth(t, s, "a")
	if e = s.Deregister(t.Context(), healthAdmin(), "a", "retire"); e != nil {
		t.Fatal(e)
	}
	if ok, e := s.PublishHealthCheck(t.Context(), old, passedHealth(), 30*time.Second); e != nil || ok {
		t.Fatal("retired cluster revived", ok, e)
	}
}

func TestHealthPATSkipsUnhealthyFirstAndPreservesPrimary(t *testing.T) {
	s, _ := testutil.Database(t)
	registerUnobserved(t, s, "a")
	registerUnobserved(t, s, "b")
	// Claiming a batch leases both clusters; release unrelated fixture lease so
	// each helper can schedule the named cluster independently.
	if _, e := s.Pool.Exec(t.Context(), "UPDATE cluster_health SET next_check_at=clock_timestamp()+interval '1 day' WHERE cluster_id='a'"); e != nil {
		t.Fatal(e)
	}
	healthy(t, s, "b")
	alice := identity("alice")
	_, raw, e := s.CreatePATWithPolicy(t.Context(), alice, "auto", time.Hour, model.AutoBookingPolicy{Enabled: true, Selector: map[string]string{}})
	if e != nil {
		t.Fatal(e)
	}
	session, _, cluster, _, e := s.PrimaryPATConfig(t.Context(), raw)
	if e != nil || cluster != "b" {
		t.Fatal("unhealthy first candidate stopped fallback", cluster, e)
	}
	if _, e = s.Pool.Exec(t.Context(), "UPDATE cluster_health SET observed_state='FAILING',reason_code='connect_timeout' WHERE cluster_id='b'"); e != nil {
		t.Fatal(e)
	}
	same, _, again, _, e := s.PrimaryPATConfig(t.Context(), raw)
	if e != nil || again != "b" || same.ID != session.ID {
		t.Fatal("background failure moved primary", same, again, e)
	}
}

func TestHealthReadAndPublicationNeverExtendOrExpireBookings(t *testing.T) {
	s, _ := testutil.Database(t)
	registerUnobserved(t, s, "a")
	healthy(t, s, "a")
	alice := identity("alice")
	held, _, e := s.Book(t.Context(), alice, model.Booking{Cluster: "a"}, "held")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Pool.Exec(t.Context(), "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", held.ID); e != nil {
		t.Fatal(e)
	}
	var before time.Time
	var activityBefore *time.Time
	if e = s.Pool.QueryRow(t.Context(), "SELECT expires_at,last_activity_at FROM sessions WHERE id=$1", held.ID).Scan(&before, &activityBefore); e != nil {
		t.Fatal(e)
	}
	if _, e = s.GetHealth(t.Context(), "a"); e != nil {
		t.Fatal(e)
	}
	first, e := s.RequestHealthCheck(t.Context(), healthAdmin(), "a", "check")
	if e != nil {
		t.Fatal(e)
	}
	second, e := s.RequestHealthCheck(t.Context(), healthAdmin(), "a", "duplicate request")
	if e != nil || first.ID != second.ID {
		t.Fatal("refresh did not coalesce", first, second, e)
	}
	publishHealth(t, s, claimHealth(t, s, "a"), model.HealthResult{ReasonCode: "connect_timeout"})
	var after time.Time
	var activityAfter *time.Time
	var state string
	if e = s.Pool.QueryRow(t.Context(), "SELECT expires_at,last_activity_at,state FROM sessions WHERE id=$1", held.ID).Scan(&after, &activityAfter, &state); e != nil {
		t.Fatal(e)
	}
	if !before.Equal(after) || state != "ACTIVE" || activityBefore != nil || activityAfter != nil {
		t.Fatal("health mutated reservation", before, after, state)
	}
	// Expected health allocation rejection still commits valid expiry housekeeping.
	if _, _, e = s.Book(t.Context(), identity("bob"), model.Booking{Cluster: "a"}, "rejected"); !errors.Is(e, scheduler.ErrUnavailable) {
		t.Fatal(e)
	}
	if e = s.Pool.QueryRow(t.Context(), "SELECT state FROM sessions WHERE id=$1", held.ID).Scan(&state); e != nil || state != "EXPIRED" {
		t.Fatal("expected rejection rolled back expiry", state, e)
	}
}

func TestHealthFailureAndAllocationHaveDurableOrder(t *testing.T) {
	s, _ := testutil.Database(t)
	registerUnobserved(t, s, "a")
	for attempt := range 8 {
		healthy(t, s, "a")
		claim := claimHealth(t, s, "a")
		user := identity("racer-" + time.Now().Format("150405.000000000"))
		start := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			<-start
			accepted, e := s.PublishHealthCheck(context.Background(), claim, model.HealthResult{ReasonCode: "connect_timeout"}, 30*time.Second)
			if e == nil && !accepted {
				e = errors.New("claim unexpectedly rejected")
			}
			done <- e
		}()
		close(start)
		held, _, e := s.Book(t.Context(), user, model.Booking{Cluster: "a"}, "race")
		if publication := <-done; publication != nil {
			t.Fatal(publication)
		}
		if e != nil && !errors.Is(e, scheduler.ErrUnavailable) {
			t.Fatal(e)
		}
		if e == nil {
			var bookOrder, failureOrder int64
			if e = s.Pool.QueryRow(t.Context(), "SELECT id FROM audit WHERE action='book' AND object_id=$1", held.ID).Scan(&bookOrder); e != nil {
				t.Fatal(e)
			}
			if e = s.Pool.QueryRow(t.Context(), "SELECT max(id) FROM audit WHERE action='cluster_health_transition' AND object_id='a' AND detail LIKE '%-> FAILING%' ").Scan(&failureOrder); e != nil {
				t.Fatal(e)
			}
			if bookOrder >= failureOrder {
				t.Fatalf("allocation %d happened after health failure: iteration %d", bookOrder, attempt)
			}
			if e = s.Stop(t.Context(), user, held.ID, "finish race fixture", false); e != nil {
				t.Fatal(e)
			}
		}
	}
}

func TestHealthRestartPreservesFreshObservation(t *testing.T) {
	s, dsn := testutil.Database(t)
	registerUnobserved(t, s, "a")
	healthy(t, s, "a")
	before, e := s.GetHealth(t.Context(), "a")
	if e != nil {
		t.Fatal(e)
	}
	restarted, e := store.Open(t.Context(), dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Pool.Close()
	after, e := restarted.GetHealth(t.Context(), "a")
	if e != nil || after.State != "PASSING" || after.CheckedAt == nil || !after.CheckedAt.Equal(*before.CheckedAt) || after.ConsecutiveSuccesses != before.ConsecutiveSuccesses {
		t.Fatal("restart changed durable observation", before, after, e)
	}
	if _, _, e = restarted.Book(t.Context(), identity("alice"), model.Booking{Cluster: "a"}, "after-restart"); e != nil {
		t.Fatal(e)
	}
}

func TestHealthMigrationRemovesLegacyDisabledModeWithoutChangingBooking(t *testing.T) {
	s, dsn := testutil.Database(t)
	register(t, s, "a")
	held, _, err := s.Book(t.Context(), identity("alice"), model.Booking{Cluster: "a"}, "before-upgrade")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Pool.Exec(t.Context(), `ALTER TABLE application_settings ADD COLUMN health_mode text NOT NULL DEFAULT 'disabled';
 UPDATE cluster_health SET observed_state='UNKNOWN',checked_at=NULL,next_check_at=clock_timestamp(),consecutive_successes=0;
 DELETE FROM schema_version WHERE version=11`); err != nil {
		t.Fatal(err)
	}
	upgraded, err := store.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Pool.Close()
	claims, err := upgraded.ClaimHealthChecks(t.Context(), 4)
	if err != nil || len(claims) != 1 {
		t.Fatal("legacy disabled install did not schedule checks automatically", len(claims), err)
	}
	if err = upgraded.Access(t.Context(), identity("alice"), held.ID); err != nil {
		t.Fatal("automatic health migration revoked existing access", err)
	}
	if _, _, err = upgraded.Book(t.Context(), identity("bob"), model.Booking{Cluster: "a"}, "after-upgrade"); !errors.Is(err, scheduler.ErrUnavailable) {
		t.Fatal("unobserved cluster accepted a new booking", err)
	}
}
