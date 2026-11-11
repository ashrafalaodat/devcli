package store_test

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
)

// Age a reservation without sleeping or weakening the configured minimum. All
// deadlines remain derived from the same baseline the production policy uses.
func ageBooking(t *testing.T, s *store.Store, id string, age time.Duration) {
	t.Helper()
	_, err := s.Pool.Exec(ctx, `UPDATE sessions SET created_at=clock_timestamp()-$2*interval '1 second',
 idle_anchor_at=clock_timestamp()-$2*interval '1 second',last_activity_at=NULL,
 expires_at=clock_timestamp()-$2*interval '1 second'+make_interval(secs=>a.inactivity_grace_seconds)
 FROM application_settings a WHERE id=$1`, id, age.Seconds())
	if err != nil {
		t.Fatal(err)
	}
}

func currentBooking(t *testing.T, s *store.Store, id string) model.Session {
	t.Helper()
	_, sessions, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		if session.ID == id {
			return session
		}
	}
	t.Fatal("booking not found")
	return model.Session{}
}

func TestActivityKeepsOnlyExactPrimaryClusterReserved(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	register(t, s, "b")
	u := identity("alice")
	u.TokenExpiresAt = time.Now().Add(8 * time.Hour)
	allowBookings(t, s, u, 2)
	a, _, err := s.Book(ctx, u, model.Booking{Cluster: "a"}, "a")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := s.Book(ctx, u, model.Booking{Cluster: "b"}, "b")
	if err != nil {
		t.Fatal(err)
	}
	if a.ExpiresAt == nil || a.ExpiresAt.Sub(a.CreatedAt) != 4*time.Hour || a.LastActivityAt != nil {
		t.Fatal("new reservation lacks grace baseline or fabricates activity", a)
	}
	ageBooking(t, s, a.ID, 3*time.Hour)
	ageBooking(t, s, b.ID, 3*time.Hour)
	beforeB := currentBooking(t, s, b.ID)
	active, version, _, encrypted, err := s.PrimaryConfig(ctx, u)
	if err != nil || len(encrypted) == 0 || active.ID != a.ID || active.LastActivityAt == nil || active.ExpiresAt.Sub(*active.LastActivityAt) != 4*time.Hour {
		t.Fatal("gateway request did not extend its reservation", active, err)
	}
	afterB := currentBooking(t, s, b.ID)
	if !afterB.ExpiresAt.Equal(*beforeB.ExpiresAt) || afterB.LastActivityAt != nil {
		t.Fatal("activity on primary extended another booking")
	}
	// Read-only state, login observations and OAuth refresh cannot keep bookings.
	if _, err = s.Profile(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err = s.ObserveIdentity(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AuthorizePrimary(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err = s.HeartbeatPrimary(ctx, u); err != nil {
		t.Fatal(err)
	}
	unchanged := currentBooking(t, s, a.ID)
	if !unchanged.ExpiresAt.Equal(*active.ExpiresAt) || !unchanged.LastActivityAt.Equal(*active.LastActivityAt) {
		t.Fatal("read or OAuth heartbeat counted as reservation activity")
	}
	// A genuine primary switch keeps only its target alive, including reselect.
	p, err := s.SelectPrimary(ctx, u, b.ID)
	if err != nil || p.PrimarySession.LastActivityAt == nil || !p.PrimarySession.ExpiresAt.After(*beforeB.ExpiresAt) {
		t.Fatal("explicit selection did not extend target", err)
	}
	if _, err = s.RecordPrimaryActivity(ctx, u, a.ID, version); !errors.Is(err, store.ErrConflict) {
		t.Fatal("stale tab or stream kept old cluster alive", err)
	}
	if _, err = s.RecordPrimaryActivity(ctx, identity("bob"), b.ID, p.SelectionVersion); !errors.Is(err, store.ErrConflict) {
		t.Fatal("foreign identity counted activity", err)
	}
	if _, err = s.Pool.Exec(ctx, "UPDATE sessions SET last_activity_at=clock_timestamp()-interval '20s',expires_at=clock_timestamp()+interval '1h' WHERE id=$1", b.ID); err != nil {
		t.Fatal(err)
	}
	p, err = s.SelectPrimary(ctx, u, b.ID)
	if err != nil || p.PrimarySession.ExpiresAt.Sub(*p.PrimarySession.LastActivityAt) != 4*time.Hour {
		t.Fatal("reselecting same primary failed to count activity", err)
	}
	if err = s.Stop(ctx, u, b.ID, "done", false); err != nil {
		t.Fatal(err)
	}
	p, err = s.Profile(ctx, u)
	if err != nil || p.PrimarySession.ID != a.ID || !p.PrimarySession.ExpiresAt.Equal(*active.ExpiresAt) || !p.PrimarySession.LastActivityAt.Equal(*active.LastActivityAt) {
		t.Fatal("automatic promotion fabricated activity", err)
	}
}

func TestInactivityPolicyChangesCurrentBookingsAndPreservesPATs(t *testing.T) {
	s, _ := testutil.Database(t)
	for _, cluster := range []string{"a", "b", "c"} {
		register(t, s, cluster)
	}
	u, admin := identity("alice"), adminIdentity()
	allowBookings(t, s, u, 3)
	a, _, err := s.Book(ctx, u, model.Booking{Cluster: "a"}, "a")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := s.Book(ctx, u, model.Booking{Cluster: "b"}, "b")
	if err != nil {
		t.Fatal(err)
	}
	pat, secret, err := s.CreatePAT(ctx, u, "laptop", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ageBooking(t, s, a.ID, 20*time.Minute)
	grace := 10 * time.Minute
	if err = s.UpdateReservationPolicy(ctx, admin, nil, &grace, "release unused capacity sooner"); err != nil {
		t.Fatal(err)
	}
	ended := currentBooking(t, s, a.ID)
	if ended.State != "EXPIRED" || !strings.Contains(ended.Reason, "inactivity") {
		t.Fatal("shorter policy did not expire idle booking", ended)
	}
	p, err := s.Profile(ctx, u)
	if err != nil || p.ActiveBookings != 1 || p.MaxBookings != 3 || p.PrimarySession.ID != b.ID || p.PrimarySession.LastActivityAt != nil || p.PrimarySession.ExpiresAt.Sub(b.CreatedAt) != grace {
		t.Fatal("policy changed override, counts, promotion or activity", p, err)
	}
	if _, err = s.VerifyPAT(ctx, secret); err != nil {
		t.Fatal("inactivity revoked reusable PAT", err)
	}
	rows, err := s.PATs(ctx, u, false)
	if err != nil || len(rows) != 1 || !rows[0].ExpiresAt.Equal(pat.ExpiresAt) || rows[0].RevokedAt != nil {
		t.Fatal("inactivity changed PAT lifetime", err)
	}
	grace = 2 * time.Hour
	if err = s.UpdateReservationPolicy(ctx, admin, nil, &grace, "longer grace for test runs"); err != nil {
		t.Fatal(err)
	}
	if currentBooking(t, s, a.ID).State != "EXPIRED" {
		t.Fatal("policy increase revived expired booking")
	}
	// Independent partial policy patches must not overwrite one another.
	max, grace := 4, 7*time.Hour
	var wg sync.WaitGroup
	errorsCh := make(chan error, 2)
	for _, edit := range []func() error{
		func() error { return s.UpdateReservationPolicy(ctx, admin, &max, nil, "more default bookings") },
		func() error { return s.UpdateReservationPolicy(ctx, admin, nil, &grace, "more inactivity grace") },
	} {
		wg.Add(1)
		go func(edit func() error) { defer wg.Done(); errorsCh <- edit() }(edit)
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	settings, err := s.Settings(ctx, admin)
	if err != nil || settings.DefaultMaxBookings != max || settings.InactivityGracePeriod != grace.String() {
		t.Fatal("partial settings edit lost concurrent change", settings, err)
	}
	c, _, err := s.Book(ctx, u, model.Booking{Cluster: "c"}, "c")
	if err != nil || c.ExpiresAt.Sub(c.CreatedAt) != grace {
		t.Fatal("future booking did not inherit updated grace", err)
	}
	var audits int
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='inactivity_grace_period' AND actor=$1 AND detail LIKE '%reason:%'", admin.Key()).Scan(&audits); err != nil || audits != 3 {
		t.Fatal("policy changes lack audited reasons", audits, err)
	}
}

func TestInactivityPolicyRejectsInvalidAndUnauditedChanges(t *testing.T) {
	s, _ := testutil.Database(t)
	admin := adminIdentity()
	valid := time.Hour
	if err := s.UpdateReservationPolicy(ctx, identity("alice"), nil, &valid, "denied"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("developer changed inactivity policy", err)
	}
	for _, grace := range []time.Duration{0, time.Minute - time.Second, 168*time.Hour + time.Second, time.Minute + time.Millisecond} {
		if err := s.UpdateReservationPolicy(ctx, admin, nil, &grace, "invalid"); !errors.Is(err, store.ErrConflict) {
			t.Fatal("invalid grace accepted", grace, err)
		}
	}
	for _, reason := range []string{"", "  ", strings.Repeat("x", 1001)} {
		if err := s.UpdateReservationPolicy(ctx, admin, nil, &valid, reason); !errors.Is(err, store.ErrConflict) {
			t.Fatal("missing or invalid audit reason accepted", err)
		}
	}
	if err := s.UpdateReservationPolicy(ctx, admin, nil, nil, "empty patch"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("empty policy edit accepted", err)
	}
	for _, grace := range []time.Duration{time.Minute, 168 * time.Hour} {
		if err := s.UpdateReservationPolicy(ctx, admin, nil, &grace, "supported boundary"); err != nil {
			t.Fatal("supported grace boundary rejected", grace, err)
		}
	}
}

func TestConcurrentActivityAndExpiryNeverResurrects(t *testing.T) {
	s, dsn := testutil.Database(t)
	register(t, s, "a")
	other, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Pool.Close()
	u := identity("alice")
	for round := range 10 {
		for _, elapsed := range []bool{false, true} {
			booking, _, err := s.Book(ctx, u, model.Booking{}, fmt.Sprintf("%d/%t", round, elapsed))
			if err != nil {
				t.Fatal(err)
			}
			_, version, err := s.Primary(ctx, u)
			if err != nil {
				t.Fatal(err)
			}
			if elapsed {
				ageBooking(t, s, booking.ID, 5*time.Hour)
			}
			var wg sync.WaitGroup
			failures := make(chan error, 20)
			for i := range 10 {
				wg.Add(2)
				go func() { defer wg.Done(); failures <- s.Expire(ctx) }()
				go func(i int) {
					defer wg.Done()
					db := s
					if i%2 == 0 {
						db = other
					}
					_, err := db.RecordPrimaryActivity(ctx, u, booking.ID, version)
					if elapsed && errors.Is(err, store.ErrConflict) {
						err = nil
					} else if elapsed && err == nil {
						err = errors.New("elapsed booking accepted activity")
					}
					failures <- err
				}(i)
			}
			wg.Wait()
			close(failures)
			for err := range failures {
				if err != nil {
					t.Fatal(err)
				}
			}
			after := currentBooking(t, s, booking.ID)
			if elapsed && after.State != "EXPIRED" || !elapsed && (after.State != "ACTIVE" || after.LastActivityAt == nil) {
				t.Fatal("concurrent activity/expiry corrupted reservation", after)
			}
			if err = s.Stop(ctx, u, booking.ID, "round complete", false); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestInactivityMigrationAndRestartPreserveBaseline(t *testing.T) {
	s, dsn := testutil.Database(t)
	register(t, s, "a")
	u := identity("alice")
	a, _, err := s.Book(ctx, u, model.Booking{}, "a")
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := s.CreatePAT(ctx, u, "existing PAT", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Pool.Exec(ctx, `ALTER TABLE sessions DROP CONSTRAINT active_inactivity_deadline;
 DELETE FROM schema_version WHERE version=6;
 UPDATE sessions SET created_at=clock_timestamp()-interval '2d',last_activity_at=clock_timestamp()-interval '1d',idle_anchor_at=NULL,expires_at=NULL;
 UPDATE application_settings SET inactivity_grace_seconds=1200`)
	if err != nil {
		t.Fatal(err)
	}
	var historical time.Time
	if err = s.Pool.QueryRow(ctx, "SELECT last_activity_at FROM sessions WHERE id=$1", a.ID).Scan(&historical); err != nil {
		t.Fatal(err)
	}
	restarted, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Pool.Close()
	after := currentBooking(t, restarted, a.ID)
	if after.State != "ACTIVE" || !after.LastActivityAt.Equal(historical) || time.Until(*after.ExpiresAt) < 19*time.Minute || time.Until(*after.ExpiresAt) > 20*time.Minute {
		t.Fatal("upgrade failed to preserve historical activity and give full grace", after)
	}
	var anchor time.Time
	if err = s.Pool.QueryRow(ctx, "SELECT idle_anchor_at FROM sessions WHERE id=$1", a.ID).Scan(&anchor); err != nil {
		t.Fatal(err)
	}
	if _, err = s.VerifyPAT(ctx, secret); err != nil {
		t.Fatal("inactivity upgrade revoked PAT", err)
	}
	second, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Pool.Close()
	unchanged := currentBooking(t, second, a.ID)
	var again time.Time
	if err = s.Pool.QueryRow(ctx, "SELECT idle_anchor_at FROM sessions WHERE id=$1", a.ID).Scan(&again); err != nil || !again.Equal(anchor) || !unchanged.ExpiresAt.Equal(*after.ExpiresAt) {
		t.Fatal("restart reset inactivity baseline/deadline", err)
	}
	// Policy changes anchor to the upgrade baseline, not an old historical read.
	grace := 30 * time.Minute
	if err = s.UpdateReservationPolicy(ctx, adminIdentity(), nil, &grace, "new inactivity policy"); err != nil {
		t.Fatal(err)
	}
	updated := currentBooking(t, s, a.ID)
	if updated.State != "ACTIVE" || updated.ExpiresAt.Sub(anchor) != grace || !updated.LastActivityAt.Equal(historical) {
		t.Fatal("updated grace ignored upgrade baseline", updated)
	}
}
