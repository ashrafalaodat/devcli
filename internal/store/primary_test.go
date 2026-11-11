package store_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
)

func adminIdentity() model.Identity { u := identity("admin"); u.Admin = true; return u }
func allowBookings(t *testing.T, s *store.Store, u model.Identity, n int) {
	t.Helper()
	if err := s.ObserveIdentity(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateDeveloperLimit(ctx, adminIdentity(), u.Key(), &n, "integration test permission"); err != nil {
		t.Fatal(err)
	}
}

func TestPrimarySelectionLimitsAndSafePromotion(t *testing.T) {
	s, _ := testutil.Database(t)
	for _, id := range []string{"a", "b", "c"} {
		register(t, s, id)
	}
	u := identity("alice")
	p, err := s.Profile(ctx, u)
	if err != nil || p.MaxBookings != 1 || p.ActiveBookings != 0 || p.PrimarySession != nil {
		t.Fatal("default profile invalid", p, err)
	}
	a, _, err := s.Book(ctx, u, model.Booking{Cluster: "a"}, "a")
	if err != nil || !a.Primary {
		t.Fatal("first booking not primary", err)
	}
	if _, _, err = s.Book(ctx, u, model.Booking{Cluster: "b"}, "b"); !errors.Is(err, store.ErrBookingLimit) {
		t.Fatal("default limit ignored", err)
	}
	if again, created, err := s.Book(ctx, u, model.Booking{Cluster: "a"}, "a"); err != nil || created || again.ID != a.ID {
		t.Fatal("idempotent retry blocked by limit", err)
	}
	allowBookings(t, s, u, 2)
	b, _, err := s.Book(ctx, u, model.Booking{Cluster: "b"}, "b")
	if err != nil || b.Primary {
		t.Fatal("additional booking changed primary", err)
	}
	p, err = s.SelectPrimary(ctx, u, "b")
	if err != nil || p.PrimarySession.ID != b.ID {
		t.Fatal("cluster switch failed", err)
	}
	version := p.SelectionVersion
	same, err := s.SelectPrimary(ctx, u, b.ID)
	if err != nil || same.SelectionVersion != version {
		t.Fatal("same selection changed version", err)
	}
	if err = s.CheckPrimaryAccess(ctx, u, a.ID, version-1); err == nil {
		t.Fatal("old selection still authorized")
	}
	if _, err = s.SelectPrimary(ctx, identity("bob"), b.ID); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("foreign primary selected", err)
	}
	if err = s.UpdateDeveloperLimit(ctx, adminIdentity(), u.Key(), new(int), "zero limit"); err == nil {
		t.Fatal("zero limit accepted")
	}
	one := 1
	if err = s.UpdateDeveloperLimit(ctx, adminIdentity(), u.Key(), &one, "reduce future holds"); err != nil {
		t.Fatal(err)
	}
	p, err = s.Profile(ctx, u)
	if err != nil || p.ActiveBookings != 2 || p.MaxBookings != 1 || p.PrimarySession.ID != b.ID {
		t.Fatal("limit reduction evicted holder", err)
	}
	if _, _, err = s.Book(ctx, u, model.Booking{Cluster: "c"}, "c"); !errors.Is(err, store.ErrBookingLimit) {
		t.Fatal("lowered limit ignored", err)
	}
	if err = s.Stop(ctx, u, b.ID, "done", false); err != nil {
		t.Fatal(err)
	}
	p, err = s.Profile(ctx, u)
	if err != nil || p.PrimarySession.ID != a.ID || p.SelectionVersion <= version {
		t.Fatal("remaining oldest not promoted", err)
	}
	if err = s.Stop(ctx, u, a.ID, "done", false); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Primary(ctx, u); !errors.Is(err, store.ErrNoPrimary) {
		t.Fatal("no-booking error missing", err)
	}
	c, _, err := s.Book(ctx, u, model.Booking{Cluster: "c"}, "c")
	if err != nil || !c.Primary {
		t.Fatal("new first booking not primary", err)
	}
	if _, err = s.Pool.Exec(ctx, "UPDATE sessions SET expires_at=clock_timestamp()-interval '1s' WHERE id=$1", c.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.Expire(ctx); err != nil {
		t.Fatal(err)
	}
	p, err = s.Profile(ctx, u)
	if err != nil || p.PrimarySession != nil || p.ActiveBookings != 0 {
		t.Fatal("expiry did not clear primary", err)
	}
}

func TestConcurrentDeveloperLimitAcrossStoreInstances(t *testing.T) {
	s, dsn := testutil.Database(t)
	for i := 0; i < 12; i++ {
		register(t, s, fmt.Sprintf("c%02d", i))
	}
	other, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Pool.Close()
	u := identity("alice")
	allowBookings(t, s, u, 3)
	var wg sync.WaitGroup
	results := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			db := s
			if i%2 == 1 {
				db = other
			}
			_, _, err := db.Book(ctx, u, model.Booking{}, fmt.Sprint(i))
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	count := 0
	for err := range results {
		if err == nil {
			count++
		} else if !errors.Is(err, store.ErrBookingLimit) {
			t.Fatal("unexpected booking failure", err)
		}
	}
	p, err := s.Profile(ctx, u)
	if err != nil || count != 3 || p.ActiveBookings != 3 || p.PrimarySession == nil {
		t.Fatal("concurrent limit exceeded", count, p, err)
	}
	_, sessions, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	primaryCount := 0
	for _, v := range sessions {
		if v.Primary {
			primaryCount++
		}
	}
	if primaryCount != 1 {
		t.Fatal("more than one primary", primaryCount)
	}
}

func TestGlobalAndIndividualPolicyAuthorization(t *testing.T) {
	s, _ := testutil.Database(t)
	alice, admin := identity("alice"), adminIdentity()
	if err := s.ObserveIdentity(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSettings(ctx, alice, 2, "not allowed"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("developer changed defaults", err)
	}
	if _, err := s.Settings(ctx, alice); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("developer read admin settings", err)
	}
	if _, err := s.Developers(ctx, alice); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("developer listed admin policies", err)
	}
	if err := s.UpdateSettings(ctx, admin, 3, ""); err == nil {
		t.Fatal("reason not required")
	}
	if err := s.UpdateSettings(ctx, admin, 3, "team policy"); err != nil {
		t.Fatal(err)
	}
	p, err := s.Profile(ctx, alice)
	if err != nil || p.MaxBookings != 3 {
		t.Fatal("default not inherited", err)
	}
	two := 2
	if err = s.UpdateDeveloperLimit(ctx, admin, alice.Key(), &two, "per developer"); err != nil {
		t.Fatal(err)
	}
	p, err = s.Profile(ctx, alice)
	if err != nil || p.MaxBookings != 2 || p.MaxBookingsOverride == nil {
		t.Fatal("override not applied", err)
	}
	if err = s.UpdateDeveloperLimit(ctx, admin, alice.Key(), nil, "inherit policy"); err != nil {
		t.Fatal(err)
	}
	p, err = s.Profile(ctx, alice)
	if err != nil || p.MaxBookings != 3 || p.MaxBookingsOverride != nil {
		t.Fatal("override not reset", err)
	}
	users, err := s.Developers(ctx, admin)
	if err != nil || len(users) != 1 || users[0].OwnerID != alice.Key() {
		t.Fatal("developer listing incorrect", err)
	}
}

func TestPrimaryAuthorizationLeaseAndActivity(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	register(t, s, "b")
	u := identity("alice")
	u.TokenExpiresAt = time.Now().UTC().Add(30 * time.Minute).Truncate(time.Microsecond)
	allowBookings(t, s, u, 2)
	a, _, err := s.Book(ctx, u, model.Booking{Cluster: "a"}, "a")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := s.Book(ctx, u, model.Booking{Cluster: "b"}, "b")
	if err != nil {
		t.Fatal(err)
	}
	read, err := s.PrimaryAccess(ctx, u)
	if err != nil || !read.AuthorizationExpiresAt.IsZero() {
		t.Fatal("read authorized gateway", err)
	}
	if err = s.CheckGatewayAuthorization(ctx, u, a.ID, read.SelectionVersion); !errors.Is(err, store.ErrConflict) {
		t.Fatal("empty lease did not fail closed with conflict", err)
	}
	authorized, err := s.AuthorizePrimary(ctx, u)
	if err != nil || !authorized.AuthorizationExpiresAt.Equal(u.TokenExpiresAt) {
		t.Fatal("JWT expiry not respected", err)
	}
	if _, err = s.HeartbeatPrimary(ctx, u); !errors.Is(err, store.ErrConflict) {
		t.Fatal("heartbeat without activity accepted", err)
	}
	if _, err = s.RecordPrimaryActivity(ctx, u, a.ID, authorized.SelectionVersion); err != nil {
		t.Fatal(err)
	}
	fresh := u
	fresh.TokenExpiresAt = time.Now().UTC().Add(8 * time.Hour)
	heartbeat, err := s.HeartbeatPrimary(ctx, fresh)
	if err != nil || !heartbeat.AuthorizationExpiresAt.Equal(fresh.TokenExpiresAt) {
		t.Fatal("moving inactivity deadline incorrectly capped verified JWT lifetime", err)
	}
	activity := *heartbeat.Session.LastActivityAt
	again, err := s.HeartbeatPrimary(ctx, fresh)
	if err != nil || !again.Session.LastActivityAt.Equal(activity) {
		t.Fatal("heartbeat counted as activity", err)
	}
	if err = s.CheckGatewayAuthorization(ctx, u, a.ID, authorized.SelectionVersion); err != nil {
		t.Fatal("lease invalid", err)
	}
	if _, err = s.SelectPrimary(ctx, u, b.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.CheckGatewayAuthorization(ctx, u, a.ID, authorized.SelectionVersion); !errors.Is(err, store.ErrConflict) {
		t.Fatal("switch did not revoke lease", err)
	}
	newAccess, err := s.PrimaryAccess(ctx, u)
	if err != nil || !newAccess.AuthorizationExpiresAt.IsZero() {
		t.Fatal("old lease transferred to new cluster", err)
	}
	if _, err = s.HeartbeatPrimary(ctx, fresh); err != nil {
		t.Fatal("explicit primary selection did not count user activity", err)
	}
	if _, err = s.AuthorizePrimary(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SelectPrimary(ctx, u, a.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.CheckPrimaryAccess(ctx, u, a.ID, authorized.SelectionVersion); !errors.Is(err, store.ErrConflict) {
		t.Fatal("switch away/back resurrected stream", err)
	}
	u.TokenExpiresAt = time.Now().Add(-time.Second)
	if _, err = s.AuthorizePrimary(ctx, u); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("expired JWT authorized lease", err)
	}
}

func TestNoPrimaryResponseCommitsExpiry(t *testing.T) {
	for _, method := range []string{"primary", "configuration", "access"} {
		t.Run(method, func(t *testing.T) {
			s, _ := testutil.Database(t)
			register(t, s, "a")
			u := identity("alice")
			a, _, err := s.Book(ctx, u, model.Booking{}, "a")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Pool.Exec(ctx, "UPDATE sessions SET expires_at=clock_timestamp()-interval '1s' WHERE id=$1", a.ID); err != nil {
				t.Fatal(err)
			}
			switch method {
			case "primary":
				_, _, err = s.Primary(ctx, u)
			case "configuration":
				_, _, _, _, err = s.PrimaryConfig(ctx, u)
			case "access":
				_, err = s.PrimaryAccess(ctx, u)
			}
			if !errors.Is(err, store.ErrNoPrimary) {
				t.Fatal("expected no primary", err)
			}
			var state string
			var primary *string
			if err = s.Pool.QueryRow(ctx, "SELECT s.state,d.primary_session_id FROM sessions s JOIN developers d ON d.owner_id=s.owner_id WHERE s.id=$1", a.ID).Scan(&state, &primary); err != nil || state != "EXPIRED" || primary != nil {
				t.Fatal("expected no-booking response rolled back expiry/selection cleanup", err)
			}
		})
	}
}

func TestPrimaryMigrationPreservesBookingsAndRetiresLegacyPAT(t *testing.T) {
	s, dsn := testutil.Database(t)
	register(t, s, "a")
	register(t, s, "b")
	register(t, s, "c")
	u := identity("alice")
	allowBookings(t, s, u, 2)
	a, _, err := s.Book(ctx, u, model.Booking{Cluster: "a"}, "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Book(ctx, u, model.Booking{Cluster: "b"}, "b"); err != nil {
		t.Fatal(err)
	}
	_, currentRaw, err := s.CreatePAT(ctx, u, "current", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	legacy := sha256.Sum256([]byte("legacy credential"))
	_, err = s.Pool.Exec(ctx, `INSERT INTO personal_access_tokens(id,owner_id,session_id,name,scope,token_digest,identity,created_at,expires_at)
 SELECT 'legacy',owner_id,id,'old kubeconfig','kubernetes:session',$2,identity,clock_timestamp(),clock_timestamp()+interval '1h' FROM sessions WHERE id=$1`, a.ID, legacy[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Pool.Exec(ctx, "DELETE FROM developers; DELETE FROM schema_version WHERE version=5; CREATE TABLE automatic_bindings(legacy text)"); err != nil {
		t.Fatal(err)
	}
	restarted, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Pool.Close()
	p, err := restarted.Profile(ctx, u)
	if err != nil || p.ActiveBookings != 2 || p.MaxBookings != 1 || p.PrimarySession.ID != a.ID {
		t.Fatal("migration changed holdings/oldest primary", p, err)
	}
	if _, _, err = restarted.Book(ctx, u, model.Booking{Cluster: "c"}, "c"); !errors.Is(err, store.ErrBookingLimit) {
		t.Fatal("grandfathered owner added more bookings", err)
	}
	var revoked bool
	var retired int
	if err = s.Pool.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM personal_access_tokens WHERE id='legacy'").Scan(&revoked); err != nil || !revoked {
		t.Fatal("legacy PAT not revoked", err)
	}
	if _, err = restarted.VerifyPAT(ctx, currentRaw); err != nil {
		t.Fatal("current PAT wrongly revoked", err)
	}
	second, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Pool.Close()
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='pat_retired' AND object_id='legacy'").Scan(&retired); err != nil || retired != 1 {
		t.Fatal("migration not idempotent", err)
	}
	var oldTable *string
	if err = s.Pool.QueryRow(ctx, "SELECT to_regclass('automatic_bindings')::text").Scan(&oldTable); err != nil || oldTable != nil {
		t.Fatal("legacy automatic binding table retained", err)
	}
}
