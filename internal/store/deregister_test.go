package store_test

import (
	"encoding/json"
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

func TestDeregisterRequiresAdminReasonAndKnownCluster(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	if err := s.Deregister(ctx, identity("alice"), "a", "unauthorized"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("developer deregistered cluster", err)
	}
	for _, reason := range []string{"", "  \n\t", strings.Repeat("x", 1001)} {
		if err := s.Deregister(ctx, adminIdentity(), "a", reason); !errors.Is(err, store.ErrConflict) {
			t.Fatal("invalid audit reason accepted", err)
		}
	}
	if err := s.Deregister(ctx, adminIdentity(), "missing", "unknown"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unknown deregistration should return not found", err)
	}
	clusters, _, err := s.Snapshot(ctx)
	if err != nil || len(clusters) != 1 || !clusters[0].Available {
		t.Fatal("rejected requests changed cluster", clusters, err)
	}
}

func TestDeregisterRetainsHistoryAndPATButErasesCredentials(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	register(t, s, "b")
	alice, bob, admin := identity("alice"), identity("bob"), adminIdentity()
	a, _, err := s.Book(ctx, alice, model.Booking{Cluster: "a"}, "original-booking")
	if err != nil {
		t.Fatal(err)
	}
	pat, secret, err := s.CreatePAT(ctx, alice, "personal", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Deregister(ctx, admin, "a", "while exclusive"); !errors.Is(err, store.ErrConflict) || !strings.Contains(err.Error(), "release all bookings") {
		t.Fatal("deregistered occupied exclusive cluster", err)
	}
	if err = s.Share(ctx, alice, a.ID, true); err != nil {
		t.Fatal(err)
	}
	b, _, err := s.Book(ctx, bob, model.Booking{Cluster: "a"}, "shared-booking")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Deregister(ctx, admin, "a", "while shared"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("deregistered occupied shared cluster", err)
	}
	if err = s.Stop(ctx, alice, a.ID, "finished", false); err != nil {
		t.Fatal(err)
	}
	if err = s.Deregister(ctx, admin, "a", "participant remains"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("deregistration ignored another active participant", err)
	}
	if err = s.Stop(ctx, bob, b.ID, "finished", false); err != nil {
		t.Fatal(err)
	}
	const reason = "Retire obsolete team environment"
	if err = s.Deregister(ctx, admin, "a", "  "+reason+"  "); err != nil {
		t.Fatal(err)
	}
	if err = s.Deregister(ctx, admin, "a", "idempotent retry"); err != nil {
		t.Fatal(err)
	}
	clusters, sessions, err := s.Snapshot(ctx)
	if err != nil || len(clusters) != 1 || clusters[0].ID != "b" || len(sessions) != 2 {
		t.Fatal("deregistration lost history or another cluster", clusters, sessions, err)
	}
	for _, session := range sessions {
		if session.Cluster != "a" || session.State != "RELEASED" || session.EndedAt == nil {
			t.Fatal("historical booking changed", session)
		}
	}
	metadata, err := s.Cluster(ctx, "a")
	if err != nil || metadata.DeregisteredAt == nil || metadata.Name != "a" || metadata.Available || !metadata.Maintenance || metadata.Shareable || metadata.ControllerSession != "" || len(metadata.Participants) != 0 {
		t.Fatal("archived public metadata is incorrect", metadata, err)
	}
	public, err := json.Marshal(metadata)
	if err != nil || strings.Contains(string(public), "encrypted-placeholder") || strings.Contains(string(public), "kubeconfig") {
		t.Fatal("metadata exposed original credentials", err)
	}
	var erased bool
	if err = s.Pool.QueryRow(ctx, "SELECT kubeconfig_ciphertext IS NULL FROM clusters WHERE id='a'").Scan(&erased); err != nil || !erased {
		t.Fatal("stored credentials were retained", err)
	}
	if _, err = s.VerifyPAT(ctx, secret); err != nil {
		t.Fatal("deregistration revoked personal credentials", err)
	}
	pats, err := s.PATs(ctx, alice, false)
	if err != nil || len(pats) != 1 || !pats[0].ExpiresAt.Equal(pat.ExpiresAt) || pats[0].RevokedAt != nil {
		t.Fatal("deregistration changed PAT lifetime", err)
	}
	if _, _, err = s.Config(ctx, alice, a.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatal("historical session obtained credentials", err)
	}
	if err = s.Maintain(ctx, admin, "a", false, "cannot reactivate"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("maintenance revived retired cluster", err)
	}
	retry, created, err := s.Book(ctx, alice, model.Booking{Cluster: "a"}, "original-booking")
	if err != nil || created || retry.ID != a.ID || retry.State != "RELEASED" {
		t.Fatal("old idempotency key allocated instead of preserving history", retry, created, err)
	}
	if _, _, err = s.Book(ctx, alice, model.Booking{Cluster: "a"}, "new-booking"); !errors.Is(err, scheduler.ErrUnavailable) {
		t.Fatal("retired cluster remained bookable", err)
	}
	var count int
	var actor, detail string
	if err = s.Pool.QueryRow(ctx, "SELECT count(*),min(actor),min(detail) FROM audit WHERE action='deregister' AND object_id='a'").Scan(&count, &actor, &detail); err != nil || count != 1 || actor != admin.Key() || !strings.HasSuffix(detail, "reason: "+reason) {
		t.Fatal("deregistration audit missing reason or duplicated", count, actor, detail, err)
	}
	// The immutable archived ID cannot be redirected to a different cluster.
	if err = s.Register(ctx, admin, model.Cluster{ID: "a", Name: "replacement", MaxParticipants: 2}, []byte("new-encrypted-placeholder")); err == nil {
		t.Fatal("retired ID was reused")
	}
	// Display names are not identity keys and can be reused after retirement.
	if err = s.Register(ctx, admin, model.Cluster{ID: "replacement", Name: "a", MaxParticipants: 2}, []byte("new-encrypted-placeholder")); err != nil {
		t.Fatal("retired display name could not be reused", err)
	}
	if _, err = s.Pool.Exec(ctx, "UPDATE clusters SET kubeconfig_ciphertext='forbidden'::bytea WHERE id='a'"); err == nil {
		t.Fatal("database permitted credentials on an archived cluster")
	}
}

func TestDeregisterExpiresElapsedBookingsWithoutEviction(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	u := identity("alice")
	booking, _, err := s.Book(ctx, u, model.Booking{Cluster: "a"}, "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Pool.Exec(ctx, "UPDATE sessions SET expires_at=clock_timestamp()-interval '1s' WHERE id=$1", booking.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.Deregister(ctx, adminIdentity(), "a", "inactive environment retired"); err != nil {
		t.Fatal(err)
	}
	ended := currentBooking(t, s, booking.ID)
	profile, err := s.Profile(ctx, u)
	if ended.State != "EXPIRED" || profile.ActiveBookings != 0 || profile.PrimarySession != nil || err != nil {
		t.Fatal("elapsed booking or primary was not repaired", ended, profile, err)
	}
}

func TestConcurrentBookAndDeregisterAcrossStores(t *testing.T) {
	s, dsn := testutil.Database(t)
	other, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Pool.Close()
	for i := range 12 {
		id := fmt.Sprintf("cluster-%02d", i)
		register(t, s, id)
		start := make(chan struct{})
		var booking model.Session
		var bookErr, deregisterErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			booking, _, bookErr = s.Book(ctx, identity(id), model.Booking{Cluster: id}, id)
		}()
		go func() {
			defer wg.Done()
			<-start
			deregisterErr = other.Deregister(ctx, adminIdentity(), id, "concurrent retirement")
		}()
		close(start)
		wg.Wait()
		if bookErr == nil && deregisterErr == nil {
			t.Fatal("booking and deregistration both succeeded")
		}
		if bookErr == nil {
			if !errors.Is(deregisterErr, store.ErrConflict) {
				t.Fatal("occupied cluster was not safely rejected", deregisterErr)
			}
			if err = s.Stop(ctx, identity(id), booking.ID, "round complete", false); err != nil {
				t.Fatal(err)
			}
		} else if deregisterErr != nil || !errors.Is(bookErr, scheduler.ErrUnavailable) {
			t.Fatal("unexpected concurrent outcome", bookErr, deregisterErr)
		}
	}
	var invalid int
	if err = s.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions s JOIN clusters c ON c.id=s.cluster_id
 WHERE s.state='ACTIVE' AND c.deregistered_at IS NOT NULL`).Scan(&invalid); err != nil || invalid != 0 {
		t.Fatal("archived cluster acquired an active reservation", invalid, err)
	}
}

func TestDeregistrationMigrationAndRestartPreserveState(t *testing.T) {
	s, dsn := testutil.Database(t)
	register(t, s, "a")
	u := identity("alice")
	booking, _, err := s.Book(ctx, u, model.Booking{Cluster: "a"}, "before-upgrade")
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the pre007 constraints on this disposable schema, then execute
	// the actual startup migration with an existing reservation and credential.
	_, err = s.Pool.Exec(ctx, `ALTER TABLE clusters DROP CONSTRAINT cluster_registration_credentials;
 DROP INDEX live_cluster_names;
 ALTER TABLE clusters DROP COLUMN deregistered_at;
 ALTER TABLE clusters ALTER COLUMN kubeconfig_ciphertext SET NOT NULL;
 ALTER TABLE clusters ADD CONSTRAINT clusters_name_key UNIQUE(name);
 DELETE FROM schema_version WHERE version=7`)
	if err != nil {
		t.Fatal(err)
	}
	upgraded, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Pool.Close()
	after := currentBooking(t, upgraded, booking.ID)
	if after.State != "ACTIVE" || !after.ExpiresAt.Equal(*booking.ExpiresAt) {
		t.Fatal("migration changed reservation or inactivity deadline", after)
	}
	metadata, err := upgraded.Cluster(ctx, "a")
	if err != nil || metadata.DeregisteredAt != nil || metadata.ControllerSession != booking.ID {
		t.Fatal("migration changed registry metadata", metadata, err)
	}
	if _, ciphertext, err := upgraded.Config(ctx, u, booking.ID); err != nil || string(ciphertext) != "encrypted-placeholder" {
		t.Fatal("migration changed existing credentials", err)
	}
	if err = upgraded.Stop(ctx, u, booking.ID, "done", false); err != nil {
		t.Fatal(err)
	}
	if err = upgraded.Deregister(ctx, adminIdentity(), "a", "retired after upgrade"); err != nil {
		t.Fatal(err)
	}
	archived, err := upgraded.Cluster(ctx, "a")
	if err != nil || archived.DeregisteredAt == nil {
		t.Fatal(err)
	}
	restarted, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Pool.Close()
	stable, err := restarted.Cluster(ctx, "a")
	if err != nil || stable.DeregisteredAt == nil || !stable.DeregisteredAt.Equal(*archived.DeregisteredAt) {
		t.Fatal("restart reset archived identity", err)
	}
	clusters, sessions, err := restarted.Snapshot(ctx)
	if err != nil || len(clusters) != 0 || len(sessions) != 1 || sessions[0].ID != booking.ID || sessions[0].State != "RELEASED" {
		t.Fatal("restart revived retired cluster or lost history", clusters, sessions, err)
	}
	var erased bool
	if err = restarted.Pool.QueryRow(ctx, "SELECT kubeconfig_ciphertext IS NULL FROM clusters WHERE id='a'").Scan(&erased); err != nil || !erased {
		t.Fatal("restart restored erased credential", err)
	}
}
