package health

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
)

type publication struct {
	claim  store.HealthClaim
	result model.HealthResult
	delay  time.Duration
}
type fixtureQueue struct {
	mu           sync.Mutex
	claims       []store.HealthClaim
	publications chan publication
}

func (q *fixtureQueue) ClaimHealthChecks(ctx context.Context, limit int) ([]store.HealthClaim, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(q.claims) < limit {
		limit = len(q.claims)
	}
	claims := append([]store.HealthClaim(nil), q.claims[:limit]...)
	q.claims = q.claims[limit:]
	return claims, nil
}
func (q *fixtureQueue) PublishHealthCheck(ctx context.Context, claim store.HealthClaim, result model.HealthResult, delay time.Duration) (bool, error) {
	select {
	case q.publications <- publication{claim, result, delay}:
		return true, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}
func fixtureVault(t *testing.T) *kube.Vault {
	t.Helper()
	v, err := kube.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func encryptedClaim(t *testing.T, vault *kube.Vault, id string, raw []byte) store.HealthClaim {
	t.Helper()
	cipher, err := vault.Seal(id, raw)
	if err != nil {
		t.Fatal(err)
	}
	return store.HealthClaim{ClusterID: id, Token: "test-lease", Sequence: 1, Profile: model.HealthProfileAPIReady, Ciphertext: cipher, StartedAt: time.Now(), LeaseUntil: time.Now().Add(model.HealthLeaseDuration)}
}
func startWorker(t *testing.T, w *Worker) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("worker did not stop")
		}
	})
	return cancel, done
}

func TestWorkerPublishesProbesAndVaultFailures(t *testing.T) {
	_, raw, _, _ := probeFixture(t, true, nil)
	vault := fixtureVault(t)
	bad := encryptedClaim(t, vault, "invalid", raw)
	bad.Ciphertext = []byte("invalid encrypted material")
	q := &fixtureQueue{claims: []store.HealthClaim{encryptedClaim(t, vault, "valid", raw), bad}, publications: make(chan publication, 2)}
	w := &Worker{Store: q, Vault: vault, PollInterval: 10 * time.Millisecond}
	cancel, _ := startWorker(t, w)
	defer cancel()
	seen := map[string]bool{}
	for range 2 {
		select {
		case p := <-q.publications:
			seen[p.claim.ClusterID] = true
			if p.delay < 24*time.Second || p.delay > 36*time.Second {
				t.Fatal("default scheduling jitter invalid", p.delay)
			}
			if p.claim.ClusterID == "valid" && (!p.result.Passed || p.result.ReasonCode != "checks_passed") {
				t.Fatal(p.result)
			}
			if p.claim.ClusterID == "invalid" && (p.result.Passed || p.result.ReasonCode != "credentials_unavailable") {
				t.Fatal(p.result)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("health results not published")
		}
	}
	if len(seen) != 2 {
		t.Fatal("claim lost", seen)
	}
}

func TestWorkerCancellationDoesNotPublishFailure(t *testing.T) {
	started, closed := make(chan struct{}), make(chan struct{})
	_, raw, _, _ := probeFixture(t, true, func(_ http.ResponseWriter, r *http.Request) bool {
		close(started)
		<-r.Context().Done()
		close(closed)
		return true
	})
	vault := fixtureVault(t)
	q := &fixtureQueue{claims: []store.HealthClaim{encryptedClaim(t, vault, "cancel", raw)}, publications: make(chan publication, 1)}
	w := &Worker{Store: q, Vault: vault, PollInterval: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("probe never started")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not cancel the upstream request")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("upstream connection was not closed")
	}
	select {
	case p := <-q.publications:
		t.Fatal("shutdown generated a false observation", p.result)
	default:
	}
}

func TestWorkerBoundsConcurrencyAndHonorsBackoff(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{}, 8)
	var active, maximum atomic.Int32
	_, raw, _, _ := probeFixture(t, true, func(_ http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/version" {
			return false
		}
		count := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); count > old; old = maximum.Load() {
			if maximum.CompareAndSwap(old, count) {
				break
			}
		}
		started <- struct{}{}
		select {
		case <-gate:
			return false
		case <-r.Context().Done():
			return true
		}
	})
	vault := fixtureVault(t)
	q := &fixtureQueue{publications: make(chan publication, 8)}
	for i := range 8 {
		q.claims = append(q.claims, encryptedClaim(t, vault, fmt.Sprintf("cluster-%d", i), raw))
	}
	cancel, _ := startWorker(t, &Worker{Store: q, Vault: vault, PollInterval: 10 * time.Millisecond})
	defer cancel()
	for range 4 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("initial batch not started")
		}
	}
	select {
	case <-started:
		t.Fatal("more than four clusters probed concurrently")
	case <-time.After(30 * time.Millisecond):
	}
	close(gate)
	for range 8 {
		select {
		case <-q.publications:
		case <-time.After(3 * time.Second):
			t.Fatal("queued cluster did not finish")
		}
	}
	if maximum.Load() > 4 {
		t.Fatal("concurrency cap exceeded", maximum.Load())
	}
	cancel()

	_, limited, _, _ := probeFixture(t, true, func(w http.ResponseWriter, _ *http.Request) bool {
		w.Header().Set("Retry-After", "600")
		w.WriteHeader(429)
		return true
	})
	q2 := &fixtureQueue{claims: []store.HealthClaim{encryptedClaim(t, vault, "limited", limited)}, publications: make(chan publication, 1)}
	cancel2, _ := startWorker(t, &Worker{Store: q2, Vault: vault, PollInterval: 10 * time.Millisecond})
	defer cancel2()
	select {
	case got := <-q2.publications:
		if got.delay != 5*time.Minute || got.result.ReasonCode != "rate_limited" {
			t.Fatal(got.delay, got.result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("rate limit not published")
	}
}

func TestWorkerWithPostgresPreservesReservationsAndActivity(t *testing.T) {
	db, _ := testutil.Database(t)
	_, raw, paths, mu := probeFixture(t, true, nil)
	vault := fixtureVault(t)
	admin := model.Identity{Issuer: "https://identity.example.test", Subject: "admin", Admin: true}
	alice := model.Identity{Issuer: admin.Issuer, Subject: "alice", Name: "alice"}
	cipher, err := vault.Seal("cluster", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Register(t.Context(), admin, model.Cluster{ID: "cluster", Name: "Fixture", MaxParticipants: 2}, cipher); err != nil {
		t.Fatal(err)
	}
	testutil.MarkHealthy(t, db, "cluster")
	session, _, err := db.Book(t.Context(), alice, model.Booking{Cluster: "cluster"}, "worker-booking")
	if err != nil {
		t.Fatal(err)
	}
	pat, _, err := db.CreatePAT(t.Context(), alice, "fixture credential", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// The health worker must not run expiry housekeeping either. The regular
	// backend expiry worker is deliberately absent in this isolated schema.
	if _, err = db.Pool.Exec(t.Context(), "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", session.ID); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		var value string
		err := db.Pool.QueryRow(t.Context(), `SELECT json_build_object('session_state',s.state,'activity',s.last_activity_at,'deadline',s.expires_at,'primary',d.primary_session_id,'version',d.selection_version,'pat_used',p.last_used_at,'pat_expiry',p.expires_at)::text FROM sessions s JOIN developers d ON d.owner_id=s.owner_id JOIN personal_access_tokens p ON p.id=$2 WHERE s.id=$1`, session.ID, pat.ID).Scan(&value)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	if _, err = db.Pool.Exec(t.Context(), "UPDATE cluster_health SET observed_state='UNKNOWN',checked_at=NULL,consecutive_successes=0,next_check_at=clock_timestamp() WHERE cluster_id='cluster'"); err != nil {
		t.Fatal(err)
	}
	w := NewWorker(db, vault)
	w.PollInterval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("worker failed to stop")
		}
	}()
	deadline := time.Now().Add(4 * time.Second)
	advanced := false
	for {
		h, err := db.GetHealth(t.Context(), "cluster")
		if err != nil {
			t.Fatal(err)
		}
		if h.State == "RECOVERING" && !advanced {
			if _, err = db.Pool.Exec(t.Context(), "UPDATE cluster_health SET next_check_at=clock_timestamp() WHERE cluster_id='cluster'"); err != nil {
				t.Fatal(err)
			}
			advanced = true
		}
		if h.State == "PASSING" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real worker never published healthy observation", h)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if after := snapshot(); after != before {
		t.Fatal("health polling changed reservation or credential activity", before, after)
	}
	var gatewayAudits int
	if err = db.Pool.QueryRow(t.Context(), "SELECT count(*) FROM audit WHERE action IN ('gateway','expire','primary_select')").Scan(&gatewayAudits); err != nil || gatewayAudits != 0 {
		t.Fatal("health entered developer gateway/expiry paths", gatewayAudits, err)
	}
	mu.Lock()
	count := len(*paths)
	mu.Unlock()
	if count != 8 {
		t.Fatal("expected two complete fixed GET cycles", count)
	}
}
