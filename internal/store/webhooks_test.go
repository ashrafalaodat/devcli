package store_test

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/scheduler"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
)

func webhookRule(t *testing.T, s *store.Store, id string, blocking bool, events ...string) store.Webhook {
	t.Helper()
	h, e := s.SaveWebhook(t.Context(), healthAdmin(), store.Webhook{ID: id, Name: id, URL: "https://pipeline.example.test/run", Events: events, Selector: map[string]string{}, Enabled: true, Blocking: blocking, Idempotent: true, TimeoutSeconds: 3600, SecretCiphertext: []byte("encrypted-placeholder")}, 0, "owned pipeline fixture")
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func webhookJobs(t *testing.T, s *store.Store) []store.WebhookDelivery {
	t.Helper()
	v, e := s.WebhookDeliveries(t.Context(), healthAdmin(), 100)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func claimWebhook(t *testing.T, s *store.Store) store.WebhookDelivery {
	t.Helper()
	v, e := s.ClaimWebhookDeliveries(t.Context(), 1)
	if e != nil || len(v) != 1 {
		t.Fatal("expected one delivery claim", e, len(v))
	}
	return v[0]
}
func TestWebhooksAuditNotificationsSnapshotAndLease(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	hook := webhookRule(t, s, "notify", false, "book", "release")
	booked, _, e := s.Book(t.Context(), identity("alice"), model.Booking{Cluster: "a"}, "same")
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Book(t.Context(), identity("alice"), model.Booking{Cluster: "a"}, "same"); e != nil {
		t.Fatal(e)
	}
	jobs := webhookJobs(t, s)
	if len(jobs) != 1 || jobs[0].EventType != "book" || jobs[0].ClusterID != "a" {
		t.Fatal("duplicate or incorrect audit notification", jobs)
	}
	var body map[string]any
	if json.Unmarshal(jobs[0].Body, &body) != nil || body["object_id"] != booked.ID || body["labels"] == nil {
		t.Fatal("event context missing")
	}
	for _, forbidden := range []string{"detail", "kubeconfig", "token", "credentials"} {
		if _, ok := body[forbidden]; ok {
			t.Fatal("unsafe payload field", forbidden)
		}
	}
	hook.URL = "https://changed.example.test/run"
	hook.SecretCiphertext = []byte("new-encrypted-secret")
	hook.Enabled = false
	if _, e = s.SaveWebhook(t.Context(), healthAdmin(), hook, hook.Version, "disable future deliveries"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.SaveWebhook(t.Context(), healthAdmin(), hook, hook.Version, "stale editor"); !errors.Is(e, store.ErrConflict) {
		t.Fatal("stale rule update accepted", e)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	claimed := []store.WebhookDelivery{}
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := s.ClaimWebhookDeliveries(t.Context(), 1)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			claimed = append(claimed, v...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(claimed) != 1 || claimed[0].URL != "https://pipeline.example.test/run" || string(claimed[0].SecretCiphertext) != "encrypted-placeholder" {
		t.Fatal("lease duplicated or rule edit retargeted work", len(claimed))
	}
	if e = s.FinishWebhookDelivery(t.Context(), claimed[0], 204, false, "accepted"); e != nil {
		t.Fatal(e)
	}
	if e = s.Stop(t.Context(), identity("alice"), booked.ID, "done", false); e != nil {
		t.Fatal(e)
	}
	if len(webhookJobs(t, s)) != 1 {
		t.Fatal("disabled rule delivered new events")
	}
	public, _ := json.Marshal(webhookJobs(t, s))
	if strings.Contains(string(public), "encrypted-placeholder") || strings.Contains(string(public), "pipeline.example.test") {
		t.Fatal("private delivery metadata exposed")
	}
}
func TestWebhooksSharedFinalReleaseAndHealthVerification(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	webhookRule(t, s, "reset", true, "cluster_idle")
	alice, _, e := s.Book(t.Context(), identity("alice"), model.Booking{Cluster: "a"}, "one")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Share(t.Context(), identity("alice"), alice.ID, true); e != nil {
		t.Fatal(e)
	}
	bob, _, e := s.Book(t.Context(), identity("bob"), model.Booking{Cluster: "a"}, "two")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Stop(t.Context(), identity("alice"), alice.ID, "owner finished", false); e != nil {
		t.Fatal(e)
	}
	if len(webhookJobs(t, s)) != 0 {
		t.Fatal("controlling holder leaving triggered reset with another participant")
	}
	if e = s.Logout(t.Context(), identity("bob")); e != nil {
		t.Fatal(e)
	}
	jobs := webhookJobs(t, s)
	if len(jobs) != 1 || jobs[0].State != "PENDING" || !jobs[0].Blocking {
		t.Fatal("last release did not create one hold")
	}
	if e = s.Stop(t.Context(), identity("bob"), bob.ID, "retry", false); e != nil || len(webhookJobs(t, s)) != 1 {
		t.Fatal("duplicate stop created another pipeline", e)
	}
	if _, _, e = s.Book(t.Context(), identity("carol"), model.Booking{Cluster: "a"}, "blocked"); !errors.Is(e, scheduler.ErrUnavailable) {
		t.Fatal("booking bypassed lifecycle hold", e)
	}
	if e = s.Deregister(t.Context(), healthAdmin(), "a", "must not discard a pending hold"); !errors.Is(e, store.ErrConflict) {
		t.Fatal("deregister discarded hold", e)
	}
	if _, e = s.CompleteWebhook(t.Context(), jobs[0].ID, true); !errors.Is(e, store.ErrConflict) {
		t.Fatal("undispatched callback accepted", e)
	}
	claim := claimWebhook(t, s)
	if e = s.Maintain(t.Context(), healthAdmin(), "a", true, "independent platform maintenance"); e != nil {
		t.Fatal(e)
	}
	// Callback may race the trigger's HTTP acknowledgement. An earlier green
	// health sample and the currently leased probe must not verify this workflow.
	oldHealth := claimHealth(t, s, "a")
	publishHealth(t, s, oldHealth, passedHealth())
	oldHealth = claimHealth(t, s, "a")
	publishHealth(t, s, oldHealth, passedHealth())
	stale := claimHealth(t, s, "a")
	if _, e = s.CompleteWebhook(t.Context(), claim.ID, true); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishWebhookDelivery(t.Context(), claim, 202, false, "accepted"); e != nil {
		t.Fatal(e)
	}
	if e = s.ReconcileWebhooks(t.Context()); e != nil {
		t.Fatal(e)
	}
	d, _ := s.GetWebhookDelivery(t.Context(), claim.ID)
	if d.State != "VERIFYING" {
		t.Fatal("old green result or late acceptance released workflow", d.State)
	}
	accepted, e := s.PublishHealthCheck(t.Context(), stale, passedHealth(), 30*time.Second)
	if e != nil || accepted {
		t.Fatal("pre-callback probe published", e)
	}
	publishHealth(t, s, claimHealth(t, s, "a"), passedHealth())
	if e = s.ReconcileWebhooks(t.Context()); e != nil {
		t.Fatal(e)
	}
	d, _ = s.GetWebhookDelivery(t.Context(), claim.ID)
	if d.State != "VERIFYING" {
		t.Fatal("single post-callback cycle satisfied recovery")
	}
	publishHealth(t, s, claimHealth(t, s, "a"), passedHealth())
	if e = s.ReconcileWebhooks(t.Context()); e != nil {
		t.Fatal(e)
	}
	d, _ = s.GetWebhookDelivery(t.Context(), claim.ID)
	if d.State != "SUCCEEDED" {
		t.Fatal("fresh health did not complete workflow", d.State)
	}
	if _, e = s.CompleteWebhook(t.Context(), claim.ID, true); e != nil {
		t.Fatal("duplicate success not idempotent", e)
	}
	c, e := s.Cluster(t.Context(), "a")
	if e != nil || c.LifecycleHolds != 0 || !c.Maintenance || c.Available {
		t.Fatal("callback changed manual maintenance", e)
	}
}
func TestWebhooksBatchExpiryAndRejectedAllocationKeepHold(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	webhookRule(t, s, "reset", true, "cluster_idle")
	a, _, e := s.Book(t.Context(), identity("a"), model.Booking{Cluster: "a"}, "a")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Share(t.Context(), identity("a"), a.ID, true); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Book(t.Context(), identity("b"), model.Booking{Cluster: "a"}, "b"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Pool.Exec(t.Context(), "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE state='ACTIVE'"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Book(t.Context(), identity("new"), model.Booking{Cluster: "a"}, "new"); !errors.Is(e, scheduler.ErrUnavailable) {
		t.Fatal("implicit expiry did not block allocation", e)
	}
	if len(webhookJobs(t, s)) != 1 {
		t.Fatal("batch expiry did not emit exactly one idle event")
	}
	_, sessions, e := s.Snapshot(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	for _, session := range sessions {
		if session.State != "EXPIRED" {
			t.Fatal("allocation rejection rolled back valid expiry")
		}
	}
}
func TestWebhooksFailureTimeoutResolveAndSerialBlocking(t *testing.T) {
	s, dsn := testutil.Database(t)
	register(t, s, "a")
	webhookRule(t, s, "first", true, "cluster_idle")
	webhookRule(t, s, "second", true, "cluster_idle")
	a, _, e := s.Book(t.Context(), identity("alice"), model.Booking{Cluster: "a"}, "one")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Stop(t.Context(), identity("alice"), a.ID, "finished", false); e != nil {
		t.Fatal(e)
	}
	first := claimWebhook(t, s)
	others, e := s.ClaimWebhookDeliveries(t.Context(), 4)
	if e != nil || len(others) != 0 {
		t.Fatal("blocking pipelines overlapped", e)
	}
	if _, e = s.Pool.Exec(t.Context(), "UPDATE webhook_deliveries SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", first.ID); e != nil {
		t.Fatal(e)
	}
	next := claimWebhook(t, s)
	if next.ID != first.ID || next.LeaseToken == first.LeaseToken {
		t.Fatal("crashed worker not recovered")
	}
	if e = s.FinishWebhookDelivery(t.Context(), first, 202, false, "accepted"); e != nil {
		t.Fatal(e)
	}
	d, _ := s.GetWebhookDelivery(t.Context(), first.ID)
	if d.State != "PENDING" {
		t.Fatal("old lease completed reclaimed delivery")
	}
	if e = s.FinishWebhookDelivery(t.Context(), next, 400, false, "receiver_rejected"); e != nil {
		t.Fatal(e)
	}
	reopened, e := store.Open(t.Context(), dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Pool.Close()
	d, _ = reopened.GetWebhookDelivery(t.Context(), first.ID)
	if d.State != "FAILED" {
		t.Fatal("restart lost failure hold")
	}
	if _, e = s.RetryWebhook(t.Context(), healthAdmin(), first.ID, "FAILED", "fix receiver configuration"); e != nil {
		t.Fatal(e)
	}
	retried := claimWebhook(t, s)
	if retried.ID != first.ID || string(retried.Body) != string(first.Body) {
		t.Fatal("retry created a new operation or changed payload")
	}
	if _, e = s.Pool.Exec(t.Context(), "UPDATE webhook_deliveries SET deadline=clock_timestamp()-interval '1 second' WHERE id=$1", first.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.ReconcileWebhooks(t.Context()); e != nil {
		t.Fatal(e)
	}
	if _, e = s.CompleteWebhook(t.Context(), first.ID, true); !errors.Is(e, store.ErrConflict) {
		t.Fatal("late callback accepted", e)
	}
	if _, e = s.ResolveWebhook(t.Context(), healthAdmin(), first.ID, "FAILED", "stale recovery"); !errors.Is(e, store.ErrConflict) {
		t.Fatal("stale admin action accepted", e)
	}
	if _, e = s.ResolveWebhook(t.Context(), healthAdmin(), first.ID, "TIMED_OUT", "external action confirmed stopped"); e != nil {
		t.Fatal(e)
	}
	second := claimWebhook(t, s)
	if second.ID == first.ID {
		t.Fatal("serial next operation did not advance")
	}
	c, e := s.Cluster(t.Context(), "a")
	if e != nil || c.LifecycleHolds != 1 || c.Available {
		t.Fatal("resolving one hold cleared all holds", e)
	}
}
func TestWebhooksValidationAndSafeEventCatalogue(t *testing.T) {
	s, _ := testutil.Database(t)
	for _, h := range []store.Webhook{
		{ID: "x", Name: "x", URL: "https://example.test", Events: []string{"gateway"}, TimeoutSeconds: 3600},
		{ID: "x", Name: "x", URL: "https://example.test", Events: []string{"book"}, Blocking: true, Idempotent: true, TimeoutSeconds: 3600},
		{ID: "x", Name: "x", URL: "https://example.test", Events: []string{"logout"}, Selector: map[string]string{"team": "one"}, TimeoutSeconds: 3600},
	} {
		if _, e := s.SaveWebhook(t.Context(), healthAdmin(), h, 0, "invalid policy"); !errors.Is(e, store.ErrConflict) {
			t.Fatal("invalid webhook accepted", e)
		}
	}
	for _, event := range store.WebhookEvents() {
		if strings.HasPrefix(event.Name, "webhook_") || event.Name == "gateway" || event.Name == "identity" || event.Name == "cluster_kubeconfig_view" {
			t.Fatal("recursive/read event exported")
		}
	}
	h := store.Webhook{ID: "x", Name: "x", URL: "https://example.test", Events: []string{"cluster_idle"}, Enabled: true, Blocking: true, Idempotent: true, TimeoutSeconds: 3600, SecretCiphertext: []byte("encrypted")}
	if _, e := s.SaveWebhook(t.Context(), healthAdmin(), h, 0, "automatic health verification"); e != nil {
		t.Fatal("automatic monitoring did not permit blocking rule", e)
	}
	if _, e := s.SaveWebhook(t.Context(), identity("alice"), h, 0, "not admin"); !errors.Is(e, store.ErrForbidden) {
		t.Fatal("developer created rule", e)
	}
}

func TestClusterEditorWebhookPublishesMetadataWithoutCredentials(t *testing.T) {
	s, _ := testutil.Database(t)
	register(t, s, "a")
	webhookRule(t, s, "registration-notify", false, "cluster_update")
	admin := adminIdentity()
	cluster, err := s.AdminCluster(ctx, admin, "a")
	if err != nil {
		t.Fatal(err)
	}
	name := "Approved cluster"
	patch := store.ClusterUpdate{Name: &name, Ciphertext: []byte("encrypted-replacement-only"), ExpectedVersion: &cluster.RegistryVersion}
	if err = s.UpdateCluster(ctx, admin, "a", patch, "private-reason-not-for-webhook"); err != nil {
		t.Fatal(err)
	}
	jobs := webhookJobs(t, s)
	if len(jobs) != 1 || jobs[0].EventType != "cluster_update" || jobs[0].ClusterID != "a" || jobs[0].Blocking {
		t.Fatal("registration edit did not create one notification", len(jobs))
	}
	var body map[string]any
	if json.Unmarshal(jobs[0].Body, &body) != nil || body["actor"] != admin.Key() || body["object_id"] != "a" || body["cluster_id"] != "a" || len(body) != 7 {
		t.Fatal("registration notification has unexpected fields")
	}
	for _, forbidden := range []string{"encrypted-replacement-only", "private-reason-not-for-webhook", "kubeconfig", "credentials", "ciphertext"} {
		if strings.Contains(string(jobs[0].Body), forbidden) {
			t.Fatal("credential or private audit detail exposed in notification")
		}
	}
	if _, err = s.AdminKubeconfig(ctx, admin, "a", "inspect connection"); err != nil {
		t.Fatal(err)
	}
	if len(webhookJobs(t, s)) != 1 {
		t.Fatal("administrative credential view created a lifecycle notification")
	}
	for _, event := range store.WebhookEvents() {
		if event.Name == "cluster_update" {
			if !event.Cluster || event.Blocking {
				t.Fatal("cluster edit notification has unsafe event capabilities")
			}
			return
		}
	}
	t.Fatal("cluster edit notification missing from event catalogue")
}
