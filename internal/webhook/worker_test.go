package webhook

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/store"
)

type testQueue struct {
	mu       sync.Mutex
	delivery store.WebhookDelivery
	pending  bool
	finished chan Result
	checks   int
}

func (q *testQueue) ReconcileWebhooks(context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.checks++
	return nil
}
func (q *testQueue) ClaimWebhookDeliveries(_ context.Context, limit int) ([]store.WebhookDelivery, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if limit != 1 || !q.pending {
		return nil, nil
	}
	q.pending = false
	q.delivery.Attempts++
	return []store.WebhookDelivery{q.delivery}, nil
}
func (q *testQueue) FinishWebhookDelivery(_ context.Context, delivery store.WebhookDelivery, status int, retry bool, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pending = retry
	q.finished <- Result{StatusCode: status, Retryable: retry, ReasonCode: reason}
	return nil
}

func workerFixture(t *testing.T, handler http.HandlerFunc) (*Worker, *testQueue, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	vault, err := kube.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := vault.Seal("webhook:hook", []byte(strings.Repeat("secret", 8)))
	if err != nil {
		t.Fatal(err)
	}
	lease := time.Now().Add(20 * time.Second)
	queue := &testQueue{delivery: store.WebhookDelivery{ID: "job", WebhookID: "hook", URL: server.URL, SecretCiphertext: encrypted, Body: []byte(`{"id":"audit-1"}`), LeaseUntil: &lease, Deadline: time.Now().Add(time.Hour)}, pending: true, finished: make(chan Result, 5)}
	return &Worker{Store: queue, Vault: vault, Sender: Sender{Policy: fixturePolicy(server)}, PollInterval: 10 * time.Millisecond}, queue, server
}

func TestWorkerRetriesSameDeliveryAndReconciles(t *testing.T) {
	var calls atomic.Int32
	worker, queue, _ := workerFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Idempotency-Key") != "job" || r.Header.Get("X-Devctl-Callback-Token") != "" || r.Header.Get("X-Devctl-Callback-URL") != "" {
			t.Error("notification identity or credential scope changed")
		}
		io.Copy(io.Discard, r.Body)
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(204)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	for _, expected := range []Result{{StatusCode: 503, Retryable: true, ReasonCode: "receiver_rejected"}, {StatusCode: 204, ReasonCode: "accepted"}} {
		select {
		case got := <-queue.finished:
			if got != expected {
				t.Fatal("unexpected persisted delivery result", got)
			}
		case <-ctx.Done():
			t.Fatal("worker did not deliver queued notification")
		}
	}
	cancel()
	if err := <-done; err != nil || calls.Load() != 2 {
		t.Fatal("worker retry or graceful shutdown failed", err)
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.checks < 2 {
		t.Fatal("worker did not run deadline/verification reconciliation")
	}
}

func TestWorkerShutdownLeavesClaimForRecovery(t *testing.T) {
	started := make(chan struct{})
	worker, queue, _ := workerFixture(t, func(_ http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not start owned receiver request")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker ignored shutdown")
	}
	select {
	case <-queue.finished:
		t.Fatal("shutdown fabricated a receiver failure or completed a claim")
	default:
	}
}

func TestWorkerRejectsInvalidSecretWithoutContactingReceiver(t *testing.T) {
	var calls atomic.Int32
	worker, queue, _ := workerFixture(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	queue.delivery.SecretCiphertext = []byte("invalid encrypted secret")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	select {
	case result := <-queue.finished:
		if result.ReasonCode != "credentials_unavailable" || result.Retryable || calls.Load() != 0 {
			t.Fatal("invalid vault credential leaked or reached receiver", result)
		}
	case <-ctx.Done():
		t.Fatal("worker did not classify vault failure")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestExpiredWorkerClaimNeverDispatches(t *testing.T) {
	var calls atomic.Int32
	worker, queue, _ := workerFixture(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	past := time.Now().Add(-time.Second)
	queue.delivery.LeaseUntil = &past
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	if err := worker.Run(ctx); err != nil || calls.Load() != 0 {
		t.Fatal("a paused worker dispatched after its lease expired", err)
	}
	select {
	case <-queue.finished:
		t.Fatal("former worker completed an expired claim")
	default:
	}
}

func TestExpiredWorkflowDeadlineNeverDispatches(t *testing.T) {
	var calls atomic.Int32
	worker, queue, _ := workerFixture(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	queue.delivery.Deadline = time.Now().Add(-time.Second)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	if err := worker.Run(ctx); err != nil || calls.Load() != 0 {
		t.Fatal("worker dispatched an already-expired workflow", err)
	}
	select {
	case <-queue.finished:
		t.Fatal("expired workflow was submitted as a delivery result")
	default:
	}
}

func TestWorkflowDeadlineBoundsRequestBeforeLeaseExpiry(t *testing.T) {
	started := make(chan struct{})
	worker, queue, _ := workerFixture(t, func(_ http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
	})
	queue.delivery.Deadline = time.Now().Add(200 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("worker did not start the owned receiver request")
	}
	select {
	case result := <-queue.finished:
		if result.ReasonCode != "request_timeout" || !result.Retryable {
			t.Fatal("workflow deadline did not bound the delivery", result)
		}
	case <-ctx.Done():
		t.Fatal("request used the later lease deadline instead of workflow deadline")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
