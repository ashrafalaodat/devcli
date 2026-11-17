package health

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
)

// Queue is the durable boundary. PostgreSQL leases and fencing, rather than
// local worker goroutines, prevent duplicate or stale publication.
type Queue interface {
	ClaimHealthChecks(context.Context, int) ([]store.HealthClaim, error)
	PublishHealthCheck(context.Context, store.HealthClaim, model.HealthResult, time.Duration) (bool, error)
}

type Worker struct {
	Store        Queue
	Vault        *kube.Vault
	Prober       Prober
	PollInterval time.Duration
	Concurrency  int
	Interval     time.Duration
}

func NewWorker(db *store.Store, vault *kube.Vault) *Worker {
	return &Worker{Store: db, Vault: vault}
}

// Run keeps bounded health work in the backend process. A transient database
// failure is retried; process cancellation drains local probes without
// manufacturing failure observations. Disabled mode is enforced by the queue.
func (w *Worker) Run(ctx context.Context) error {
	if w.Store == nil || w.Vault == nil {
		return errors.New("health worker requires a store and vault")
	}
	concurrency := w.Concurrency
	if concurrency <= 0 || concurrency > 4 {
		concurrency = 4
	}
	poll := w.PollInterval
	if poll <= 0 {
		poll = time.Second
	}
	if poll < 10*time.Millisecond {
		poll = 10 * time.Millisecond
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	var active atomic.Int32
	var tasks sync.WaitGroup
	defer tasks.Wait()
	for {
		if ctx.Err() != nil {
			return nil
		}
		free := concurrency - int(active.Load())
		if free > 0 {
			claimContext, cancel := context.WithTimeout(ctx, 5*time.Second)
			claims, err := w.Store.ClaimHealthChecks(claimContext, free)
			cancel()
			if err != nil && ctx.Err() == nil {
				slog.Warn("Cluster health queue unavailable", "category", "claim_failed")
			}
			// The durable store honors the requested limit. Keep the local bound
			// even if an alternative Queue implementation violates its contract.
			if len(claims) > free {
				claims = claims[:free]
			}
			for _, claim := range claims {
				active.Add(1)
				tasks.Add(1)
				go func() {
					defer tasks.Done()
					defer active.Add(-1)
					w.runClaim(ctx, claim)
				}()
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (w *Worker) runClaim(ctx context.Context, claim store.HealthClaim) {
	if ctx.Err() != nil {
		return
	}
	raw, err := w.Vault.Open(claim.ClusterID, claim.Ciphertext)
	result := model.HealthResult{ReasonCode: "credentials_unavailable", DiscoveryCoverage: "not_completed"}
	if err == nil {
		result = w.Prober.Probe(ctx, raw, claim.Profile)
	}
	if ctx.Err() != nil {
		return
	}
	interval := w.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if interval < 2*time.Second {
		interval = 2 * time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	delay := time.Duration(float64(interval) * (0.8 + rand.Float64()*0.4))
	if rateLimit := time.Duration(result.RetryAfterSeconds) * time.Second; rateLimit > delay {
		delay = rateLimit
	}
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	publishContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := w.Store.PublishHealthCheck(publishContext, claim, result, delay); err != nil && ctx.Err() == nil {
		slog.Warn("Cluster health observation could not be saved", "cluster_id", claim.ClusterID, "category", "publish_failed")
	}
}
