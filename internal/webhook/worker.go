package webhook

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/store"
)

type Queue interface {
	ReconcileWebhooks(context.Context) error
	ClaimWebhookDeliveries(context.Context, int) ([]store.WebhookDelivery, error)
	FinishWebhookDelivery(context.Context, store.WebhookDelivery, int, bool, string) error
}

// Worker is intentionally serial per backend. PostgreSQL leases coordinate
// replicas; HTTP and reconciliation never share an open transaction.
type Worker struct {
	Store        Queue
	Vault        *kube.Vault
	Sender       Sender
	PollInterval time.Duration
}

func NewWorker(db *store.Store, vault *kube.Vault, policy Policy, publicURL string) *Worker {
	return &Worker{Store: db, Vault: vault, Sender: Sender{Policy: policy, PublicURL: publicURL}}
}

func (w *Worker) Run(ctx context.Context) error {
	if w.Store == nil || w.Vault == nil {
		return errors.New("webhook worker requires store and vault")
	}
	poll := w.PollInterval
	if poll < 10*time.Millisecond {
		poll = time.Second
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for ctx.Err() == nil {
		task, done := context.WithTimeout(ctx, 5*time.Second)
		err := w.Store.ReconcileWebhooks(task)
		var deliveries []store.WebhookDelivery
		if err == nil {
			deliveries, err = w.Store.ClaimWebhookDeliveries(task, 1)
		}
		done()
		if err != nil && ctx.Err() == nil {
			slog.Warn("Webhook queue unavailable", "category", "queue_failed")
		}
		for _, delivery := range deliveries {
			if delivery.LeaseUntil == nil {
				continue
			}
			until := *delivery.LeaseUntil
			if delivery.Deadline.Before(until) {
				until = delivery.Deadline
			}
			if !until.After(time.Now()) {
				continue // A paused owner must not dispatch after its lease or workflow deadline.
			}
			deliveryContext, stopDelivery := context.WithDeadline(ctx, until)
			secret, err := w.Vault.Open("webhook:"+delivery.WebhookID, delivery.SecretCiphertext)
			result := Result{ReasonCode: "credentials_unavailable"}
			if err == nil {
				result = w.Sender.Send(deliveryContext, delivery, secret)
			}
			stopDelivery()
			if ctx.Err() != nil {
				return nil // Leave the claim to expire; shutdown is not receiver failure.
			}
			finish, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = w.Store.FinishWebhookDelivery(finish, delivery, result.StatusCode, result.Retryable, result.ReasonCode)
			cancel()
			if err != nil && ctx.Err() == nil {
				slog.Warn("Webhook result unavailable", "delivery_id", delivery.ID, "category", "publish_failed")
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
	return nil
}
