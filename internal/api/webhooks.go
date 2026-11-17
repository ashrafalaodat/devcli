package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/webhook"
	"github.com/google/uuid"
)

func webhookReply(w http.ResponseWriter, err error, status int, value any) {
	switch {
	case err == nil:
		write(w, status, value)
	case errors.Is(err, store.ErrNotFound):
		fail(w, 404, "webhook or delivery was not found")
	case errors.Is(err, store.ErrForbidden):
		fail(w, 403, "administrator required")
	case errors.Is(err, store.ErrConflict):
		fail(w, 409, err.Error())
	default:
		fail(w, 503, "webhook service unavailable; try again")
	}
}

func (s *Server) webhooks(w http.ResponseWriter, r *http.Request) {
	rules, err := s.Store.Webhooks(r.Context(), user(r))
	if err != nil {
		webhookReply(w, err, 0, nil)
		return
	}
	settings, err := s.Store.Settings(r.Context(), user(r))
	origins := s.WebhookPolicy.AllowedOrigins
	if origins == nil {
		origins = []string{}
	}
	webhookReply(w, err, 200, map[string]any{"rules": rules, "events": store.WebhookEvents(), "allowed_origins": origins, "health_mode": settings.HealthMode})
}

func (s *Server) saveWebhook(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name            string            `json:"name"`
		URL             string            `json:"url"`
		Events          []string          `json:"events"`
		ClusterID       string            `json:"cluster_id"`
		Selector        map[string]string `json:"selector"`
		Blocking        *bool             `json:"blocking"`
		Enabled         *bool             `json:"enabled"`
		Idempotent      *bool             `json:"idempotent"`
		TimeoutSeconds  *int              `json:"timeout_seconds"`
		ExpectedVersion *int64            `json:"expected_version"`
		Reason          string            `json:"reason"`
	}
	create := r.Method == http.MethodPost
	if err := decode(w, r, &body); err != nil || !create && (!safeID.MatchString(r.PathValue("id")) || body.ExpectedVersion == nil || *body.ExpectedVersion < 1 || body.Blocking == nil || body.Enabled == nil || body.Idempotent == nil || body.TimeoutSeconds == nil) || create && body.ExpectedVersion != nil {
		fail(w, 400, "valid webhook settings and expected_version for updates are required")
		return
	}
	reason, valid := healthReason(body.Reason)
	if !valid {
		fail(w, 400, "an audit reason of 1 through 1000 bytes is required")
		return
	}
	if err := s.WebhookPolicy.Validate(body.URL); err != nil {
		// Removing a destination from operator policy must not prevent disabling
		// its existing rule. New/changed URLs still require normal validation.
		canDisable := false
		if !create && body.Enabled != nil && !*body.Enabled {
			rules, readErr := s.Store.Webhooks(r.Context(), user(r))
			if readErr != nil {
				webhookReply(w, readErr, 0, nil)
				return
			}
			for _, rule := range rules {
				canDisable = canDisable || rule.ID == r.PathValue("id") && rule.URL == body.URL
			}
		}
		if !canDisable {
			fail(w, 400, err.Error())
			return
		}
	}
	rule := store.Webhook{Name: body.Name, URL: body.URL, Events: body.Events, ClusterID: body.ClusterID, Selector: body.Selector, TimeoutSeconds: 3600}
	if body.Blocking != nil {
		rule.Blocking = *body.Blocking
	}
	if body.Enabled != nil {
		rule.Enabled = *body.Enabled
	}
	if body.Idempotent != nil {
		rule.Idempotent = *body.Idempotent
	}
	if body.TimeoutSeconds != nil {
		rule.TimeoutSeconds = *body.TimeoutSeconds
	}
	expected, status, secret := int64(0), http.StatusOK, ""
	if create {
		rule.ID, status = "wh-"+uuid.NewString(), http.StatusCreated
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			webhookReply(w, err, 0, nil)
			return
		}
		secret = base64.RawURLEncoding.EncodeToString(random[:])
		var err error
		rule.SecretCiphertext, err = s.Vault.Seal("webhook:"+rule.ID, []byte(secret))
		if err != nil {
			webhookReply(w, err, 0, nil)
			return
		}
	} else {
		rule.ID, expected = r.PathValue("id"), *body.ExpectedVersion
	}
	saved, err := s.Store.SaveWebhook(r.Context(), user(r), rule, expected, reason)
	response := map[string]any{"rule": saved}
	if create {
		response["secret"] = secret // One-time configuration value, never a log.
	}
	webhookReply(w, err, status, response)
}

func (s *Server) webhookDeliveries(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		var err error
		limit, err = strconv.Atoi(value)
		if err != nil || limit < 1 || limit > 100 {
			fail(w, 400, "limit must be between 1 and 100")
			return
		}
	}
	value, err := s.Store.WebhookDeliveries(r.Context(), user(r), limit)
	webhookReply(w, err, 200, value)
}

func (s *Server) webhookRecovery(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ExpectedState    string `json:"expected_state"`
		ConfirmedStopped bool   `json:"confirmed_stopped"`
		Reason           string `json:"reason"`
	}
	if err := decode(w, r, &body); err != nil || !safeID.MatchString(r.PathValue("id")) || body.ExpectedState == "" {
		fail(w, 400, "delivery ID, expected_state and audit reason required")
		return
	}
	reason, valid := healthReason(body.Reason)
	if !valid {
		fail(w, 400, "an audit reason of 1 through 1000 bytes is required")
		return
	}
	var value store.WebhookDelivery
	var err error
	if strings.HasSuffix(r.URL.Path, "/resolve") {
		if !body.ConfirmedStopped {
			fail(w, 400, "confirm the external work has stopped before resolving its hold")
			return
		}
		value, err = s.Store.ResolveWebhook(r.Context(), user(r), r.PathValue("id"), body.ExpectedState, reason)
	} else {
		value, err = s.Store.RetryWebhook(r.Context(), user(r), r.PathValue("id"), body.ExpectedState, reason)
	}
	webhookReply(w, err, 200, value)
}

// Integrations authenticate only this operation, never with browser cookies,
// developer PATs or administrator credentials. Ordinary API auth is bypassed
// solely for this route; the token is checked before applying any completion.
func (s *Server) completeWebhook(w http.ResponseWriter, r *http.Request) {
	if !safeID.MatchString(r.PathValue("id")) {
		fail(w, 401, "invalid completion credential")
		return
	}
	job, err := s.Store.GetWebhookDelivery(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, 401, "invalid completion credential")
		} else {
			webhookReply(w, err, 0, nil)
		}
		return
	}
	secret, err := s.Vault.Open("webhook:"+job.WebhookID, job.SecretCiphertext)
	if err != nil {
		webhookReply(w, err, 0, nil)
		return
	}
	expected := webhook.CallbackToken(secret, job.ID, job.Deadline)
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
		fail(w, 401, "invalid completion credential")
		return
	}
	var body struct {
		Outcome string `json:"outcome"`
	}
	if err := decode(w, r, &body); err != nil || body.Outcome != "succeeded" && body.Outcome != "failed" {
		fail(w, 400, "outcome must be succeeded or failed")
		return
	}
	value, err := s.Store.CompleteWebhook(r.Context(), job.ID, body.Outcome == "succeeded")
	webhookReply(w, err, 200, value)
}
