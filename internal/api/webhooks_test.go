package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/webhook"
)

func webhookBody(events ...string) map[string]any {
	return map[string]any{"name": "Owned receiver", "url": "https://ci.example.test/run", "events": events, "selector": map[string]string{}, "blocking": false, "enabled": true, "idempotent": true, "timeout_seconds": 3600, "reason": "Configure the owned receiver"}
}
func webhookJSON(t *testing.T, body any) string {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestWebhookAPIProtectsConfigurationAndOneTimeSecrets(t *testing.T) {
	var hits atomic.Int64
	g := newGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }), false)
	g.app.WebhookPolicy = webhook.Policy{AllowedOrigins: []string{"https://ci.example.test"}}
	for _, token := range []string{"", "invalid", "alice", "bob"} {
		status := 403
		if token == "" || token == "invalid" {
			status = 401
		}
		expectAPI(t, g, "GET", "/v1/admin/webhooks", token, "", status)
		expectAPI(t, g, "POST", "/v1/admin/webhooks", token, webhookJSON(t, webhookBody("release")), status)
	}
	for _, url := range []string{"http://ci.example.test/run", "https://outside.example.test/run", "https://user:password@ci.example.test/run", "https://ci.example.test/run?token=secret"} {
		body := webhookBody("release")
		body["url"] = url
		expectAPI(t, g, "POST", "/v1/admin/webhooks", "admin", webhookJSON(t, body), 400)
	}
	for _, body := range []string{`{}`, `null`, `{"name":"test","reason":"valid","admin":true}`} {
		expectAPI(t, g, "POST", "/v1/admin/webhooks", "admin", body, 400)
	}
	var created struct {
		Rule   store.Webhook `json:"rule"`
		Secret string        `json:"secret"`
	}
	if json.Unmarshal([]byte(expectAPI(t, g, "POST", "/v1/admin/webhooks", "admin", webhookJSON(t, webhookBody("release")), 201)), &created) != nil || len(created.Secret) != 43 || created.Rule.Version != 1 {
		t.Fatal("create did not issue one signing secret and revision")
	}
	list := expectAPI(t, g, "GET", "/v1/admin/webhooks", "admin", "", 200)
	if strings.Contains(list, created.Secret) || strings.Contains(list, "secret_ciphertext") || !strings.Contains(list, "cluster_idle") {
		t.Fatal("catalogue leaked a secret or omitted supported events")
	}
	g.app.WebhookPolicy.AllowedOrigins = nil
	body := webhookBody("release")
	body["enabled"], body["expected_version"] = false, 1
	path := "/v1/admin/webhooks/" + created.Rule.ID
	updated := expectAPI(t, g, "PATCH", path, "admin", webhookJSON(t, body), 200)
	if strings.Contains(updated, created.Secret) {
		t.Fatal("update redisplayed the one-time secret")
	}
	expectAPI(t, g, "PATCH", path, "admin", webhookJSON(t, body), 409)
	body["url"], body["expected_version"] = "https://outside.example.test/changed", 2
	expectAPI(t, g, "PATCH", path, "admin", webhookJSON(t, body), 400)
	if hits.Load() != 0 {
		t.Fatal("configuration contacted a receiver or Kubernetes")
	}
}

func TestWebhookCallbackScopeAndFreshHealthVerification(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), false)
	g.app.WebhookPolicy = webhook.Policy{AllowedOrigins: []string{"https://ci.example.test"}}
	body := webhookBody("cluster_idle")
	body["blocking"] = true
	var created struct {
		Rule   store.Webhook `json:"rule"`
		Secret string        `json:"secret"`
	}
	if json.Unmarshal([]byte(expectAPI(t, g, "POST", "/v1/admin/webhooks", "admin", webhookJSON(t, body), 201)), &created) != nil {
		t.Fatal("could not configure blocking fixture rule")
	}
	expectAPI(t, g, "POST", "/v1/sessions/"+g.session.ID+"/stop", "alice", "", 200)
	jobs, err := g.db.WebhookDeliveries(t.Context(), model.Identity{Admin: true}, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatal("final release did not queue one delivery", err)
	}
	job := jobs[0]
	path := "/v1/webhooks/deliveries/" + job.ID + "/complete"
	token := webhook.CallbackToken([]byte(created.Secret), job.ID, job.Deadline)
	for _, bad := range []string{"", "admin", "alice", token + "bad", webhook.CallbackToken([]byte(created.Secret), "another-job", job.Deadline)} {
		expectAPI(t, g, "POST", path, bad, `{"outcome":"succeeded"}`, 401)
	}
	expectAPI(t, g, "POST", path, token, `{"outcome":"succeeded"}`, 409)
	claims, err := g.db.ClaimWebhookDeliveries(t.Context(), 1)
	if err != nil || len(claims) != 1 {
		t.Fatal("could not claim delivery", err)
	}
	expectAPI(t, g, "POST", path, token, `{"outcome":"succeeded","maintenance":false}`, 400)
	expectAPI(t, g, "POST", path, token, `{"outcome":"succeeded"}`, 200)
	if err := g.db.FinishWebhookDelivery(t.Context(), claims[0], 202, false, "accepted"); err != nil {
		t.Fatal(err)
	}
	public := expectAPI(t, g, "GET", "/v1/admin/webhook-deliveries", "admin", "", 200)
	if !strings.Contains(public, "VERIFYING") || strings.Contains(public, token) || strings.Contains(public, created.Secret) || strings.Contains(public, "ci.example.test") {
		t.Fatal("acceptance race lost verification or exposed private data")
	}
	for cycle := 1; cycle <= 2; cycle++ {
		if _, err := g.db.Pool.Exec(t.Context(), "UPDATE cluster_health SET next_check_at=clock_timestamp() WHERE cluster_id='cluster'"); err != nil {
			t.Fatal(err)
		}
		health, err := g.db.ClaimHealthChecks(t.Context(), 1)
		if err != nil || len(health) != 1 {
			t.Fatal("expected fresh health cycle", err)
		}
		if accepted, err := g.db.PublishHealthCheck(t.Context(), health[0], model.HealthResult{Passed: true, ReasonCode: "checks_passed", ReadinessConfirmed: true, DiscoveryCoverage: "aggregated"}, time.Second); err != nil || !accepted {
			t.Fatal("health publication failed", err)
		}
		if err := g.db.ReconcileWebhooks(t.Context()); err != nil {
			t.Fatal(err)
		}
		current, err := g.db.GetWebhookDelivery(t.Context(), job.ID)
		if err != nil || cycle == 1 && current.State != "VERIFYING" || cycle == 2 && current.State != "SUCCEEDED" {
			t.Fatal("completion did not require two fresh cycles", err)
		}
		expectAPI(t, g, "POST", path, token, `{"outcome":"succeeded"}`, 200)
	}
	expectAPI(t, g, "POST", path, token, `{"outcome":"failed"}`, 409)
	expectAPI(t, g, "POST", "/v1/admin/webhook-deliveries/"+job.ID+"/resolve", "admin", `{"expected_state":"SUCCEEDED","reason":"cannot skip confirmation"}`, 400)
}
