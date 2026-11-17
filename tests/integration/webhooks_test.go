package integration

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
)

func TestBrowserWebhooks(t *testing.T) {
	api, issuer := os.Getenv("DEVCTL_TEST_WEB_URL"), os.Getenv("DEVCTL_TEST_ISSUER")
	if api == "" || issuer == "" {
		t.Skip("set the disposable browser integration URL and issuer")
	}
	db, dsn := testutil.Database(t)
	root, _ := filepath.Abs("../..")
	e := &environment{t: t, root: root, api: api, issuer: issuer, dsn: dsn, key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{86}, 32))}
	configureGatewayTLS(t, e)
	type receipt struct {
		id, callback, token string
		valid               bool
		body                []byte
	}
	received := make(chan receipt, 8)
	var mu sync.Mutex
	keys := map[string]string{}
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		defer r.Body.Close()
		mu.Lock()
		key := keys[r.URL.Path]
		mu.Unlock()
		id, stamp := r.Header.Get("X-Devctl-Delivery-ID"), r.Header.Get("X-Devctl-Timestamp")
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte(id + "\n" + stamp + "\n"))
		mac.Write(body)
		valid := r.Method == "POST" && key != "" && id != "" && r.Header.Get("Idempotency-Key") == id && hmac.Equal([]byte(r.Header.Get("X-Devctl-Signature")), []byte("sha256="+hex.EncodeToString(mac.Sum(nil))))
		value := receipt{id: id, callback: r.Header.Get("X-Devctl-Callback-URL"), token: r.Header.Get("X-Devctl-Callback-Token"), valid: valid, body: body}
		select {
		case received <- value:
		default:
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer receiver.Close()
	caFile := filepath.Join(t.TempDir(), "receiver-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	e.extraEnv = []string{"DEVCTL_WEBHOOK_ALLOWED_ORIGINS=" + receiver.URL, "DEVCTL_WEBHOOK_CA_FILE=" + caFile, "DEVCTL_DEV_WEBHOOK_LOOPBACK=1"}
	e.start()
	defer e.stop()
	admin, alice, bob := e.browserLogin("admin", true), e.browserLogin("alice", true), e.browserLogin("bob", true)
	_, config := newHealthFixture(t, 200)
	e.browserRequest(admin, "POST", "/v1/admin/clusters", map[string]any{"id": "lifecycle-cluster", "name": "Lifecycle fixture", "labels": map[string]string{"purpose": "lifecycle"}, "kubeconfig": config}, 200)
	e.browserRequest(admin, "PATCH", "/v1/admin/health", map[string]string{"mode": "observe", "reason": "Check the owned lifecycle fixture"}, 200)
	getHealth := func() model.ClusterHealth {
		var h model.ClusterHealth
		if json.Unmarshal(e.browserRequest(alice, "GET", "/v1/clusters/lifecycle-cluster/health", nil, 200), &h) != nil {
			t.Fatal("invalid health metadata")
		}
		return h
	}
	waitHealth := func(want string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			h := getHealth()
			if h.State == want && !h.CheckPending {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("health did not reach %s", want)
	}
	due := func() {
		t.Helper()
		if _, err := db.Pool.Exec(t.Context(), "UPDATE cluster_health SET next_check_at=clock_timestamp() WHERE cluster_id='lifecycle-cluster'"); err != nil {
			t.Fatal(err)
		}
	}
	waitHealth("RECOVERING")
	due()
	waitHealth("PASSING")
	makeRule := func(path, event string, blocking bool) (store.Webhook, string) {
		t.Helper()
		body := map[string]any{"name": "Owned lifecycle receiver", "url": receiver.URL + path, "events": []string{event}, "cluster_id": "lifecycle-cluster", "selector": map[string]string{"purpose": "lifecycle"}, "blocking": blocking, "idempotent": true, "enabled": true, "timeout_seconds": 3600, "reason": "Configure an owned test receiver"}
		var result struct {
			Rule   store.Webhook `json:"rule"`
			Secret string        `json:"secret"`
		}
		if json.Unmarshal(e.browserRequest(admin, "POST", "/v1/admin/webhooks", body, 201), &result) != nil || result.Secret == "" {
			t.Fatal("missing one-time signing secret")
		}
		mu.Lock()
		keys[path] = result.Secret
		mu.Unlock()
		return result.Rule, result.Secret
	}
	e.browserRequest(alice, "GET", "/v1/admin/webhooks", nil, 403)
	// Cookie authorization alone never bypasses the browser CSRF check.
	req, _ := http.NewRequest("POST", e.api+"/v1/admin/webhooks", strings.NewReader(`{}`))
	req.Header.Set("Origin", e.api)
	req.Header.Set("Content-Type", "application/json")
	resp, err := admin.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("webhook administration bypassed CSRF")
	}
	_, secret := makeRule("/run", "cluster_idle", true)
	first := session(t, e.browserRequest(alice, "POST", "/v1/sessions", model.Booking{Cluster: "lifecycle-cluster"}, 201))
	e.browserRequest(alice, "POST", "/v1/sessions/"+first.ID+"/share", map[string]bool{"shareable": true}, 200)
	second := session(t, e.browserRequest(bob, "POST", "/v1/sessions", model.Booking{Cluster: "lifecycle-cluster"}, 201))
	e.browserRequest(alice, "POST", "/v1/sessions/"+first.ID+"/stop", nil, 200)
	jobs, err := db.WebhookDeliveries(t.Context(), admin.user, 100)
	if err != nil || len(jobs) != 0 {
		t.Fatal("first shared departure triggered a pipeline", err)
	}
	e.browserRequest(bob, "POST", "/v1/sessions/"+second.ID+"/stop", nil, 200)
	var delivery receipt
	select {
	case delivery = <-received:
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not deliver the committed idle event")
	}
	if !delivery.valid || delivery.token == "" || delivery.callback != e.api+"/v1/webhooks/deliveries/"+delivery.id+"/complete" {
		t.Fatal("signature, idempotency or callback scope was missing")
	}
	if bytes.Contains(delivery.body, []byte(secret)) || bytes.Contains(delivery.body, []byte("kubeconfig")) {
		t.Fatal("unsafe event payload")
	}
	var event map[string]any
	if json.Unmarshal(delivery.body, &event) != nil || event["type"] != "cluster_idle" || event["cluster_id"] != "lifecycle-cluster" {
		t.Fatal("wrong event snapshot")
	}
	e.browserRequest(alice, "POST", "/v1/sessions", model.Booking{Cluster: "lifecycle-cluster"}, 409)
	e.browserRequest(admin, "PATCH", "/v1/admin/clusters/lifecycle-cluster", map[string]any{"maintenance": true, "reason": "Manual maintenance survives callbacks"}, 200)
	callback := func(token, outcome string, status int) {
		t.Helper()
		request, _ := http.NewRequest("POST", delivery.callback, strings.NewReader(`{"outcome":"`+outcome+`"}`))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response, err := e.gatewayClient().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != status {
			t.Fatalf("callback returned %d, want %d", response.StatusCode, status)
		}
	}
	callback(delivery.token+"bad", "succeeded", 401)
	callback(delivery.token, "succeeded", 200)
	job, err := db.GetWebhookDelivery(t.Context(), delivery.id)
	if err != nil || job.State != "VERIFYING" {
		t.Fatal("completion reused a pre-callback green observation", err)
	}
	e.stop()
	e.start()
	waitHealth("RECOVERING")
	job, _ = db.GetWebhookDelivery(t.Context(), delivery.id)
	if job.State != "VERIFYING" {
		t.Fatal("restart released the hold before fresh health verification")
	}
	due()
	waitHealth("PASSING")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		job, err = db.GetWebhookDelivery(t.Context(), delivery.id)
		if err == nil && job.State == "SUCCEEDED" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if job.State != "SUCCEEDED" {
		t.Fatal("verified callback did not resolve its hold")
	}
	cluster, err := db.Cluster(t.Context(), "lifecycle-cluster")
	if err != nil || cluster.LifecycleHolds != 0 || !cluster.Maintenance {
		t.Fatal("callback cleared manual maintenance or retained its completed hold", err)
	}
	callback(delivery.token, "succeeded", 200)
	callback(delivery.token, "failed", 409)
	e.browserRequest(admin, "PATCH", "/v1/admin/clusters/lifecycle-cluster", map[string]any{"maintenance": false, "reason": "Manual review complete"}, 200)
	e.browserRequest(alice, "POST", "/v1/sessions", model.Booking{Cluster: "lifecycle-cluster"}, 201)
	// The same mechanism handles ordinary auditable changes without a hold.
	_, notifySecret := makeRule("/notify", "cluster_labels_update", false)
	e.browserRequest(admin, "PATCH", "/v1/admin/clusters/lifecycle-cluster", map[string]any{"labels": map[string]string{"purpose": "lifecycle", "region": "eu"}, "expected_labels": map[string]string{"purpose": "lifecycle"}, "reason": "private-freeform-marker-not-for-webhook"}, 200)
	select {
	case notification := <-received:
		if !notification.valid || notification.token != "" || bytes.Contains(notification.body, []byte(notifySecret)) || bytes.Contains(notification.body, []byte("private-freeform-marker")) {
			t.Fatal("notification signature or payload was unsafe")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("label notification was not delivered")
	}
	public := e.browserRequest(admin, "GET", "/v1/admin/webhook-deliveries", nil, 200)
	if bytes.Contains(public, []byte(secret)) || bytes.Contains(public, []byte(delivery.token)) || bytes.Contains(public, []byte(receiver.URL)) {
		t.Fatal("delivery history exposed private receiver credentials")
	}
	t.Log("local Keycloak/CSRF, signed TLS notification, last-shared release, atomic hold, scoped callback, fresh health, restart and independent maintenance passed")
}
