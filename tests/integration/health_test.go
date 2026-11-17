package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
	"k8s.io/client-go/tools/clientcmd"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
)

// This is a disposable TLS protocol fixture. Every Kubernetes request in this
// test is a GET; neither the worker nor the test contacts registered clusters.
type healthFixture struct {
	server    *httptest.Server
	readiness atomic.Int64
	hits      atomic.Int64
	unsafe    atomic.Int64
}

func newHealthFixture(t *testing.T, readiness int) (*healthFixture, string) {
	t.Helper()
	f := &healthFixture{}
	f.readiness.Store(int64(readiness))
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer health-fixture-secret" {
			f.unsafe.Add(1)
			http.Error(w, "unsupported fixture operation", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			io.WriteString(w, `{"major":"1","minor":"35","gitVersion":"v1.35.1-health"}`)
		case "/readyz":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(int(f.readiness.Load()))
			io.WriteString(w, "fixture readiness")
		case "/api":
			io.WriteString(w, `{"apiVersion":"apidiscovery.k8s.io/v2","kind":"APIGroupDiscoveryList","items":[{"metadata":{"name":""},"versions":[{"version":"v1","freshness":"Current","resources":[{"resource":"pods","scope":"Namespaced","responseKind":{"version":"v1","kind":"Pod"}}]}]}]}`)
		case "/apis":
			io.WriteString(w, `{"apiVersion":"apidiscovery.k8s.io/v2","kind":"APIGroupDiscoveryList","items":[{"metadata":{"name":"apps"},"versions":[{"version":"v1","freshness":"Current","resources":[{"resource":"deployments","scope":"Namespaced","responseKind":{"group":"apps","version":"v1","kind":"Deployment"}}]}]},{"metadata":{"name":"batch"},"versions":[{"version":"v1","freshness":"Current","resources":[{"resource":"jobs","scope":"Namespaced","responseKind":{"group":"batch","version":"v1","kind":"Job"}}]}]}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	config := clientapi.NewConfig()
	config.CurrentContext = "health"
	config.Clusters["fixture"] = &clientapi.Cluster{Server: f.server.URL, CertificateAuthorityData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw})}
	config.AuthInfos["fixture"] = &clientapi.AuthInfo{Token: "health-fixture-secret"}
	config.Contexts["health"] = &clientapi.Context{Cluster: "fixture", AuthInfo: "fixture"}
	raw, err := clientcmd.Write(*config)
	if err != nil {
		t.Fatal(err)
	}
	return f, string(raw)
}

func TestBrowserClusterHealth(t *testing.T) {
	api, issuer := os.Getenv("DEVCTL_TEST_WEB_URL"), os.Getenv("DEVCTL_TEST_ISSUER")
	if api == "" || issuer == "" {
		t.Skip("set DEVCTL_TEST_WEB_URL and DEVCTL_TEST_ISSUER for the disposable browser health integration")
	}
	db, dsn := testutil.Database(t)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	e := &environment{t: t, root: root, api: api, issuer: issuer, dsn: dsn, key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{49}, 32))}
	configureGatewayTLS(t, e)
	e.start()
	defer e.stop()
	admin, alice, bob := e.browserLogin("admin", true), e.browserLogin("alice", true), e.browserLogin("bob", true)
	bad, badConfig := newHealthFixture(t, 503)
	good, goodConfig := newHealthFixture(t, 200)
	for _, fixture := range []struct{ id, config string }{{"health-a-bad", badConfig}, {"health-z-good", goodConfig}} {
		e.browserRequest(admin, "POST", "/v1/admin/clusters", map[string]any{"id": fixture.id, "name": fixture.id, "kubeconfig": fixture.config, "labels": map[string]string{"purpose": "health-test"}}, 200)
	}
	var issued struct {
		PAT        store.PAT `json:"pat"`
		Kubeconfig string    `json:"kubeconfig"`
	}
	if json.Unmarshal(e.browserRequest(bob, "POST", "/v1/pats", map[string]any{"name": "Health fallback fixture", "ttl": "1h", "auto_booking": model.AutoBookingPolicy{Enabled: true, Selector: map[string]string{"purpose": "health-test"}}}, 201), &issued) != nil {
		t.Fatal("could not issue the fixture PAT")
	}
	config, err := clientcmd.Load([]byte(issued.Kubeconfig))
	if err != nil {
		t.Fatal(err)
	}
	secret := config.AuthInfos["devctl-personal-access"].Token
	getHealth := func(id string) model.ClusterHealth {
		t.Helper()
		var value model.ClusterHealth
		if json.Unmarshal(e.browserRequest(alice, "GET", "/v1/clusters/"+id+"/health", nil, 200), &value) != nil {
			t.Fatal("health summary was not JSON")
		}
		return value
	}
	waitFor := func(id, state string) model.ClusterHealth {
		t.Helper()
		deadline := time.Now().Add(12 * time.Second)
		for time.Now().Before(deadline) {
			value := getHealth(id)
			if value.State == state && !value.CheckPending {
				return value
			}
			time.Sleep(50 * time.Millisecond)
		}
		value := getHealth(id)
		t.Fatalf("health cycle did not reach %s (state=%s, category=%s)", state, value.State, value.ReasonCode)
		return value
	}
	// Advance only this isolated test schema's due time, avoiding a production
	// timer override or thirty-second sleeps. The actual backend worker probes.
	due := func(id string) {
		t.Helper()
		if _, err := db.Pool.Exec(t.Context(), "UPDATE cluster_health SET next_check_at=clock_timestamp() WHERE cluster_id=$1", id); err != nil {
			t.Fatal(err)
		}
	}

	// Automatic monitoring starts immediately after registration; no enable setting.
	e.browserRequest(bob, "POST", "/v1/sessions", model.Booking{Cluster: "health-a-bad"}, 409)
	e.browserRequest(alice, "POST", "/v1/admin/clusters/health-z-good/health-check", map[string]string{"reason": "developer must not request admin checks"}, 403)
	// The cookie-authenticated administrative refresh retains Origin/CSRF checks.
	request, _ := http.NewRequest(http.MethodPost, e.api+"/v1/admin/clusters/health-z-good/health-check", bytes.NewBufferString(`{"reason":"missing csrf"}`))
	request.Header.Set("Origin", e.api)
	request.Header.Set("Content-Type", "application/json")
	response, err := admin.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("health mutation bypassed browser CSRF")
	}
	waitFor("health-a-bad", "FAILING")
	waitFor("health-z-good", "RECOVERING")
	e.browserRequest(admin, "POST", "/v1/admin/clusters/health-z-good/health-check", map[string]string{"reason": "verify second complete fixture cycle"}, 202)
	waitFor("health-z-good", "PASSING")
	if bad.hits.Load() == 0 || good.hits.Load() == 0 {
		t.Fatal("default monitoring made no upstream requests")
	}
	current := session(t, e.browserRequest(alice, "POST", "/v1/sessions", model.Booking{Cluster: "health-z-good"}, 201))
	var beforeExpiry time.Time
	var beforeActivity *time.Time
	if err := db.Pool.QueryRow(t.Context(), "SELECT expires_at,last_activity_at FROM sessions WHERE id=$1", current.ID).Scan(&beforeExpiry, &beforeActivity); err != nil {
		t.Fatal(err)
	}
	due("health-z-good")
	waitFor("health-z-good", "PASSING")
	var afterExpiry time.Time
	var afterActivity, patUse *time.Time
	if err := db.Pool.QueryRow(t.Context(), "SELECT expires_at,last_activity_at FROM sessions WHERE id=$1", current.ID).Scan(&afterExpiry, &afterActivity); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(t.Context(), "SELECT last_used_at FROM personal_access_tokens WHERE id=$1", issued.PAT.ID).Scan(&patUse); err != nil {
		t.Fatal(err)
	}
	if !beforeExpiry.Equal(afterExpiry) || beforeActivity != nil || afterActivity != nil || patUse != nil {
		t.Fatal("background probes created developer activity or used a PAT")
	}
	waitFor("health-z-good", "PASSING")
	waitFor("health-a-bad", "FAILING")
	e.browserRequest(bob, "POST", "/v1/sessions", model.Booking{Cluster: "health-a-bad"}, 409)
	good.readiness.Store(503)
	due("health-z-good")
	waitFor("health-z-good", "FAILING")
	// Existing holders still have gateway access; health only gates placement.
	var own struct {
		Kubeconfig string `json:"kubeconfig"`
	}
	if json.Unmarshal(e.browserRequest(alice, "POST", "/v1/pats", map[string]string{"name": "Existing holder", "ttl": "1h"}, 201), &own) != nil {
		t.Fatal("could not issue holder credential")
	}
	ownerConfig, _ := clientcmd.Load([]byte(own.Kubeconfig))
	ownerRequest, _ := http.NewRequest(http.MethodGet, e.api+"/k8s/version", nil)
	ownerRequest.Header.Set("Authorization", "Bearer "+ownerConfig.AuthInfos["devctl-personal-access"].Token)
	ownerResponse, err := e.gatewayClient().Do(ownerRequest)
	if err != nil {
		t.Fatal(err)
	}
	ownerResponse.Body.Close()
	if ownerResponse.StatusCode != 200 {
		t.Fatal("background health failure revoked an existing booking")
	}
	good.readiness.Store(200)
	due("health-z-good")
	waitFor("health-z-good", "RECOVERING")
	due("health-z-good")
	waitFor("health-z-good", "PASSING")
	e.browserRequest(alice, "POST", "/v1/sessions/"+current.ID+"/stop", nil, 200)
	fallback, _ := http.NewRequest(http.MethodGet, e.api+"/k8s/version", nil)
	fallback.Header.Set("Authorization", "Bearer "+secret)
	fallbackResponse, err := e.gatewayClient().Do(fallback)
	if err != nil {
		t.Fatal(err)
	}
	fallbackResponse.Body.Close()
	if fallbackResponse.StatusCode != 200 {
		t.Fatal("PAT fallback did not skip the failing first candidate")
	}
	profile, err := db.Profile(t.Context(), bob.user)
	if err != nil || profile.PrimarySession == nil || profile.PrimarySession.Cluster != "health-z-good" {
		t.Fatal("automatic placement chose a failing cluster", err)
	}
	e.stop()
	e.start()
	if health := getHealth("health-z-good"); health.State != "PASSING" {
		t.Fatal("restart discarded durable health observations")
	}
	if bad.unsafe.Load()+good.unsafe.Load() != 0 {
		t.Fatal("health monitoring attempted non-GET or unapproved credential operations")
	}
	t.Log("real Keycloak/CSRF, default automatic background probes, recovery, preserved activity/access, enforced placement, PAT fallback and restart passed")
}
