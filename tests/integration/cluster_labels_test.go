package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
	"k8s.io/client-go/tools/clientcmd"
)

// Real local Keycloak browser SSO and PostgreSQL exercise the same cookie/CSRF
// API used by the label editor. Upstreams are disposable TLS protocol fixtures.
func TestBrowserClusterLabels(t *testing.T) {
	api, issuer := os.Getenv("DEVCTL_TEST_WEB_URL"), os.Getenv("DEVCTL_TEST_ISSUER")
	if api == "" || issuer == "" {
		t.Skip("set DEVCTL_TEST_WEB_URL and DEVCTL_TEST_ISSUER with an approved browser callback")
	}
	db, dsn := testutil.Database(t)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	e := &environment{t: t, root: root, api: api, issuer: issuer, dsn: dsn, key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{94}, 32))}
	configureGatewayTLS(t, e)
	e.start()
	defer e.stop()
	admin, alice := e.browserLogin("admin", true), e.browserLogin("alice", true)
	first := newKubernetesFixtureVersion(t, "v1.35.1-label-first")
	second := newKubernetesFixtureVersion(t, "v1.35.1-label-second")
	for _, registration := range []struct{ id, region, config string }{
		{"labels-first", "eu", first.kubeconfig()},
		{"labels-second", "us", second.kubeconfig()},
	} {
		e.browserRequest(admin, "POST", "/v1/admin/clusters", map[string]any{
			"id": registration.id, "name": registration.id,
			"labels": map[string]string{"region": registration.region}, "kubeconfig": registration.config,
		}, 200)
	}
	booked := session(t, e.browserRequest(alice, "POST", "/v1/sessions", model.Booking{Cluster: "labels-first"}, 201))
	var issued struct {
		PAT        store.PAT `json:"pat"`
		Kubeconfig string    `json:"kubeconfig"`
	}
	if json.Unmarshal(e.browserRequest(alice, "POST", "/v1/pats", map[string]any{
		"name": "Stable config during registry edits", "ttl": "1h",
		"auto_booking": model.AutoBookingPolicy{Enabled: true, Selector: map[string]string{"region": "eu"}},
	}, 201), &issued) != nil {
		t.Fatal("could not issue test credential")
	}
	config, err := clientcmd.Load([]byte(issued.Kubeconfig))
	if err != nil {
		t.Fatal("invalid gateway test configuration")
	}
	secret := config.AuthInfos["devctl-personal-access"].Token
	var beforeCipher, beforeDigest []byte
	var beforeExpiry time.Time
	if err = db.Pool.QueryRow(t.Context(), "SELECT kubeconfig_ciphertext FROM clusters WHERE id='labels-first'").Scan(&beforeCipher); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(t.Context(), "SELECT token_digest,expires_at FROM personal_access_tokens WHERE id=$1", issued.PAT.ID).Scan(&beforeDigest, &beforeExpiry); err != nil {
		t.Fatal(err)
	}
	path := "/v1/admin/clusters/labels-first"
	old := map[string]string{"region": "eu"}
	replacement := map[string]string{"region": "us", "purpose": ""}
	change := map[string]any{"labels": replacement, "expected_labels": old, "reason": "Browser administrator relabelled this registered environment"}
	e.browserRequest(alice, "PATCH", path, change, 403)
	for _, origin := range []string{e.api, "https://unapproved.example.test"} {
		raw, _ := json.Marshal(change)
		request, err := http.NewRequest(http.MethodPatch, e.api+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		if origin != e.api {
			request.Header.Set("X-CSRF-Token", admin.csrf)
		}
		response, err := admin.client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatal("registry-label mutation bypassed CSRF or Origin checks")
		}
	}
	e.browserRequest(admin, "PATCH", path, change, 200)
	// Two browser tabs editing the same snapshot cannot silently overwrite.
	e.browserRequest(admin, "PATCH", path, map[string]any{
		"labels": map[string]string{"region": "ap"}, "expected_labels": old, "reason": "Stale browser tab",
	}, 409)
	registered, err := db.Cluster(t.Context(), "labels-first")
	if err != nil || !maps.Equal(registered.Labels, replacement) || registered.Maintenance || registered.ControllerSession != booked.ID {
		t.Fatal("label edit changed unrelated registry or reservation state", err)
	}
	profile, err := db.Profile(t.Context(), alice.user)
	if err != nil || profile.PrimarySession == nil || profile.PrimarySession.ID != booked.ID || profile.ActiveBookings != 1 {
		t.Fatal("label edit replaced or released the existing primary", err)
	}
	var afterCipher, afterDigest []byte
	var afterExpiry time.Time
	if err = db.Pool.QueryRow(t.Context(), "SELECT kubeconfig_ciphertext FROM clusters WHERE id='labels-first'").Scan(&afterCipher); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(t.Context(), "SELECT token_digest,expires_at FROM personal_access_tokens WHERE id=$1", issued.PAT.ID).Scan(&afterDigest, &afterExpiry); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeCipher, afterCipher) || !bytes.Equal(beforeDigest, afterDigest) || !beforeExpiry.Equal(afterExpiry) {
		t.Fatal("label mutation changed a Kubernetes credential, PAT or its expiry")
	}
	requests := func() int {
		first.mu.Lock()
		a := len(first.Requests)
		first.mu.Unlock()
		second.mu.Lock()
		b := len(second.Requests)
		second.mu.Unlock()
		return a + b
	}
	if requests() != 0 {
		t.Fatal("label administration contacted Kubernetes")
	}
	version := func(want int, expected string) {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, e.api+"/k8s/version", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+secret)
		response, err := e.gatewayClient().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != want || !strings.Contains(string(body), expected) {
			t.Fatalf("gateway result differs: got status%d, expected%d (response withheld)", response.StatusCode, want)
		}
	}
	// Existing primaries beat the PAT selector, even after labels stop matching.
	version(200, "v1.35.1-label-first")
	e.browserRequest(alice, "POST", "/v1/sessions/"+booked.ID+"/stop", nil, 200)
	version(http.StatusForbidden, "no matching available cluster")
	beforeUpdateCalls := requests()
	e.browserRequest(admin, "PATCH", "/v1/admin/clusters/labels-second", map[string]any{
		"labels": map[string]string{"region": "eu"}, "expected_labels": map[string]string{"region": "us"}, "reason": "Make another environment eligible for future automatic booking",
	}, 200)
	if requests() != beforeUpdateCalls {
		t.Fatal("changing future placement labels contacted Kubernetes")
	}
	version(200, "v1.35.1-label-second")
	profile, err = db.Profile(t.Context(), alice.user)
	if err != nil || profile.PrimarySession == nil || profile.PrimarySession.Cluster != "labels-second" {
		t.Fatal("same PAT did not use updated registry labels at its next allocation", err)
	}
	e.stop()
	e.start()
	if after, err := db.Cluster(t.Context(), "labels-first"); err != nil || !maps.Equal(after.Labels, replacement) {
		t.Fatal("label edit did not persist across restart", err)
	}
	e.browserRequest(admin, "GET", "/v1/admin/audit?limit=100", nil, 200)
	t.Log("real Keycloak browser admin/developer roles, CSRF, stale-edit protection, stable credentials/bookings and future PAT placement use edited registry labels; no remote cluster contacted")
}
