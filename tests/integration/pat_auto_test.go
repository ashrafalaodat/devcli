package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
	"k8s.io/client-go/tools/clientcmd"
)

// Uses real local Keycloak code/PKCE login, the actual CLI, native kubectl with
// no helper on PATH, and two disposable HTTPS Kubernetes protocol fixtures.
func TestBrowserAutoBooking(t *testing.T) {
	api, issuer := os.Getenv("DEVCTL_TEST_WEB_URL"), os.Getenv("DEVCTL_TEST_ISSUER")
	if api == "" || issuer == "" {
		t.Skip("set DEVCTL_TEST_WEB_URL and DEVCTL_TEST_ISSUER with an approved browser callback")
	}
	db, dsn := testutil.Database(t)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	e := &environment{t: t, root: root, api: api, issuer: issuer, dsn: dsn, key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{87}, 32))}
	configureGatewayTLS(t, e)
	e.start()
	defer e.stop()
	admin, alice, bob := e.browserLogin("admin", true), e.browserLogin("alice", true), e.browserLogin("bob", true)
	for _, fixture := range []struct{ id, region, version string }{
		{"auto-eu", "eu", "v1.35.1-auto-eu"},
		{"auto-us", "us", "v1.35.1-auto-us"},
	} {
		upstream := newKubernetesFixtureVersion(t, fixture.version)
		e.browserRequest(admin, "POST", "/v1/admin/clusters", map[string]any{"id": fixture.id, "name": fixture.id, "labels": map[string]string{"region": fixture.region}, "kubeconfig": upstream.kubeconfig()}, 200)
	}
	var issued struct {
		PAT        store.PAT `json:"pat"`
		Kubeconfig string    `json:"kubeconfig"`
	}
	if json.Unmarshal(e.browserRequest(alice, "POST", "/v1/pats", map[string]any{
		"name": "automatic browser config", "ttl": "1h",
		"auto_booking": model.AutoBookingPolicy{Enabled: true, Selector: map[string]string{"region": "eu"}},
	}, 201), &issued) != nil || !issued.PAT.AutoBooking.Enabled {
		t.Fatal("browser did not persist opt-in preferences")
	}
	_, sessions, err := db.Snapshot(t.Context())
	if err != nil || len(sessions) != 0 {
		t.Fatal("creating a PAT booked a cluster", err)
	}
	config, err := clientcmd.Load([]byte(issued.Kubeconfig))
	if err != nil || config.AuthInfos["devctl-personal-access"].Exec != nil {
		t.Fatal("browser configuration needs an installed helper", err)
	}
	var beforeDigest []byte
	if err = db.Pool.QueryRow(t.Context(), "SELECT token_digest FROM personal_access_tokens WHERE id=$1", issued.PAT.ID).Scan(&beforeDigest); err != nil {
		t.Fatal(err)
	}
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "automatic.yaml")
	if err = os.WriteFile(path, []byte(issued.Kubeconfig), 0600); err != nil {
		t.Fatal(err)
	}
	version := func() (string, error) {
		command := exec.Command(kubectl, "--kubeconfig", path, "--request-timeout=10s", "get", "--raw=/version")
		command.Env = []string{"PATH=" + dir, "KUBECONFIG=" + path}
		output, err := command.CombinedOutput()
		return string(output), err
	}
	expectVersion := func(want string) {
		t.Helper()
		got, err := version()
		if err != nil || !strings.Contains(got, want) {
			t.Fatalf("native kubectl did not reach expected fixture %s (response withheld)", want)
		}
	}
	profile := func() model.DeveloperProfile {
		t.Helper()
		var out model.DeveloperProfile
		if json.Unmarshal(e.browserRequest(alice, "GET", "/v1/profile", nil, 200), &out) != nil {
			t.Fatal("invalid developer profile")
		}
		return out
	}
	expectVersion("v1.35.1-auto-eu")
	p := profile()
	if p.ActiveBookings != 1 || p.PrimarySession == nil || p.PrimarySession.Cluster != "auto-eu" {
		t.Fatal("first Kubernetes request did not book one matching primary")
	}
	patPath := "/v1/pats/" + issued.PAT.ID
	e.browserRequest(bob, "GET", patPath, nil, 403)
	e.browserRequest(bob, "PATCH", patPath, map[string]any{"auto_booking": model.AutoBookingPolicy{Enabled: true}}, 403)
	withoutCSRF, err := http.NewRequest("PATCH", e.api+patPath, strings.NewReader(`{"auto_booking":{"enabled":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	withoutCSRF.Header.Set("Origin", e.api)
	response, err := alice.client.Do(withoutCSRF)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("browser preference edit did not enforce CSRF")
	}

	// CLI editing preserves the omitted enabled flag and edits the same PAT; it
	// does not download or replace the existing native-kubectl config.
	cliAlice := t.TempDir()
	e.login(cliAlice, "alice", true)
	var updated store.PAT
	if json.Unmarshal(e.run(cliAlice, "token", "update", issued.PAT.ID, "--selector", "region=us"), &updated) != nil || !updated.AutoBooking.Enabled || updated.AutoBooking.Selector["region"] != "us" {
		t.Fatal("CLI edit did not preserve enabled automatic booking")
	}
	expectVersion("v1.35.1-auto-eu")
	e.browserRequest(alice, "POST", "/v1/sessions/"+p.PrimarySession.ID+"/stop", nil, 200)
	expectVersion("v1.35.1-auto-us")
	var afterDigest []byte
	if err = db.Pool.QueryRow(t.Context(), "SELECT token_digest FROM personal_access_tokens WHERE id=$1", issued.PAT.ID).Scan(&afterDigest); err != nil || !bytes.Equal(beforeDigest, afterDigest) || !updated.ExpiresAt.Equal(issued.PAT.ExpiresAt) {
		t.Fatal("preference edit changed the token or its expiry", err)
	}
	if saved, err := os.ReadFile(path); err != nil || !bytes.Equal(saved, []byte(issued.Kubeconfig)) {
		t.Fatal("editing preferences rewrote downloaded kubeconfig")
	}
	e.stop()
	e.start()
	expectVersion("v1.35.1-auto-us")
	p = profile()
	e.run(cliAlice, "token", "update", issued.PAT.ID, "--selector", "region=nowhere")
	e.browserRequest(alice, "POST", "/v1/sessions/"+p.PrimarySession.ID+"/stop", nil, 200)
	if got, err := version(); err == nil || !strings.Contains(got, "no matching available cluster for automatic booking") {
		t.Fatal("native kubectl did not show a useful no-match error")
	}
	e.run(cliAlice, "token", "update", issued.PAT.ID, "--auto-book=false")
	if got, err := version(); err == nil || !strings.Contains(got, "no cluster is booked") {
		t.Fatal("disabled fallback unexpectedly allocated")
	}
	e.browserRequest(alice, "PATCH", patPath, map[string]any{"auto_booking": model.AutoBookingPolicy{Enabled: true, Selector: map[string]string{"region": "eu"}}}, 200)
	// Concurrent actual kubectl processes all resolve one committed primary.
	var wg sync.WaitGroup
	failures := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := version()
			if err == nil && !strings.Contains(got, "v1.35.1-auto-eu") {
				err = fmt.Errorf("incorrect concurrent primary")
			}
			failures <- err
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal("concurrent native kubectl fallback failed (response withheld)")
		}
	}
	p = profile()
	if p.ActiveBookings != 1 || p.PrimarySession.Cluster != "auto-eu" {
		t.Fatal("concurrent first requests duplicated bookings")
	}
	firstID := p.PrimarySession.ID
	e.browserRequest(alice, "POST", "/auth/logout", nil, 200)
	expectVersion("v1.35.1-auto-eu")
	current, err := db.Profile(t.Context(), alice.user)
	if err != nil || current.PrimarySession == nil || current.PrimarySession.ID == firstID {
		t.Fatal("opted-in PAT did not remain able to rebook after logout", err)
	}
	e.run(cliAlice, "token", "update", issued.PAT.ID, "--auto-book=false")
	e.run(cliAlice, "stop", current.PrimarySession.ID)
	if got, err := version(); err == nil || !strings.Contains(got, "no cluster is booked") {
		t.Fatal("disabling preference did not stop future automatic allocation")
	}
	e.browserRequest(admin, "DELETE", patPath, map[string]string{"reason": "end automatic integration credential"}, 200)
	if _, err := version(); err == nil {
		t.Fatal("revoked automatic credential was accepted")
	}
	e.run(cliAlice, "logout")
	t.Log("real browser/CLI SSO, editable PAT policy, same native kubeconfig, exact labels, primary precedence, concurrency, restart, no-match/disabled errors, CSRF and explicit post-logout fallback passed")
}
