package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
	"golang.org/x/net/html"
	"k8s.io/client-go/tools/clientcmd"
)

type browserSession struct {
	client *http.Client
	csrf   string
	user   model.Identity
}

func (e *environment) browserLogin(username string, approved bool) *browserSession {
	e.t.Helper()
	c := e.gatewayClient()
	c.Timeout = 20 * time.Second
	c.Jar, _ = cookiejar.New(nil)
	r, err := c.Get(e.api + "/auth/login")
	if err != nil {
		e.t.Fatal(err)
	}
	doc, err := html.Parse(r.Body)
	r.Body.Close()
	if err != nil {
		e.t.Fatal(err)
	}
	action := formAction(doc)
	if action == "" {
		e.t.Fatal("web SSO did not reach the Keycloak login form; approve the web callback URI in the test client")
	}
	r, err = c.PostForm(action, url.Values{"username": {username}, "password": {username + "-dev-only"}, "credentialId": {""}})
	if err != nil {
		e.t.Fatal(err)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if !approved {
		if r.StatusCode != 403 {
			e.t.Fatalf("unapproved browser returned %d", r.StatusCode)
		}
		return &browserSession{client: c}
	}
	if r.StatusCode != 200 {
		e.t.Fatalf("web SSO callback returned %d", r.StatusCode)
	}
	r, err = c.Get(e.api + "/web/session")
	if err != nil {
		e.t.Fatal(err)
	}
	defer r.Body.Close()
	var metadata struct {
		User model.Identity `json:"user"`
		CSRF string         `json:"csrf_token"`
	}
	if r.StatusCode != 200 || json.NewDecoder(r.Body).Decode(&metadata) != nil || metadata.User.Name != username || metadata.CSRF == "" {
		e.t.Fatal("browser session not established")
	}
	origin, _ := url.Parse(e.api)
	for _, cookie := range c.Jar.Cookies(origin) {
		if strings.Contains(cookie.Name, "devctl") && (strings.Contains(cookie.Value, "eyJ") || len(cookie.Value) != 43) {
			e.t.Fatal("OAuth token or malformed cookie exposed to browser")
		}
	}
	return &browserSession{client: c, csrf: metadata.CSRF, user: metadata.User}
}

func (e *environment) browserRequest(b *browserSession, method, path string, body any, want int) []byte {
	e.t.Helper()
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	req, err := http.NewRequest(method, e.api+path, bytes.NewReader(data))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", b.csrf)
	req.Header.Set("Origin", e.api)
	requestHash := sha256.Sum256(append([]byte(b.user.Subject+path), data...))
	req.Header.Set("Idempotency-Key", "browser-test-"+hex.EncodeToString(requestHash[:]))
	resp, err := b.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		e.t.Fatalf("browser %s %s: got %d want %d (body withheld to avoid credential disclosure)", method, path, resp.StatusCode, want)
	}
	return raw
}

// Uses real Keycloak code/PKCE login and stock kubectl with no installed helper.
// Registration points only at a disposable TLS Kubernetes fixture.
func TestBrowserAccess(t *testing.T) {
	api := os.Getenv("DEVCTL_TEST_WEB_URL")
	issuer := os.Getenv("DEVCTL_TEST_ISSUER")
	if api == "" || issuer == "" {
		t.Skip("set DEVCTL_TEST_WEB_URL and DEVCTL_TEST_ISSUER with an approved devctl-web callback")
	}
	db, dsn := testutil.Database(t)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	e := &environment{t: t, root: root, api: api, issuer: issuer, dsn: dsn, key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{64}, 32))}
	configureGatewayTLS(t, e)
	e.start()
	defer e.stop()
	admin := e.browserLogin("admin", true)
	alice := e.browserLogin("alice", true)
	bob := e.browserLogin("bob", true)
	e.browserLogin("outsider", false)
	t.Log("real browser code flow, approved groups, state/nonce/PKCE and encrypted server-side sessions established")
	upstream := newKubernetesFixtureVersion(t, "v1.35.1-browser-a")
	otherUpstream := newKubernetesFixtureVersion(t, "v1.36.0-browser-b")
	for _, registration := range []struct{ id, name, config string }{
		{"web-fixture", "Browser fixture A", upstream.kubeconfig()},
		{"web-other", "Browser fixture B", otherUpstream.kubeconfig()},
	} {
		e.browserRequest(admin, "POST", "/v1/admin/clusters", map[string]any{"id": registration.id, "name": registration.name, "labels": map[string]string{"test": "browser"}, "kubeconfig": registration.config}, 200)
	}
	var settings model.Settings
	if err = json.Unmarshal(e.browserRequest(admin, "GET", "/v1/admin/settings", nil, 200), &settings); err != nil || settings.DefaultMaxBookings != 1 {
		t.Fatal("default developer limit is not one")
	}
	// Download once, before any reservation. The PAT authenticates its developer,
	// and the fixed gateway URL obtains that developer's current primary later.
	var issued struct {
		PAT        store.PAT `json:"pat"`
		Kubeconfig string    `json:"kubeconfig"`
	}
	if err = json.Unmarshal(e.browserRequest(alice, "POST", "/v1/pats", map[string]string{"name": "Browser laptop", "ttl": "1h"}, 201), &issued); err != nil {
		t.Fatal(err)
	}
	cfg, err := clientcmd.Load([]byte(issued.Kubeconfig))
	if err != nil {
		t.Fatal("invalid downloaded kubeconfig")
	}
	if len(cfg.AuthInfos) != 1 || cfg.AuthInfos["devctl-personal-access"].Exec != nil || !strings.HasPrefix(cfg.AuthInfos["devctl-personal-access"].Token, "dcpat_") {
		t.Fatal("download requires helper or missing PAT")
	}
	if cfg.Clusters["devctl-gateway"].Server != e.api+"/k8s" || issued.PAT.Scope != "kubernetes:primary" {
		t.Fatal("download contains old session routing")
	}
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Fatal("kubectl required for browser integration")
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.yaml")
	if err = os.WriteFile(configPath, []byte(issued.Kubeconfig), 0600); err != nil {
		t.Fatal(err)
	}
	version := func() (string, error) {
		cmd := exec.Command(kubectl, "--cache-dir", filepath.Join(dir, "cache"), "--kubeconfig", configPath, "get", "--raw=/version", "--request-timeout=5s")
		cmd.Env = []string{"PATH=" + dir, "KUBECONFIG=" + configPath}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	expectVersion := func(want string) {
		t.Helper()
		out, err := version()
		if err != nil || !strings.Contains(out, want) {
			t.Fatalf("native kubectl did not reach expected primary %s (response withheld)", want)
		}
	}
	expectNoBooking := func() {
		t.Helper()
		out, err := version()
		if err == nil || !strings.Contains(out, "no cluster is booked") {
			t.Fatal("native kubectl did not return clear no-booking error")
		}
	}
	expectNoBooking()
	booked := session(t, e.browserRequest(alice, "POST", "/v1/sessions", model.Booking{Cluster: "web-fixture"}, 201))
	if !booked.Primary {
		t.Fatal("first browser booking did not become primary")
	}
	expectVersion("v1.35.1-browser-a")
	e.browserRequest(alice, "POST", "/v1/sessions", model.Booking{Cluster: "web-other"}, 409)
	// Exercise both organisation defaults and the administrator's per-developer
	// override. Alice retains two slots while Bob inherits the default of one.
	e.browserRequest(admin, "PATCH", "/v1/admin/settings", map[string]any{"default_max_bookings": 2, "reason": "browser integration default"}, 200)
	e.browserRequest(admin, "PATCH", "/v1/admin/developers/"+alice.user.Key(), map[string]any{"max_bookings": 2, "reason": "Alice may hold two integration clusters"}, 200)
	e.browserRequest(admin, "PATCH", "/v1/admin/settings", map[string]any{"default_max_bookings": 1, "reason": "restore organisation default"}, 200)
	additional := session(t, e.browserRequest(alice, "POST", "/v1/sessions", model.Booking{Cluster: "web-other"}, 201))
	if additional.Primary {
		t.Fatal("second browser booking replaced primary")
	}
	expectVersion("v1.35.1-browser-a")
	e.browserRequest(alice, "POST", "/v1/primary", map[string]string{"cluster": "web-other"}, 200)
	expectVersion("v1.36.0-browser-b")
	e.browserRequest(alice, "POST", "/v1/primary", map[string]string{"cluster": booked.ID}, 200)
	expectVersion("v1.35.1-browser-a")
	e.browserRequest(bob, "POST", "/v1/primary", map[string]string{"cluster": additional.ID}, 403)
	e.browserRequest(bob, "POST", "/v1/sessions", model.Booking{Cluster: "web-fixture"}, 409)
	e.browserRequest(alice, "POST", "/v1/sessions/"+booked.ID+"/share", map[string]bool{"shareable": true}, 200)
	second := session(t, e.browserRequest(bob, "POST", "/v1/sessions", model.Booking{Cluster: "web-fixture"}, 201))
	e.browserRequest(bob, "POST", "/v1/pats", map[string]string{"session_id": booked.ID, "name": "old session scope rejected"}, 400)
	// Reducing a limit leaves existing bookings and selection intact.
	e.browserRequest(admin, "PATCH", "/v1/admin/developers/"+alice.user.Key(), map[string]any{"max_bookings": 1, "reason": "reduce future holdings without eviction"}, 200)
	var profile model.DeveloperProfile
	if err = json.Unmarshal(e.browserRequest(alice, "GET", "/v1/profile", nil, 200), &profile); err != nil || profile.ActiveBookings != 2 || profile.MaxBookings != 1 || profile.PrimarySession.ID != booked.ID {
		t.Fatal("limit reduction evicted or changed primary")
	}
	e.browserRequest(alice, "POST", "/v1/sessions/"+booked.ID+"/stop", nil, 200)
	expectVersion("v1.36.0-browser-b")
	e.browserRequest(alice, "POST", "/v1/sessions/"+additional.ID+"/stop", nil, 200)
	expectNoBooking()
	// An explicit new booking restores access with the exact same saved token.
	restored := session(t, e.browserRequest(alice, "POST", "/v1/sessions", model.Booking{Cluster: "web-other", TTL: "1h"}, 201))
	if !restored.Primary {
		t.Fatal("new booking after release did not become primary")
	}
	expectVersion("v1.36.0-browser-b")
	savedConfig, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(savedConfig, []byte(issued.Kubeconfig)) {
		t.Fatal("primary switching rewrote downloaded kubeconfig")
	}
	command := func() error {
		cmd := exec.Command(kubectl, "--cache-dir", filepath.Join(dir, "cache"), "--kubeconfig", configPath, "get", "pod", "example", "-n", "default", "-o", "name")
		cmd.Env = []string{"PATH=" + dir, "KUBECONFIG=" + configPath}
		out, err := cmd.CombinedOutput()
		if err == nil && !strings.Contains(string(out), "pod/example") {
			t.Fatal("unexpected fixture result")
		}
		return err
	}
	if err = command(); err != nil {
		t.Fatal("native kubectl browser config failed")
	}
	t.Log("one PAT/config, clear no-booking errors, default/per-user limits, primary switching across two TLS fixtures, sharing and release/rebooking passed")
	e.stop()
	e.start()
	e.browserRequest(alice, "GET", "/web/session", nil, 200)
	if err = command(); err != nil {
		t.Fatal("PAT did not survive restart")
	}
	// Force only encrypted OAuth access expiry. Concurrent browser requests must
	// safely rotate one refresh token and persist it for the next request.
	vault, _ := kube.NewVault(bytes.Repeat([]byte{64}, 32))
	var id string
	var encrypted []byte
	if err = db.Pool.QueryRow(t.Context(), "SELECT id_hash,payload_ciphertext FROM web_sessions WHERE owner_id=$1", alice.user.Key()).Scan(&id, &encrypted); err != nil {
		t.Fatal(err)
	}
	raw, err := vault.Open("web-session:"+id, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]json.RawMessage
	if json.Unmarshal(raw, &saved) != nil {
		t.Fatal("invalid test session")
	}
	var token map[string]any
	if json.Unmarshal(saved["token"], &token) != nil {
		t.Fatal("invalid test token")
	}
	oldAccess := token["access_token"]
	oldRefresh := token["refresh_token"]
	token["expiry"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	saved["token"], _ = json.Marshal(token)
	raw, _ = json.Marshal(saved)
	encrypted, _ = vault.Seal("web-session:"+id, raw)
	if _, err = db.Pool.Exec(t.Context(), "UPDATE web_sessions SET payload_ciphertext=$2 WHERE id_hash=$1", id, encrypted); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := alice.client.Get(e.api + "/web/session")
			if err == nil {
				r.Body.Close()
				if r.StatusCode != 200 {
					err = io.ErrUnexpectedEOF
				}
			}
			failures <- err
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal("concurrent browser refresh failed")
		}
	}
	if err = db.Pool.QueryRow(t.Context(), "SELECT payload_ciphertext FROM web_sessions WHERE id_hash=$1", id).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	raw, _ = vault.Open("web-session:"+id, encrypted)
	_ = json.Unmarshal(raw, &saved)
	_ = json.Unmarshal(saved["token"], &token)
	if token["access_token"] == oldAccess || token["refresh_token"] == oldRefresh {
		t.Fatal("browser access and refresh tokens were not rotated")
	}
	t.Log("stock kubectl without helper, backend restart, and concurrent real OIDC refresh rotation passed")
	e.browserRequest(alice, "PATCH", "/v1/admin/clusters/web-fixture", map[string]any{"maintenance": true, "reason": "not admin"}, 403)
	e.browserRequest(admin, "PATCH", "/v1/admin/clusters/web-fixture", map[string]any{"maintenance": true, "reason": "browser integration maintenance"}, 200)
	e.browserRequest(admin, "GET", "/v1/admin/audit?limit=20", nil, 200)
	e.browserRequest(admin, "DELETE", "/v1/pats/"+issued.PAT.ID, map[string]string{"reason": "browser integration revocation"}, 200)
	if err = command(); err == nil {
		t.Fatal("revoked browser PAT still works")
	}
	e.browserRequest(admin, "POST", "/v1/admin/sessions/"+second.ID+"/release", map[string]string{"reason": "browser integration release"}, 200)
	// A different, still-valid PAT must survive browser logout. Keep its exact
	// downloaded file so later access proves that neither reissuance nor another
	// download is required after the developer explicitly books again.
	var preserved struct {
		PAT        store.PAT `json:"pat"`
		Kubeconfig string    `json:"kubeconfig"`
	}
	if err = json.Unmarshal(e.browserRequest(alice, "POST", "/v1/pats", map[string]string{"name": "Preserved through logout", "ttl": "1h"}, 201), &preserved); err != nil {
		t.Fatal(err)
	}
	configPath = filepath.Join(dir, "logout-preserved.yaml")
	if err = os.WriteFile(configPath, []byte(preserved.Kubeconfig), 0600); err != nil {
		t.Fatal(err)
	}
	preservedConfig, err := clientcmd.Load([]byte(preserved.Kubeconfig))
	if err != nil {
		t.Fatal("invalid preserved kubeconfig")
	}
	preservedSecret := preservedConfig.AuthInfos["devctl-personal-access"].Token
	expectVersion("v1.36.0-browser-b")
	e.browserRequest(alice, "POST", "/auth/logout", nil, 200)
	e.browserRequest(alice, "GET", "/web/session", nil, 401)
	var revokedAt *time.Time
	var expiry time.Time
	if err = db.Pool.QueryRow(t.Context(), "SELECT revoked_at,expires_at FROM personal_access_tokens WHERE id=$1", preserved.PAT.ID).Scan(&revokedAt, &expiry); err != nil {
		t.Fatal(err)
	}
	if revokedAt != nil || !expiry.Equal(preserved.PAT.ExpiresAt) {
		t.Fatal("browser logout revoked the PAT or changed its expiry")
	}
	if _, err = db.VerifyPAT(t.Context(), preservedSecret); err != nil {
		t.Fatal("browser logout invalidated the retained PAT")
	}
	expectNoBooking()
	refresh, _ := token["refresh_token"].(string)
	if refresh == "" {
		t.Fatal("provider refresh token is missing from the test's encrypted session")
	}
	provider, err := e.gatewayClient().PostForm(issuer+"/protocol/openid-connect/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"devctl-web"}, "refresh_token": {refresh}})
	if err != nil {
		t.Fatal("cannot check provider refresh-token revocation")
	}
	provider.Body.Close()
	if provider.StatusCode != http.StatusBadRequest {
		t.Fatal("browser logout retained its provider refresh token", provider.StatusCode)
	}
	aliceAgain := e.browserLogin("alice", true)
	newBooking := session(t, e.browserRequest(aliceAgain, "POST", "/v1/sessions", model.Booking{Cluster: "web-other", TTL: "30m"}, 201))
	expectVersion("v1.36.0-browser-b")
	savedConfig, err = os.ReadFile(configPath)
	if err != nil || !bytes.Equal(savedConfig, []byte(preserved.Kubeconfig)) {
		t.Fatal("logout or rebooking changed the saved PAT config")
	}
	e.browserRequest(aliceAgain, "DELETE", "/v1/pats/"+preserved.PAT.ID, nil, 200)
	if _, err = version(); err == nil {
		t.Fatal("explicitly revoked preserved PAT still works")
	}
	e.browserRequest(aliceAgain, "POST", "/v1/sessions/"+newBooking.ID+"/stop", nil, 200)
	e.browserRequest(aliceAgain, "POST", "/auth/logout", nil, 200)
	if _, err = db.VerifyPAT(t.Context(), preservedSecret); err == nil {
		t.Fatal("later logout revived an explicitly revoked PAT")
	}
	t.Log("browser logout preserves PAT expiry and saved kubeconfig, ends bookings and OAuth login, and permits later explicit rebooking; explicit revocation still denies access")
	t.Log("browser administrator registration/maintenance/audit/release/revocation and logout passed; no remote cluster touched")
}
