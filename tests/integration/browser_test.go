package integration

import (
	"bytes"
	"encoding/base64"
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
	req.Header.Set("Idempotency-Key", "browser-test-"+b.user.Subject+path)
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
	upstream := newKubernetesFixture(t)
	e.browserRequest(admin, "POST", "/v1/admin/clusters", map[string]any{"id": "web-fixture", "name": "Browser fixture", "labels": map[string]string{"test": "browser"}, "kubeconfig": upstream.kubeconfig()}, 200)
	booked := session(t, e.browserRequest(alice, "POST", "/v1/sessions", model.Booking{Cluster: "web-fixture"}, 201))
	e.browserRequest(bob, "POST", "/v1/sessions", model.Booking{Cluster: "web-fixture"}, 409)
	e.browserRequest(alice, "POST", "/v1/sessions/"+booked.ID+"/share", map[string]bool{"shareable": true}, 200)
	second := session(t, e.browserRequest(bob, "POST", "/v1/sessions", model.Booking{Cluster: "web-fixture"}, 201))
	e.browserRequest(bob, "POST", "/v1/pats", map[string]string{"session_id": booked.ID, "name": "forbidden"}, 403)
	var issued struct {
		PAT        store.PAT `json:"pat"`
		Kubeconfig string    `json:"kubeconfig"`
	}
	if err = json.Unmarshal(e.browserRequest(alice, "POST", "/v1/pats", map[string]string{"session_id": booked.ID, "name": "Browser laptop", "ttl": "1h"}, 201), &issued); err != nil {
		t.Fatal(err)
	}
	cfg, err := clientcmd.Load([]byte(issued.Kubeconfig))
	if err != nil {
		t.Fatal("invalid downloaded kubeconfig")
	}
	if len(cfg.AuthInfos) != 1 || cfg.AuthInfos["devctl-personal-access"].Exec != nil || !strings.HasPrefix(cfg.AuthInfos["devctl-personal-access"].Token, "dcpat_") {
		t.Fatal("download requires helper or missing PAT")
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
	command := func() error {
		cmd := exec.Command(kubectl, "--cache-dir", filepath.Join(dir, "cache"), "--kubeconfig", configPath, "get", "pod", "example", "-n", "default", "-o", "name")
		cmd.Env = []string{"PATH=" + dir, "KUBECONFIG=" + configPath}
		output, err := cmd.CombinedOutput()
		if err == nil && !strings.Contains(string(output), "pod/example") {
			t.Fatal("unexpected fixture result")
		}
		return err
	}
	if err = command(); err != nil {
		t.Fatalf("native kubectl browser config failed: %v", err)
	}
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
	e.browserRequest(alice, "POST", "/auth/logout", nil, 200)
	e.browserRequest(alice, "GET", "/web/session", nil, 401)
	t.Log("browser administrator registration/maintenance/audit/release/revocation and logout passed; no remote cluster touched")
}
