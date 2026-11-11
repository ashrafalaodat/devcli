package integration

import (
	"bufio"
	"bytes"
	"context"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/testutil"
	"encoding/base64"
	"encoding/json"
	"errors"
	"golang.org/x/net/html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This is a real Keycloak Authorization Code + PKCE flow. The test fills Keycloak's
// browser login form over HTTP; it never uses the password grant or fake API tokens.
// Upstream Kubernetes HTTP behavior is exercised against a disposable TLS fixture, never a remote cluster.
type environment struct {
	t                         *testing.T
	root, api, issuer, dsn    string
	backend                   *exec.Cmd
	log                       bytes.Buffer
	key                       string
	certFile, keyFile, caFile string
}

func (e *environment) start() {
	e.t.Helper()
	e.backend = exec.Command(filepath.Join(e.root, "bin/devctld"))
	e.backend.Env = append(os.Environ(), "DATABASE_URL="+e.dsn, "DEVCTL_LISTEN="+strings.TrimPrefix(strings.TrimPrefix(e.api, "http://"), "https://"), "DEVCTL_ISSUER="+e.issuer, "DEVCTL_MASTER_KEY="+e.key, "DEVCTL_DEV_HTTP=1", "DEVCTL_PUBLIC_URL="+e.api, "DEVCTL_TLS_CERT="+e.certFile, "DEVCTL_TLS_KEY="+e.keyFile, "DEVCTL_GATEWAY_CA_FILE="+e.caFile)
	e.backend.Stdout = &e.log
	e.backend.Stderr = &e.log
	if err := e.backend.Start(); err != nil {
		e.t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	client := e.gatewayClient()
	for time.Now().Before(deadline) {
		r, err := client.Get(e.api + "/readyz")
		if err == nil {
			r.Body.Close()
			if r.StatusCode == 200 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	e.stop()
	e.t.Fatalf("backend did not start: %s", e.log.String())
}
func (e *environment) stop() {
	if e.backend != nil && e.backend.Process != nil {
		e.backend.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- e.backend.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			e.backend.Process.Kill()
			<-done
		}
		e.backend = nil
	}
}
func (e *environment) command(dir string, args ...string) *exec.Cmd {
	cmd := exec.Command(filepath.Join(e.root, "bin/devctl"), args...)
	cmd.Env = append(os.Environ(), "DEVCTL_API="+e.api, "DEVCTL_ISSUER="+e.issuer, "DEVCTL_CONFIG_DIR="+dir, "DEVCTL_DEV_HTTP=1", "DEVCTL_DEV_TOKEN_FILE=1", "DEVCTL_NO_BROWSER=1", "DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent-devctl-e2e", "DEVCTL_API_CA_FILE="+e.caFile)
	return cmd
}
func (e *environment) run(dir string, args ...string) []byte {
	e.t.Helper()
	cmd := e.command(dir, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		e.t.Fatalf("devctl %v failed: %v %s", args, err, stderr.String())
	}
	return raw
}
func (e *environment) reject(dir string, code int, args ...string) {
	e.t.Helper()
	cmd := e.command(dir, args...)
	raw, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != code {
		e.t.Fatalf("devctl %v: expected exit %d, got %v %s", args, code, err, raw)
	}
}
func formAction(n *html.Node) string {
	if n.Type == html.ElementNode && n.Data == "form" {
		id, action := "", ""
		for _, a := range n.Attr {
			if a.Key == "id" {
				id = a.Val
			}
			if a.Key == "action" {
				action = a.Val
			}
		}
		if id == "kc-form-login" {
			return action
		}
	}
	for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
		if s := formAction(ch); s != "" {
			return s
		}
	}
	return ""
}
func (e *environment) login(dir, username string, approved bool) {
	e.t.Helper()
	cmd := e.command(dir, "login")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		e.t.Fatal(err)
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err = cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	finished := false
	defer func() {
		if !finished {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	authURL := make(chan string, 1)
	scannerDone := make(chan struct{})
	var diagnostics bytes.Buffer
	go func() {
		defer close(scannerDone)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "http") {
				diagnostics.WriteString(line + "\n")
			}
			if strings.HasPrefix(line, e.issuer+"/protocol/openid-connect/auth?") {
				select {
				case authURL <- line:
				default:
				}
			}
		}
	}()
	var address string
	select {
	case address = <-authURL:
	case <-time.After(20 * time.Second):
		e.t.Fatal("login did not publish authorization URL")
	}
	u, err := url.Parse(address)
	if err != nil {
		e.t.Fatal(err)
	}
	if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("nonce") == "" || u.Query().Get("state") == "" {
		e.t.Fatal("PKCE/state/nonce missing")
	}
	// A forged callback must not complete or poison a valid login.
	r, err := http.Get("http://127.0.0.1:18000/callback?state=forged&code=forged")
	if err != nil {
		e.t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 400 {
		e.t.Fatal("invalid state accepted")
	}
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Timeout: 20 * time.Second}
	r, err = browser.Get(address)
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
		e.t.Fatal("Keycloak login form not found (realm may still be starting)")
	}
	r, err = browser.PostForm(action, url.Values{"username": {username}, "password": {username + "-dev-only"}, "credentialId": {""}})
	if err != nil {
		e.t.Fatal(err)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	err = cmd.Wait()
	<-scannerDone
	finished = true
	if approved && err != nil {
		e.stop()
		e.t.Fatalf("OIDC login failed for %s: %v %s backend: %s", username, err, diagnostics.String(), e.log.String())
	}
	if !approved && err == nil {
		e.t.Fatal("unapproved user logged in")
	}
	if approved {
		var u model.Identity
		if err = json.Unmarshal(stdout.Bytes(), &u); err != nil || u.Name != username {
			e.t.Fatalf("wrong identity %v", err)
		}
	}
}
func session(t *testing.T, raw []byte) model.Session {
	t.Helper()
	var s model.Session
	if e := json.Unmarshal(raw, &s); e != nil || s.ID == "" {
		t.Fatalf("invalid session response: %v", e)
	}
	return s
}

func TestEndToEnd(t *testing.T) {
	issuer := os.Getenv("DEVCTL_TEST_ISSUER")
	if issuer == "" {
		t.Skip("set DEVCTL_TEST_ISSUER and DEVCTL_TEST_DATABASE_URL; run make demo-test")
	}
	database, dsn := testutil.Database(t)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	env := &environment{t: t, root: root, api: "https://" + address, issuer: issuer, dsn: dsn, key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))}
	configureGatewayTLS(t, env)
	env.start()
	defer env.stop()
	admin, alice, bob, outsider := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	env.login(admin, "admin", true)
	env.login(alice, "alice", true)
	env.login(bob, "bob", true)
	env.login(outsider, "outsider", false)
	t.Log("real Keycloak code flow, PKCE, nonce, state rejection, and group authorization passed")
	upstream := newKubernetesFixture(t)
	config := filepath.Join(t.TempDir(), "fixture.yaml")
	if err = os.WriteFile(config, []byte(upstream.kubeconfig()), 0600); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"alpha", "beta"} {
		env.run(admin, "admin", "register", "--id", id, "--name", strings.Title(id), "--kubeconfig", config, "--label", "region=local")
	}

	var ciphertext []byte
	if err = database.Pool.QueryRow(context.Background(), "SELECT kubeconfig_ciphertext FROM clusters WHERE id='alpha'").Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("inert-demo-token")) || bytes.Contains(ciphertext, []byte("apiVersion")) {
		t.Fatal("plaintext config stored in database")
	}
	env.reject(alice, 3, "admin", "register", "--id", "forbidden", "--name", "Forbidden", "--kubeconfig", config)
	a := session(t, env.run(alice, "start", "--cluster", "alpha", "--idempotency-key", "alice-alpha"))
	retry := session(t, env.run(alice, "start", "--cluster", "alpha", "--idempotency-key", "alice-alpha"))
	if a.ID != retry.ID {
		t.Fatal("idempotency failed")
	}
	env.reject(bob, 4, "start", "--cluster", "alpha")
	b := session(t, env.run(bob, "start", "--selector", "region=local"))
	if b.Cluster != "beta" {
		t.Fatal("automatic fallback failed")
	}
	env.reject(alice, 4, "start", "--idempotency-key", "full")
	env.reject(bob, 3, "share", a.ID)
	env.run(bob, "stop", b.ID)
	env.run(alice, "share", a.ID)
	b = session(t, env.run(bob, "start", "--cluster", "alpha"))
	env.reject(bob, 4, "share", b.ID, "--off")
	raw := env.run(bob, "status", b.ID, "--json")
	var detail struct {
		Cluster model.Cluster `json:"cluster"`
	}
	if err = json.Unmarshal(raw, &detail); err != nil || len(detail.Cluster.Participants) != 2 {
		t.Fatal("co-user visibility failed", err)
	}
	if detail.Cluster.Participants[0].DisplayName == "" || detail.Cluster.Participants[0].Email == "" {
		t.Fatal("co-user contact missing")
	}
	path := strings.TrimSpace(string(env.run(alice, "kubeconfig")))
	if strings.Contains(path, "\n") {
		t.Fatal("kubeconfig stdout polluted")
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("gateway kubeconfig delivery failed", err)
	}
	if bytes.Contains(saved, []byte(upstreamToken)) || bytes.Contains(saved, []byte(upstream.Server.URL)) || bytes.Contains(saved, []byte("client-key-data")) || !bytes.Contains(saved, []byte("exec:")) || !bytes.Contains(saved, []byte(env.api+"/k8s")) {
		t.Fatal("generated kubeconfig must contain only gateway metadata and the exec plugin")
	}
	aliceGatewayToken := pluginToken(t, env.run(alice, "credential"))
	bobGatewayToken := pluginToken(t, env.run(bob, "credential"))
	if output := runKubectl(t, path, "get", "--raw=/version"); !bytes.Contains(output, []byte("v1.35.1-fixture")) {
		t.Fatal("kubectl version response not forwarded")
	}
	// A new ordinary shell inherits the selected config through the installed-style
	// initialization snippet; no per-command KUBECONFIG argument is required.
	env.run(alice, "select", a.ID)
	shellSetup := env.run(alice, "shell", "init", "--shell", "bash")
	shellContext, shellCancel := context.WithTimeout(context.Background(), 15*time.Second)
	shellCmd := exec.CommandContext(shellContext, "bash", "--noprofile", "--norc", "-c", string(shellSetup)+"\nkubectl --request-timeout=10s get --raw=/version")
	shellCmd.Env = env.command(alice).Env
	shellOutput, shellErr := shellCmd.CombinedOutput()
	shellCancel()
	if shellErr != nil || !bytes.Contains(shellOutput, []byte("v1.35.1-fixture")) {
		t.Fatalf("new shell did not use global active selection: %v %s", shellErr, shellOutput)
	}

	manifest := filepath.Join(t.TempDir(), "configmap.yaml")
	if err = os.WriteFile(manifest, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: gateway-test\n  namespace: default\ndata:\n  message: gateway apply works\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runKubectl(t, path, "apply", "--server-side", "--validate=false", "-f", manifest)
	if output := runKubectl(t, path, "logs", "example"); !bytes.Contains(output, []byte("gateway fixture log line")) {
		t.Fatal("kubectl logs not forwarded")
	}
	if output := runKubectl(t, path, "exec", "example", "--", "echo", "fixture"); !bytes.Contains(output, []byte("gateway fixture exec output")) {
		t.Fatal("kubectl exec WebSocket streams not forwarded")
	}
	runKubectlPortForward(t, path)

	if output := runKubectl(t, path, "get", "--raw=/api/v1/namespaces/default/pods?watch=true&timeoutSeconds=1"); !bytes.Contains(output, []byte("ADDED")) {
		t.Fatal("watch stream not forwarded")
	}
	for _, request := range []apiRequest{{Method: "PATCH", Path: "/api/v1/namespaces/default/configmaps/gateway-test"}, {Method: "GET", Path: "/api/v1/namespaces/default/pods/example/log"}, {Method: "GET", Path: "/api/v1/namespaces/default/pods", Watch: true}} {
		if !upstream.saw(request.Method, request.Path, request.Watch) {
			t.Fatal("expected Kubernetes request did not reach the upstream fixture", request.Method, request.Path)
		}
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("kubeconfig not private")
	}
	child := strings.TrimSpace(string(env.run(alice, "exec", "--", "sh", "-c", "printf '%s' \"$KUBECONFIG\"")))
	if child != path {
		t.Fatal("exec did not set session KUBECONFIG")
	}
	// Persisted access token is deliberately marked expired to exercise refresh.
	files, _ := filepath.Glob(filepath.Join(alice, "*", "tokens.json"))
	if len(files) != 1 {
		t.Fatal("explicit development fallback missing")
	}
	tokenJSON, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var token map[string]any
	json.Unmarshal(tokenJSON, &token)
	oldAccess, _ := token["access_token"].(string)
	token["expiry"] = time.Now().Add(-time.Hour).Format(time.RFC3339Nano)
	tokenJSON, _ = json.Marshal(token)
	os.WriteFile(files[0], tokenJSON, 0600)
	env.run(alice, "whoami")
	tokenJSON, _ = os.ReadFile(files[0])
	json.Unmarshal(tokenJSON, &token)
	if token["access_token"] == oldAccess {
		t.Fatal("refresh did not update access token")
	}
	env.stop()
	env.start()
	env.run(alice, "wait", a.ID)
	env.run(bob, "wait", b.ID)

	// Retain only the refresh value in memory to verify provider revocation after logout.
	var freshToken map[string]any
	tokenJSON, _ = os.ReadFile(files[0])
	json.Unmarshal(tokenJSON, &freshToken)
	refresh, _ := freshToken["refresh_token"].(string)
	env.run(alice, "logout")
	assertGatewayDenied(t, env.gatewayClient(), env.api+"/k8s"+"/version", aliceGatewayToken)
	revoked, err := http.PostForm(issuer+"/protocol/openid-connect/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"devctl-cli"}, "refresh_token": {refresh}})
	if err != nil {
		t.Fatal(err)
	}
	revoked.Body.Close()
	if revoked.StatusCode != 400 {
		t.Fatal("logout did not revoke the provider refresh token", revoked.StatusCode)
	}
	env.reject(alice, 3, "whoami")
	env.login(alice, "alice", true)
	raw = env.run(bob, "status", b.ID, "--json")
	json.Unmarshal(raw, &detail)
	if detail.Cluster.ControllerSession != b.ID || detail.Cluster.Shareable {
		t.Fatal("controller promotion after logout failed")
	}
	env.run(bob, "share", b.ID)
	env.run(bob, "stop", b.ID)
	assertGatewayDenied(t, env.gatewayClient(), env.api+"/k8s/version", bobGatewayToken)
	// The previously generated file is harmless without an active booking.
	if bytes.Contains(saved, []byte(upstreamToken)) {
		t.Fatal("upstream secret escaped into local metadata")
	}
	t.Log("exclusive conflicts, sharing consent, gateway ownership, secret-free config, real kubectl apply/logs/exec/port-forward/watch, child environment, refresh, logout, and restart passed")
	// Inactivity release is enforced server-side without a running CLI.
	exp := session(t, env.run(alice, "start", "--cluster", "alpha"))
	expiryToken := pluginToken(t, env.run(alice, "credential"))
	if _, err = database.Pool.Exec(context.Background(), "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", exp.ID); err != nil {
		t.Fatal(err)
	}

	// Observe the database directly, without calling the API, to prove the background
	// worker expires a reservation while the CLI is closed.
	deadline := time.Now().Add(8 * time.Second)
	var expiredState string
	for time.Now().Before(deadline) {
		if err = database.Pool.QueryRow(context.Background(), "SELECT state FROM sessions WHERE id=$1", exp.ID).Scan(&expiredState); err != nil {
			t.Fatal(err)
		}
		if expiredState == "EXPIRED" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if expiredState != "EXPIRED" {
		t.Fatal("background expiry did not run")
	}
	assertGatewayDenied(t, env.gatewayClient(), env.api+"/k8s/version", expiryToken)
	env.run(alice, "logout")
	env.run(bob, "logout")
	env.run(admin, "logout")
}
