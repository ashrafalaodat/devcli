package integration

import (
	"bufio"
	"bytes"
	"context"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/testutil"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/net/html"
	"io"
	"k8s.io/client-go/tools/clientcmd"
	"net"
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
)

func primaryShellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func (e *environment) primaryKubectl(dir, config string, args ...string) []byte {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	options := []string{"--kubeconfig", config, "--cache-dir", filepath.Join(dir, "discovery-cache"), "--request-timeout=10s"}
	cmd := exec.CommandContext(ctx, "kubectl", append(options, args...)...)
	cmd.Env = e.command(dir).Env
	raw, err := cmd.CombinedOutput()
	if err != nil {
		e.t.Fatalf("automatic kubectl request failed: %v", err)
	}
	return raw
}

// Run real kubectl in a PTY, so client-go tells its credential helper that an
// interactive login is allowed. Only the development Keycloak HTML form is
// automated; no password grant or fabricated access token is used.
func (e *environment) firstPrimaryKubectl(dir, config, username string, wantSuccess bool) []byte {
	e.t.Helper()
	if _, err := exec.LookPath("script"); err != nil {
		e.t.Fatal("util-linux script is required for the interactive kubectl test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := strings.Join([]string{"kubectl", "--kubeconfig", primaryShellQuote(config), "--cache-dir", primaryShellQuote(filepath.Join(dir, "discovery-cache")), "--request-timeout=30s", "get", "pods", "-o", "json"}, " ")
	cmd := exec.CommandContext(ctx, "script", "-q", "-e", "-c", command, "/dev/null")
	cmd.Env = e.command(dir).Env
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		e.t.Fatal(err)
	}
	var scriptErrors bytes.Buffer
	cmd.Stderr = &scriptErrors
	if err = cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	finished := false
	defer func() {
		if !finished {
			cmd.Process.Signal(os.Interrupt)
			wait := make(chan error, 1)
			go func() { wait <- cmd.Wait() }()
			select {
			case <-wait:
			case <-time.After(3 * time.Second):
				cmd.Process.Kill()
				<-wait
			}
		}
	}()
	addresses := make(chan string, 1)
	done := make(chan struct{})
	var output bytes.Buffer
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(pipe)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, e.issuer+"/protocol/openid-connect/auth?") {
				select {
				case addresses <- line:
				default:
				}
				continue // Do not retain authorization URLs in test diagnostics.
			}
			fmt.Fprintln(&output, line)
		}
	}()
	var address string
	select {
	case address = <-addresses:
	case <-done:
		e.t.Fatal("interactive kubectl exited without opening the authorization flow")
	case <-ctx.Done():
		e.t.Fatal("interactive kubectl did not request browser login")
	}
	u, err := url.Parse(address)
	if err != nil || u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("state") == "" || u.Query().Get("nonce") == "" {
		e.t.Fatal("automatic kubectl login is missing PKCE, state, or nonce")
	}
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Timeout: 15 * time.Second}
	r, err := browser.Get(address)
	if err != nil {
		e.t.Fatal("cannot open the local Keycloak authorization form")
	}
	doc, err := html.Parse(r.Body)
	r.Body.Close()
	if err != nil {
		e.t.Fatal("cannot parse the local Keycloak authorization form")
	}
	action := formAction(doc)
	if !strings.HasPrefix(action, e.issuer+"/") {
		e.t.Fatal("automatic login did not use the expected local Keycloak form")
	}
	r, err = browser.PostForm(action, url.Values{"username": {username}, "password": {demoPassword(username)}, "credentialId": {""}})
	if err != nil {
		e.t.Fatal("automatic login browser form could not be completed")
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	err = cmd.Wait()
	<-done
	finished = true
	if wantSuccess && err != nil {
		e.t.Fatalf("kubectl failed after browser login: %v", err)
	}
	if !wantSuccess && (err == nil || !strings.Contains(output.String(), "no cluster is booked")) {
		var diagnostics []string
		for _, line := range strings.Split(output.String(), "\n") {
			if strings.Contains(strings.ToLower(line), "error") || strings.Contains(strings.ToLower(line), "cluster") {
				if !strings.Contains(line, "http") && !strings.Contains(line, "eyJ") {
					diagnostics = append(diagnostics, line)
				}
			}
		}
		e.t.Fatalf("first login should report no booked cluster without allocating: exit=%v diagnostics=%q", err, diagnostics)
	}
	return output.Bytes()
}

func TestStablePrimaryKubectlWorkflow(t *testing.T) {
	issuer := os.Getenv("DEVCTL_TEST_ISSUER")
	if issuer == "" {
		t.Skip("set DEVCTL_TEST_ISSUER and DEVCTL_TEST_DATABASE_URL")
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
	admin, alice := t.TempDir(), t.TempDir()
	env.login(admin, "admin", true)
	for _, id := range []string{"alpha", "beta"} {
		fixture := newKubernetesFixtureVersion(t, "v1.35.1-"+id)
		file := filepath.Join(t.TempDir(), "fixture.yaml")
		if err = os.WriteFile(file, []byte(fixture.kubeconfig()), 0600); err != nil {
			t.Fatal(err)
		}
		env.run(admin, "admin", "register", "--id", id, "--name", id, "--kubeconfig", file)
	}
	path := strings.TrimSpace(string(env.run(alice, "setup")))
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := clientcmd.Load(original)
	if err != nil || len(cfg.Clusters) != 1 || len(cfg.AuthInfos) != 1 {
		t.Fatal("invalid stable kubeconfig")
	}
	for _, c := range cfg.Clusters {
		if c.Server != env.api+"/k8s" {
			t.Fatal("booking-dependent gateway URL")
		}
	}
	for _, u := range cfg.AuthInfos {
		if u.Exec == nil || strings.Contains(strings.Join(u.Exec.Args, " "), "session") || u.Token != "" {
			t.Fatal("session binding or secret in exec config")
		}
	}
	if files, _ := filepath.Glob(filepath.Join(alice, "*", "tokens.json")); len(files) != 0 {
		t.Fatal("setup logged in")
	}
	// Authentication succeeds, but a Kubernetes request must never book capacity.
	env.firstPrimaryKubectl(alice, path, "alice", false)
	_, sessions, err := database.Snapshot(t.Context())
	if err != nil || len(sessions) != 0 {
		t.Fatal("kubectl silently allocated a cluster")
	}
	a := session(t, env.run(alice, "start", "--cluster", "alpha"))
	if raw := env.primaryKubectl(alice, path, "get", "--raw=/version"); !bytes.Contains(raw, []byte("alpha")) {
		t.Fatal("first booking was not primary")
	}
	env.reject(alice, 4, "start", "--cluster", "beta")
	env.run(admin, "admin", "settings", "--max-bookings", "2", "--reason", "primary workflow test")
	b := session(t, env.run(alice, "start", "--cluster", "beta"))
	if raw := env.primaryKubectl(alice, path, "get", "--raw=/version"); !bytes.Contains(raw, []byte("alpha")) {
		t.Fatal("second booking changed primary")
	}
	var identity model.Identity
	if json.Unmarshal(env.run(alice, "whoami"), &identity) != nil {
		t.Fatal("invalid whoami")
	}
	// Concurrent commands use one committed primary and do not create bookings.
	var wg sync.WaitGroup
	failures := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command("kubectl", "--kubeconfig", path, "--request-timeout=10s", "get", "--raw=/version")
			cmd.Env = env.command(alice).Env
			raw, e := cmd.CombinedOutput()
			if e == nil && !bytes.Contains(raw, []byte("alpha")) {
				e = fmt.Errorf("wrong primary")
			}
			failures <- e
		}()
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		if e != nil {
			t.Fatal("concurrent primary request failed", e)
		}
	}
	_, sessions, err = database.Snapshot(t.Context())
	if err != nil || len(sessions) != 2 {
		t.Fatal("commands duplicated bookings")
	}
	// Expire only the cached access token. The detached worker must rotate the
	// real provider credentials without another CLI or Kubernetes command.
	files, _ := filepath.Glob(filepath.Join(alice, "*", "tokens.json"))
	if len(files) != 1 {
		t.Fatal("development token store missing")
	}
	tokenJSON, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var token map[string]any
	_ = json.Unmarshal(tokenJSON, &token)
	oldAccess, oldRefresh := token["access_token"], token["refresh_token"]
	var before time.Time
	var activity *time.Time
	var beforeIdleDeadline, afterIdleDeadline time.Time
	query := `SELECT d.authorization_expires_at,s.last_activity_at,s.expires_at FROM developers d JOIN sessions s ON s.id=d.primary_session_id WHERE d.owner_id=$1`
	if err = database.Pool.QueryRow(t.Context(), query, identity.Key()).Scan(&before, &activity, &beforeIdleDeadline); err != nil {
		t.Fatal(err)
	}
	token["expiry"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	tokenJSON, _ = json.Marshal(token)
	temporary := files[0] + ".test-expired"
	if err = os.WriteFile(temporary, tokenJSON, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(temporary, files[0]); err != nil {
		t.Fatal(err)
	}
	var after time.Time
	var afterActivity *time.Time
	deadline := time.Now().Add(22 * time.Second)
	for time.Now().Before(deadline) {
		if err = database.Pool.QueryRow(t.Context(), query, identity.Key()).Scan(&after, &afterActivity, &afterIdleDeadline); err != nil {
			t.Fatal(err)
		}
		if after.After(before) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !after.After(before) || activity == nil || afterActivity == nil || !activity.Equal(*afterActivity) || !afterIdleDeadline.Equal(beforeIdleDeadline) {
		t.Fatal("detached renewal failed or counted its own activity")
	}
	tokenJSON, _ = os.ReadFile(files[0])
	_ = json.Unmarshal(tokenJSON, &token)
	if token["access_token"] == oldAccess || token["refresh_token"] == oldRefresh {
		t.Fatal("access/refresh rotation did not persist")
	}
	env.run(alice, "select", "beta")
	if raw := env.primaryKubectl(alice, path, "get", "--raw=/version"); !bytes.Contains(raw, []byte("beta")) {
		t.Fatal("unchanged config did not follow switch")
	}
	current, _ := os.ReadFile(path)
	if !bytes.Equal(original, current) {
		t.Fatal("switch rewrote or replaced kubeconfig contents")
	}
	env.stop()
	env.start()
	if raw := env.primaryKubectl(alice, path, "get", "--raw=/version"); !bytes.Contains(raw, []byte("beta")) {
		t.Fatal("restart lost primary")
	}
	env.run(alice, "stop", b.ID)
	if raw := env.primaryKubectl(alice, path, "get", "--raw=/version"); !bytes.Contains(raw, []byte("alpha")) {
		t.Fatal("remaining booking not promoted")
	}
	env.run(alice, "stop", a.ID)
	denied := exec.Command("kubectl", "--kubeconfig", path, "--request-timeout=5s", "get", "--raw=/version")
	denied.Env = env.command(alice).Env
	raw, e := denied.CombinedOutput()
	if e == nil || !bytes.Contains(raw, []byte("no cluster is booked")) {
		t.Fatal("no-booking error missing")
	}
	env.run(alice, "start", "--cluster", "beta")
	if raw := env.primaryKubectl(alice, path, "get", "--raw=/version"); !bytes.Contains(raw, []byte("beta")) {
		t.Fatal("stable config did not resume after new explicit booking")
	}
	env.run(alice, "logout")
	env.run(admin, "logout")
	t.Log("stable config, explicit booking limits, primary switching/promotion, no implicit booking, real refresh/heartbeat, concurrency and restart passed")
}
