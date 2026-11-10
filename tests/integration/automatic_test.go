package integration

import (
	"bufio"
	"bytes"
	"context"
	"devctl.local/devctl/internal/testutil"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/net/html"
	"io"
	"k8s.io/client-go/tools/clientcmd"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
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

func automaticShellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func (e *environment) automaticKubectl(dir, config string, args ...string) []byte {
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
func (e *environment) firstAutomaticKubectl(dir, config, username string) []byte {
	e.t.Helper()
	if _, err := exec.LookPath("script"); err != nil {
		e.t.Fatal("util-linux script is required for the interactive kubectl test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := strings.Join([]string{"kubectl", "--kubeconfig", automaticShellQuote(config), "--cache-dir", automaticShellQuote(filepath.Join(dir, "discovery-cache")), "--request-timeout=30s", "get", "pods", "-o", "json"}, " ")
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
	r, err = browser.PostForm(action, url.Values{"username": {username}, "password": {username + "-dev-only"}, "credentialId": {""}})
	if err != nil {
		e.t.Fatal("automatic login browser form could not be completed")
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	err = cmd.Wait()
	<-done
	finished = true
	if err != nil {
		e.t.Fatalf("automatic kubectl failed after browser login: %v", err)
	}
	return output.Bytes()
}

func TestAutomaticKubectlWorkflow(t *testing.T) {
	issuer := os.Getenv("DEVCTL_TEST_ISSUER")
	if issuer == "" {
		t.Skip("set DEVCTL_TEST_ISSUER and DEVCTL_TEST_DATABASE_URL; run make demo-test")
	}
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Fatal("kubectl is required for the automatic access end-to-end suite")
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
	env := &environment{t: t, root: root, api: "https://" + address, issuer: issuer, dsn: dsn, key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{67}, 32))}
	configureGatewayTLS(t, env)
	env.start()
	defer env.stop()
	admin, alice := t.TempDir(), t.TempDir()
	env.login(admin, "admin", true)
	upstream := newKubernetesFixture(t)
	upstreamConfig := filepath.Join(t.TempDir(), "upstream.yaml")
	if err = os.WriteFile(upstreamConfig, []byte(upstream.kubeconfig()), 0600); err != nil {
		t.Fatal(err)
	}
	env.run(admin, "admin", "register", "--id", "automatic", "--name", "Automatic fixture", "--kubeconfig", upstreamConfig)

	// Setup is distribution/bootstrap only: it must not require login, reserve a
	// cluster, or put upstream credentials into the developer's metadata file.
	path := strings.TrimSpace(string(env.run(alice, "setup", "--cluster", "automatic", "--ttl", "1h")))
	if !filepath.IsAbs(path) || strings.Contains(path, "\n") {
		t.Fatal("setup stdout is not a single absolute kubeconfig path")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("setup did not create a private kubeconfig")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(upstreamToken)) || bytes.Contains(raw, []byte(upstream.Server.URL)) || bytes.Contains(raw, []byte("client-key-data")) {
		t.Fatal("automatic kubeconfig contains original upstream credentials")
	}
	config, err := clientcmd.Load(raw)
	if err != nil || !strings.HasPrefix(config.CurrentContext, "a-") {
		t.Fatal("setup did not create an automatic binding context")
	}
	initialBinding := config.CurrentContext
	for _, user := range config.AuthInfos {
		if user.Token != "" || user.Exec == nil || user.Exec.InteractiveMode != clientapi.IfAvailableExecInteractiveMode || !strings.Contains(strings.Join(user.Exec.Args, " "), "credential --auto "+initialBinding) {
			t.Fatal("automatic config does not use the expected interactive exec credential helper")
		}
	}
	for _, cluster := range config.Clusters {
		if cluster.Server != env.api+"/k8s/auto/"+initialBinding {
			t.Fatal("automatic config does not use the stable gateway URL")
		}
	}
	if files, _ := filepath.Glob(filepath.Join(alice, "*", "tokens.json")); len(files) != 0 {
		t.Fatal("setup unexpectedly logged the developer in")
	}
	_, sessions, err := database.Snapshot(context.Background())
	if err != nil || len(sessions) != 0 {
		t.Fatal("setup allocated an environment before kubectl was invoked")
	}

	// A script/CI process must never unexpectedly start an interactive login.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	denied := exec.CommandContext(ctx, "kubectl", "--kubeconfig", path, "--request-timeout=5s", "get", "--raw=/version")
	denied.Env = env.command(alice).Env
	deniedOutput, deniedErr := denied.CombinedOutput()
	timedOut := ctx.Err() != nil
	cancel()
	if deniedErr == nil || bytes.Contains(deniedOutput, []byte("Open this URL")) {
		t.Fatal("noninteractive kubectl without credentials did not fail closed")
	}
	if timedOut {
		t.Fatal("noninteractive kubectl waited for an unavailable browser login")
	}

	output := env.firstAutomaticKubectl(alice, path, "alice")
	if !bytes.Contains(output, []byte(`"items"`)) || !upstream.saw("GET", "/api/v1/namespaces/default/pods", false) {
		t.Fatal("first ordinary kubectl did not finish after automatic login and reservation")
	}
	_, sessions, err = database.Snapshot(context.Background())
	if err != nil || len(sessions) != 1 || sessions[0].State != "ACTIVE" || sessions[0].Cluster != "automatic" || sessions[0].Name != "alice" || sessions[0].LastActivityAt == nil {
		t.Fatal("first kubectl did not record exactly one owned, active environment and activity")
	}
	first := sessions[0]

	// Discovery, retries, and concurrent processes all retain this reservation.
	var wg sync.WaitGroup
	results := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", path, "--request-timeout=10s", "get", "--raw=/version")
			cmd.Env = env.command(alice).Env
			raw, err := cmd.CombinedOutput()
			if err == nil && !bytes.Contains(raw, []byte("v1.35.1-fixture")) {
				err = fmt.Errorf("gateway version response missing")
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent automatic kubectl request failed: %v", err)
		}
	}
	_, sessions, err = database.Snapshot(context.Background())
	if err != nil || len(sessions) != 1 || sessions[0].ID != first.ID {
		t.Fatal("concurrent kubectl allocated more than one environment")
	}

	// Refresh the same login silently rather than requiring another browser flow.
	files, _ := filepath.Glob(filepath.Join(alice, "*", "tokens.json"))
	if len(files) != 1 {
		t.Fatal("development token fallback missing for automatic login")
	}
	tokenJSON, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var token map[string]any
	if err = json.Unmarshal(tokenJSON, &token); err != nil {
		t.Fatal(err)
	}
	oldAccess, _ := token["access_token"].(string)
	token["expiry"] = time.Now().Add(-time.Hour).Format(time.RFC3339Nano)
	tokenJSON, _ = json.Marshal(token)
	if err = os.WriteFile(files[0], tokenJSON, 0600); err != nil {
		t.Fatal(err)
	}
	env.automaticKubectl(alice, path, "get", "--raw=/version")
	tokenJSON, err = os.ReadFile(files[0])
	if err != nil || json.Unmarshal(tokenJSON, &token) != nil || token["access_token"] == oldAccess {
		t.Fatal("automatic kubectl did not silently refresh the stored access token")
	}

	// The detached worker must renew authorization after kubectl has exited,
	// without another CLI invocation driving token refresh. Database observation
	// deliberately avoids counting the test's own polling as gateway activity.
	var leaseBefore, activityBefore time.Time
	if err = database.Pool.QueryRow(context.Background(), `SELECT b.authorization_expires_at,s.last_activity_at
 FROM automatic_bindings b JOIN sessions s ON s.id=b.session_id
 WHERE b.owner_id=$1 AND b.binding_id=$2`, first.Owner, initialBinding).Scan(&leaseBefore, &activityBefore); err != nil {
		t.Fatal(err)
	}
	workerAccess, _ := token["access_token"].(string)
	workerRefresh, _ := token["refresh_token"].(string)
	if workerAccess == "" || workerRefresh == "" {
		t.Fatal("automatic login did not retain both credentials for renewal")
	}
	token["expiry"] = time.Now().Add(-time.Hour).Format(time.RFC3339Nano)
	tokenJSON, _ = json.Marshal(token)
	forcedExpiry := files[0] + ".forced-expiry"
	if err = os.WriteFile(forcedExpiry, tokenJSON, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(forcedExpiry, files[0]); err != nil {
		t.Fatal(err)
	}
	renewedByWorker := false
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		var leaseAfter, activityAfter time.Time
		if err = database.Pool.QueryRow(context.Background(), `SELECT b.authorization_expires_at,s.last_activity_at
 FROM automatic_bindings b JOIN sessions s ON s.id=b.session_id
 WHERE b.owner_id=$1 AND b.binding_id=$2`, first.Owner, initialBinding).Scan(&leaseAfter, &activityAfter); err != nil {
			t.Fatal(err)
		}
		if !activityAfter.Equal(activityBefore) {
			t.Fatal("the detached renewal worker manufactured Kubernetes activity")
		}
		if leaseAfter.After(leaseBefore) {
			tokenJSON, err = os.ReadFile(files[0])
			if err != nil || json.Unmarshal(tokenJSON, &token) != nil || token["access_token"] == workerAccess || token["refresh_token"] == workerRefresh {
				t.Fatal("the detached renewal worker did not save rotated credentials")
			}
			renewedByWorker = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !renewedByWorker {
		t.Fatal("the detached worker did not refresh gateway authorization after kubectl exited")
	}

	env.stop()
	env.start()
	env.automaticKubectl(alice, path, "get", "--raw=/version")
	_, sessions, err = database.Snapshot(context.Background())
	if err != nil || len(sessions) != 1 || sessions[0].ID != first.ID {
		t.Fatal("backend restart lost or changed the automatic binding")
	}
	env.run(alice, "stop", first.ID)
	stopped := exec.Command("kubectl", "--kubeconfig", path, "--request-timeout=5s", "get", "--raw=/version")
	stopped.Env = env.command(alice).Env
	if err = stopped.Run(); err == nil {
		t.Fatal("a stopped automatic booking silently reactivated")
	}
	_, sessions, err = database.Snapshot(context.Background())
	if err != nil || len(sessions) != 1 || sessions[0].State != "RELEASED" {
		t.Fatal("a request after stop created a replacement booking")
	}
	newPath := strings.TrimSpace(string(env.run(alice, "setup", "--cluster", "automatic", "--ttl", "1h", "--new-booking")))
	if newPath != path {
		t.Fatal("explicit reactivation changed the stable kubeconfig path")
	}
	config, err = clientcmd.LoadFromFile(path)
	if err != nil || config.CurrentContext == initialBinding {
		t.Fatal("explicit reactivation did not create a new binding")
	}
	env.automaticKubectl(alice, path, "get", "--raw=/version")
	_, sessions, err = database.Snapshot(context.Background())
	if err != nil || len(sessions) != 2 || sessions[1].ID == first.ID || sessions[1].State != "ACTIVE" {
		t.Fatal("explicit reactivation did not create a new reservation")
	}
	env.run(alice, "logout")
	env.run(admin, "logout")
	t.Log("normal kubectl completed first-use PKCE login and allocation; concurrent calls, on-demand and detached renewal, activity, restart, stop and explicit reactivation passed")
}
