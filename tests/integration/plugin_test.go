package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/testutil"
	"k8s.io/client-go/tools/clientcmd"
)

// This exercises kubectl's executable discovery and the built plugin binary,
// including first-use real Keycloak PKCE login and later silent token refresh.
// The registered upstream is a disposable TLS fixture, not a remote cluster.
func TestKubectlPluginWorkflow(t *testing.T) {
	issuer := os.Getenv("DEVCTL_TEST_ISSUER")
	if issuer == "" {
		t.Skip("set DEVCTL_TEST_ISSUER and DEVCTL_TEST_DATABASE_URL; run make demo-test")
	}
	database, dsn := testutil.Database(t)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(root, "bin/kubectl-devctl")
	if _, err = os.Stat(plugin); err != nil {
		t.Fatal("build the kubectl plugin before running this suite")
	}
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Fatal("kubectl required")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	env := &environment{t: t, root: root, api: "https://" + address, issuer: issuer, dsn: dsn, key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{75}, 32))}
	configureGatewayTLS(t, env)
	env.start()
	defer env.stop()
	admin, alice := t.TempDir(), t.TempDir()
	env.login(admin, "admin", true)
	upstream := newKubernetesFixture(t)
	upstreamConfig := filepath.Join(t.TempDir(), "plugin-upstream.yaml")
	if err = os.WriteFile(upstreamConfig, []byte(upstream.kubeconfig()), 0600); err != nil {
		t.Fatal(err)
	}
	env.run(admin, "admin", "register", "--id", "plugin", "--name", "Plugin fixture", "--kubeconfig", upstreamConfig)
	bootstrap := t.TempDir()
	env.login(bootstrap, "alice", true)
	env.run(bootstrap, "start", "--cluster", "plugin")

	// kubectl discovers only this plugin; the full devctl executable need not be
	// present in the child's PATH. Credential and heartbeat use the plugin itself.
	pluginPath := t.TempDir()
	if err = os.Symlink(plugin, filepath.Join(pluginPath, "kubectl-devctl")); err != nil {
		t.Fatal(err)
	}
	pluginEnv := []string{}
	for _, variable := range env.command(alice).Env {
		if !strings.HasPrefix(variable, "PATH=") {
			pluginEnv = append(pluginEnv, variable)
		}
	}
	pluginEnv = append(pluginEnv, "PATH="+pluginPath+":/usr/bin:/bin")
	runPlugin := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, kubectl, append([]string{"devctl"}, args...)...)
		cmd.Env = pluginEnv
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		raw, err := cmd.Output()
		return raw, err // Do not include auth URLs or credential output in diagnostics.
	}
	pathBytes, err := runPlugin("setup")
	if err != nil {
		t.Fatal("kubectl could not discover or execute the plugin")
	}
	path := strings.TrimSpace(string(pathBytes))
	if !filepath.IsAbs(path) || strings.Contains(path, "\n") {
		t.Fatal("plugin setup did not print one absolute config path")
	}
	config, err := clientcmd.LoadFromFile(path)
	if err != nil {
		t.Fatal("plugin setup did not write valid config")
	}
	for _, credentials := range config.AuthInfos {
		if credentials.Token != "" || credentials.Exec == nil || filepath.Base(credentials.Exec.Command) != "kubectl-devctl" {
			t.Fatal("plugin config embeds a credential or invokes the wrong executable")
		}
	}
	if files, _ := filepath.Glob(filepath.Join(alice, "*", "tokens.json")); len(files) != 0 {
		t.Fatal("offline setup performed login")
	}
	// A genuine interactive kubectl request causes the configured plugin to run
	// its inherited OIDC code/PKCE flow, with no devctl management invocation.
	env.firstPrimaryKubectl(alice, path, "alice", true)
	_, sessions, err := database.Snapshot(context.Background())
	if err != nil || len(sessions) != 1 || sessions[0].Cluster != "plugin" || sessions[0].State != "ACTIVE" {
		t.Fatal("plugin login changed the one prepared booking")
	}
	first := sessions[0]
	files, _ := filepath.Glob(filepath.Join(alice, "*", "tokens.json"))
	if len(files) != 1 {
		t.Fatal("private development token storage missing")
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var token map[string]any
	if json.Unmarshal(raw, &token) != nil {
		t.Fatal("invalid stored login")
	}
	oldAccess, oldRefresh := token["access_token"], token["refresh_token"]
	token["expiry"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	raw, _ = json.Marshal(token)
	if err = os.WriteFile(files[0], raw, 0600); err != nil {
		t.Fatal(err)
	}
	pathBytes, err = runPlugin("login")
	if err != nil || strings.TrimSpace(string(pathBytes)) != path {
		t.Fatal("explicit plugin login did not refresh and retain its config path")
	}
	raw, err = os.ReadFile(files[0])
	if err != nil || json.Unmarshal(raw, &token) != nil || token["access_token"] == oldAccess || token["refresh_token"] == oldRefresh {
		t.Fatal("plugin did not persist refreshed access and rotated refresh tokens")
	}
	_, sessions, err = database.Snapshot(context.Background())
	if err != nil || len(sessions) != 1 || sessions[0].ID != first.ID {
		t.Fatal("plugin refresh created another booking")
	}
	env.primaryKubectl(alice, path, "get", "--raw=/version")
	statusRaw, err := runPlugin("status", "--json")
	if err != nil {
		t.Fatal("plugin status failed")
	}
	var profile model.DeveloperProfile
	if json.Unmarshal(statusRaw, &profile) != nil || profile.PrimarySession == nil || profile.PrimarySession.ID != first.ID || profile.ActiveBookings != 1 {
		t.Fatal("plugin status did not show current primary")
	}
	// Raising the server-side limit permits another explicit booking. Plugin
	// login itself still performs no placement or additional reservation.
	env.run(admin, "admin", "settings", "--max-bookings", "2", "--reason", "plugin switching integration")
	secondUpstream := newKubernetesFixture(t)
	secondConfig := filepath.Join(t.TempDir(), "second-upstream.yaml")
	if err = os.WriteFile(secondConfig, []byte(secondUpstream.kubeconfig()), 0600); err != nil {
		t.Fatal(err)
	}
	env.run(admin, "admin", "register", "--id", "plugin-second", "--name", "Second plugin fixture", "--kubeconfig", secondConfig)
	second := session(t, env.run(bootstrap, "start", "--cluster", "plugin-second"))
	statusRaw, err = runPlugin("status", "--json")
	if err != nil || json.Unmarshal(statusRaw, &profile) != nil || profile.PrimarySession == nil || profile.PrimarySession.ID != first.ID {
		t.Fatal("additional booking unexpectedly selected itself")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := runPlugin("switch", "plugin-second")
	if err != nil || json.Unmarshal(selected, &profile) != nil || profile.PrimarySession == nil || profile.PrimarySession.ID != second.ID {
		t.Fatal("plugin switch failed")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("switch rewrote stable kubeconfig")
	}
	env.primaryKubectl(alice, path, "get", "--raw=/version")
	secondUpstream.mu.Lock()
	requests := len(secondUpstream.Requests)
	secondUpstream.mu.Unlock()
	if requests == 0 {
		t.Fatal("stable plugin kubeconfig did not reach new primary")
	}

	if _, err = runPlugin("admin", "register"); err == nil {
		t.Fatal("plugin exposed full CLI administrator command")
	}
	if _, err = runPlugin("logout"); err != nil {
		t.Fatal("plugin logout failed")
	}
	_, sessions, err = database.Snapshot(context.Background())
	if err != nil || len(sessions) != 2 {
		t.Fatal("unexpected plugin reservations after logout")
	}
	for _, booking := range sessions {
		if booking.State != "RELEASED" {
			t.Fatal("plugin logout did not release all own bookings")
		}
	}
	env.run(admin, "logout")
	t.Log("real plugin discovery, first-use PKCE without allocation, refresh rotation, unchanged config across primary switch, reduced controls and logout passed")
}
