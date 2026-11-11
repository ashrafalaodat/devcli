package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/auth"
	"devctl.local/devctl/internal/model"
	"golang.org/x/oauth2"
	"k8s.io/client-go/tools/clientcmd"
)

func TestPluginHasOnlyConnectionControls(t *testing.T) {
	root := NewPluginCommand()
	var visible []string
	for _, command := range root.Commands() {
		if !command.Hidden {
			visible = append(visible, command.Name())
		}
	}
	sort.Strings(visible)
	if strings.Join(visible, ",") != "login,logout,setup,status" {
		t.Fatal("unexpected plugin command surface", visible)
	}
	for _, forbidden := range []string{"admin", "start", "stop", "share", "renew", "clusters", "sessions", "select", "exec", "kubeconfig"} {
		if command, _, err := root.Find([]string{forbidden}); err == nil && command != root {
			t.Fatal("full CLI command exposed by plugin", forbidden)
		}
	}
	for _, required := range []string{"credential", "heartbeat", "shell"} {
		command, _, err := root.Find([]string{required})
		if err != nil || command == root || !command.Hidden {
			t.Fatal("internal helper command is missing or visible", required, err)
		}
	}
	for _, option := range []string{"cluster", "selector", "ttl", "new-booking"} {
		command, _, _ := root.Find([]string{"login"})
		if command.Flags().Lookup(option) == nil {
			t.Fatal("login does not support selection flag", option)
		}
	}
	full := NewCommand()
	if command, _, err := full.Find([]string{"admin", "register"}); err != nil || command.Name() != "register" {
		t.Fatal("plugin filtering modified the full CLI", err)
	}
}

func TestPluginLoginRefreshesAndPrintsOnlyPublicConfigPath(t *testing.T) {
	var issuer string
	var exchanges atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/token":
			r.ParseForm()
			if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "plugin-refresh-old" || r.Form.Get("client_secret") != "" {
				w.WriteHeader(400)
				return
			}
			exchanges.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"access_token": "plugin-access-new", "refresh_token": "plugin-refresh-rotated", "expires_in": 600, "token_type": "Bearer"})
		default:
			w.WriteHeader(404)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	identity := model.Identity{Issuer: issuer, Subject: "alice", Name: "alice"}
	var ensures atomic.Int32
	var c *Client
	c, out := automaticTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer plugin-access-new" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/whoami" {
			json.NewEncoder(w).Encode(identity)
			return
		}
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/ensure") {
			ensures.Add(1)
			var booking model.Booking
			if err := json.NewDecoder(r.Body).Decode(&booking); err != nil || booking.Cluster != "cluster-a" || booking.Selector["team"] != "test" {
				t.Error("plugin dropped booking preferences", err)
			}
			binding := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/auto/"), "/ensure")
			json.NewEncoder(w).Encode(map[string]any{"session": map[string]any{"id": sessionA, "owner": identity.Key(), "cluster": "cluster-a", "state": "ACTIVE"}, "server": c.automaticServer(binding), "authorization_expires_at": time.Now().Add(5 * time.Minute)})
			return
		}
		w.WriteHeader(404)
	})
	c.Login.Config = auth.DefaultConfig(issuer)
	if err := c.Login.save(&oauth2.Token{AccessToken: "plugin-access-old", RefreshToken: "plugin-refresh-old", TokenType: "Bearer", Expiry: time.Now().Add(10 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	booking := model.Booking{Cluster: "cluster-a", Selector: map[string]string{"team": "test"}}
	if _, err := c.setupAutomatic(context.Background(), booking, false, true); err != nil {
		t.Fatal(err)
	}
	state, _ := c.readAutomaticState()
	worker := c.heartbeatLock(state.Binding, sessionA)
	if ok, err := worker.TryLock(); err != nil || !ok {
		t.Fatal("cannot prevent test worker spawning", err)
	}
	defer worker.Unlock()
	if err := c.pluginLogin(context.Background(), booking, false, true); err != nil {
		t.Fatal(err)
	}
	if out.String() != c.activePath()+"\n" || exchanges.Load() != 1 || ensures.Load() != 1 {
		t.Fatal("plugin login leaked extra output or failed refresh/booking", exchanges.Load(), ensures.Load())
	}
	stored, err := c.Login.read()
	if err != nil || stored.AccessToken != "plugin-access-new" || stored.RefreshToken != "plugin-refresh-rotated" {
		t.Fatal("rotated credentials were not persisted", err)
	}
	raw, err := os.ReadFile(c.activePath())
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"plugin-access", "plugin-refresh", "token:", "client-key", "client-certificate"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("plugin kubeconfig contains private credentials", private)
		}
	}
	cfg, err := clientcmd.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	if cfg.AuthInfos["devctl"].Exec.Command != self || strings.Join(cfg.AuthInfos["devctl"].Exec.Args, "|") != "--api|"+c.URL+"|credential|--auto|"+state.Binding {
		t.Fatal("plugin config does not invoke its own executable")
	}
	// The reduced command tree executes the same credential method used by the
	// login path. Its stdout remains one ExecCredential, not status/path output.
	out.Reset()
	if err := c.automaticCredential(context.Background(), state.Binding); err != nil {
		t.Fatal(err)
	}
	var document struct {
		Kind   string `json:"kind"`
		Status struct {
			Token      string `json:"token"`
			Expiration string `json:"expirationTimestamp"`
		} `json:"status"`
	}
	decoder := json.NewDecoder(out)
	if err = decoder.Decode(&document); err != nil || decoder.Decode(new(any)) != io.EOF || document.Kind != "ExecCredential" || document.Status.Token != "plugin-access-new" || document.Status.Expiration == "" {
		t.Fatal("invalid plugin ExecCredential", err)
	}
}

func TestPluginSetupRunsOfflineThroughReducedCommandTree(t *testing.T) {
	t.Setenv("DEVCTL_CONFIG_DIR", t.TempDir())
	t.Setenv("DEVCTL_DEV_HTTP", "1")
	t.Setenv("DEVCTL_DEV_TOKEN_FILE", "1")
	t.Setenv("DEVCTL_API_CA_FILE", "")
	t.Setenv("DEVCTL_ISSUER", "http://127.0.0.1:1/issuer")
	t.Setenv("DEVCTL_OIDC_CONFIG", "")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent-devctl-plugin-test")
	out := new(bytes.Buffer)
	c := &Client{HTTP: http.DefaultClient, Out: out, Err: io.Discard}
	root := newPluginCommand(c)
	root.SetArgs([]string{"--api", "https://127.0.0.1:1", "setup", "--cluster", "cluster-test", "--ttl", "2h"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	path := strings.TrimSpace(out.String())
	if !filepath.IsAbs(path) || strings.Contains(path, "\n") {
		t.Fatal("setup did not print one absolute path")
	}
	state, err := c.readAutomaticState()
	if err != nil || state.Booking.Cluster != "cluster-test" || state.Booking.TTL != "2h0m0s" {
		t.Fatal("plugin setup lost booking parameters", err)
	}
	if _, err := c.Login.read(); err == nil {
		t.Fatal("offline setup created authentication state")
	}
}
