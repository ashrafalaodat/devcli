package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
	for _, cmd := range root.Commands() {
		if !cmd.Hidden {
			visible = append(visible, cmd.Name())
		}
	}
	sort.Strings(visible)
	if strings.Join(visible, ",") != "login,logout,setup,status,switch" {
		t.Fatal("unexpected plugin controls", visible)
	}
	for _, name := range []string{"admin", "start", "stop", "share", "renew", "clusters", "sessions", "select", "exec", "kubeconfig", "token"} {
		if cmd, _, err := root.Find([]string{name}); err == nil && cmd != root {
			t.Fatal("management command exposed", name)
		}
	}
	for _, name := range []string{"credential", "heartbeat", "shell"} {
		cmd, _, err := root.Find([]string{name})
		if err != nil || cmd == root || !cmd.Hidden {
			t.Fatal("required internal helper missing", name)
		}
	}
	for _, name := range []string{"login", "setup", "credential"} {
		cmd, _, _ := root.Find([]string{name})
		for _, flag := range []string{"cluster", "selector", "ttl", "new-booking", "auto", "session"} {
			if cmd.Flags().Lookup(flag) != nil {
				t.Fatal("retired binding/booking flag retained", name, flag)
			}
		}
	}
	full := NewCommand()
	if cmd, _, err := full.Find([]string{"admin", "register"}); err != nil || cmd.Name() != "register" {
		t.Fatal("full CLI modified by plugin filter")
	}
}

func TestPluginLoginRefreshesWithoutBookingAndPrintsOnlyStableConfigPath(t *testing.T) {
	var issuer string
	var exchanges, apiCalls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/token":
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "old-refresh" {
				t.Error("unexpected refresh grant")
				w.WriteHeader(400)
				return
			}
			exchanges.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fresh-access", "refresh_token": "rotated-refresh", "expires_in": 600, "token_type": "Bearer"})
		default:
			w.WriteHeader(404)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	identity := testAccessIdentity()
	c, out := testAccessClient(t, func(w http.ResponseWriter, r *http.Request) {
		apiCalls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/v1/profile" || r.Header.Get("Authorization") != "Bearer fresh-access" {
			t.Error("plugin attempted allocation or wrong API")
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(developerProfile{OwnerID: identity.Key(), User: identity, MaxBookings: 1})
	})
	c.Login.Config = auth.DefaultConfig(issuer)
	if err := c.Login.save(&oauth2.Token{AccessToken: "old-access", RefreshToken: "old-refresh", Expiry: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := c.pluginLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if exchanges.Load() != 1 || apiCalls.Load() != 1 || out.String() != c.activePath()+"\n" {
		t.Fatal("login did not silently refresh or printed more than path")
	}
	token, err := c.Login.read()
	if err != nil || token.RefreshToken != "rotated-refresh" {
		t.Fatal("rotated token not persisted")
	}
	raw, err := os.ReadFile(c.activePath())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := clientcmd.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Clusters["devctl"].Server != c.URL+"/k8s" || strings.Join(cfg.AuthInfos["devctl"].Exec.Args, "|") != "--api|"+c.URL+"|credential" {
		t.Fatal("plugin config not stable")
	}
	if strings.Contains(string(raw), "fresh-access") || strings.Contains(string(raw), "rotated-refresh") {
		t.Fatal("credential stored in kubeconfig")
	}
}

func TestAdditionalBookingDoesNotChangePrimarySelection(t *testing.T) {
	var posts atomic.Int32
	c, _ := testAccessClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/sessions" {
			t.Error("start altered primary")
			w.WriteHeader(400)
			return
		}
		var booking map[string]any
		if err := json.NewDecoder(r.Body).Decode(&booking); err != nil {
			t.Error(err)
		}
		if _, exists := booking["ttl"]; exists {
			t.Error("booking still requests a fixed duration")
		}
		posts.Add(1)
		_ = json.NewEncoder(w).Encode(model.Session{ID: sessionB, Cluster: "cluster-b", State: "ACTIVE"})
	})
	saveAccessTestToken(t, c)
	root := newCommand(c)
	root.PersistentPreRunE = nil
	root.SetArgs([]string{"start", "--cluster", "cluster-b"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 1 {
		t.Fatal("unexpected requests")
	}
	raw, err := os.ReadFile(c.activePath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), sessionA) || strings.Contains(string(raw), sessionB) {
		t.Fatal("booking stored as local selection")
	}
}
