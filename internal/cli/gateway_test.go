package cli

import (
	"bytes"
	"context"
	"devctl.local/devctl/internal/auth"
	"devctl.local/devctl/internal/model"
	"encoding/json"
	"encoding/pem"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"io"
	"k8s.io/client-go/tools/clientcmd"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const sessionA = "s-12345678-1234-1234-1234-123456789abc"
const sessionB = "s-12345678-1234-1234-1234-123456789abd"

func testGatewayClient(t *testing.T, handler http.HandlerFunc) (*Client, *bytes.Buffer) {
	t.Helper()
	t.Setenv("DEVCTL_CONFIG_DIR", t.TempDir())
	t.Setenv("DEVCTL_DEV_TOKEN_FILE", "1")
	t.Setenv("DEVCTL_DEV_HTTP", "1")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent-devctl-gateway-test")
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	store, e := newLoginStore(server.URL, auth.DefaultConfig("http://127.0.0.1:8081/realms/devctl"))
	if e != nil {
		t.Fatal(e)
	}
	if e = store.save(&oauth2.Token{AccessToken: "devctl-api-token-sentinel", RefreshToken: "refresh-token-sentinel", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}); e != nil {
		t.Fatal(e)
	}
	out := new(bytes.Buffer)
	return &Client{URL: server.URL, Login: store, HTTP: server.Client(), Out: out, Err: io.Discard}, out
}
func TestShellInstallIsExplicitIdempotentAndQuotesPath(t *testing.T) {
	t.Setenv("DEVCTL_CONFIG_DIR", filepath.Join(t.TempDir(), "profile's $(touch should-not-run)"))
	t.Setenv("DEVCTL_DEV_HTTP", "1")
	login, e := newLoginStore("http://127.0.0.1:8080", auth.DefaultConfig("http://127.0.0.1:8081/realms/devctl"))
	if e != nil {
		t.Fatal(e)
	}
	c := &Client{URL: "http://127.0.0.1:8080", Login: login}
	rc := filepath.Join(t.TempDir(), "bashrc")
	original := []byte("# existing setup\nexport PRESERVED=yes\n")
	if e = os.WriteFile(rc, original, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = c.installShell(context.Background(), "bash", rc); e != nil {
		t.Fatal(e)
	}
	first, e := os.ReadFile(rc)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.installShell(context.Background(), "bash", rc); e != nil {
		t.Fatal(e)
	}
	second, e := os.ReadFile(rc)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(first, second) || !bytes.HasPrefix(first, original) || bytes.Count(first, []byte(shellBlockStart)) != 1 {
		t.Fatal("shell rc not preserved or idempotent")
	}
	cmd := exec.Command("bash", "--noprofile", "--norc", "-c", "source \"$1\"; printf '%s' \"$KUBECONFIG\"", "--", rc)
	actual, e := cmd.Output()
	if e != nil || string(actual) != c.activePath() {
		t.Fatal("unsafe shell quoting or wrong export", e, string(actual))
	}
	for _, shell := range []string{"bash", "zsh", "fish"} {
		snippet, e := c.shellInit(context.Background(), shell)
		if e != nil || !strings.Contains(snippet, "KUBECONFIG") {
			t.Fatal(shell, e)
		}
	}
	symlink := filepath.Join(t.TempDir(), "rc-link")
	if e = os.Symlink(rc, symlink); e != nil {
		t.Fatal(e)
	}
	if _, e = c.installShell(context.Background(), "bash", symlink); e == nil {
		t.Fatal("overwrote symlink rc")
	}
	if _, e = updateShellRC([]byte(shellBlockStart+"\n"), "export KUBECONFIG=anything\n"); e == nil {
		t.Fatal("overwrote malformed rc block")
	}
}

func TestShellQuotingForFishAndZsh(t *testing.T) {
	value := "a\\\\b' $(echo unsafe)"
	if got := fishQuote(value); got != "'a\\\\\\\\b\\' $(echo unsafe)'" {
		t.Fatal("incorrect fish single-quote escaping", got)
	}
	zsh, e := exec.LookPath("zsh")
	if e != nil {
		t.Skip("zsh not installed")
	}
	t.Setenv("DEVCTL_CONFIG_DIR", filepath.Join(t.TempDir(), value))
	t.Setenv("DEVCTL_DEV_HTTP", "1")
	login, e := newLoginStore("http://127.0.0.1:8080", auth.DefaultConfig("http://127.0.0.1:8081/realms/devctl"))
	if e != nil {
		t.Fatal(e)
	}
	client := &Client{URL: "http://127.0.0.1:8080", Login: login}
	snippet, e := client.shellInit(context.Background(), "zsh")
	if e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(t.TempDir(), "zshrc")
	if e = os.WriteFile(file, []byte(snippet), 0600); e != nil {
		t.Fatal(e)
	}
	command := exec.Command(zsh, "-f", "-c", "source \"$1\"; printf '%s' \"$KUBECONFIG\"", "--", file)
	raw, e := command.Output()
	if e != nil || string(raw) != client.activePath() {
		t.Fatal("zsh shell snippet did not preserve quoted path", e, string(raw))
	}
}

func TestStableSetupIsOfflinePrivateAndReplacesRetiredBinding(t *testing.T) {
	var requests atomic.Int32
	c, _ := testAccessClient(t, func(http.ResponseWriter, *http.Request) { requests.Add(1) })
	legacy := filepath.Join(c.Login.Dir, "auto-binding.json")
	if err := os.WriteFile(legacy, []byte(`{"binding":"old"}`), 0600); err != nil {
		t.Fatal(err)
	}
	path, err := c.setupGateway(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := clientcmd.Load(first)
	if err != nil {
		t.Fatal(err)
	}
	plugin := cfg.AuthInfos["devctl"].Exec
	if cfg.Clusters["devctl"].Server != c.URL+"/k8s" || cfg.CurrentContext != "devctl" || plugin == nil || strings.Join(plugin.Args, "|") != "--api|"+c.URL+"|credential" || plugin.InteractiveMode != "IfAvailable" {
		t.Fatal("config does not use stable developer gateway")
	}
	if bytes.Contains(first, []byte("/sessions/")) || bytes.Contains(first, []byte("--auto")) || bytes.Contains(first, []byte("--session")) || bytes.Contains(first, []byte("token:")) {
		t.Fatal("retired route or credential persisted")
	}
	if _, err = os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("retired binding retained")
	}
	if _, err = c.setupGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if !bytes.Equal(first, second) || requests.Load() != 0 {
		t.Fatal("setup changed selection or contacted backend")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("config not private")
	}
}

func TestCredentialWithoutBookingAuthenticatesButNeverAllocates(t *testing.T) {
	var requests atomic.Int32
	identity := testAccessIdentity()
	c, out := testAccessClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "GET" || r.URL.Path != "/v1/profile" {
			t.Error("credential allocated or mutated booking")
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(developerProfile{OwnerID: identity.Key(), User: identity, MaxBookings: 1})
	})
	saveAccessTestToken(t, c)
	if err := c.credential(context.Background()); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Kind   string `json:"kind"`
		Status struct {
			Token  string    `json:"token"`
			Expiry time.Time `json:"expirationTimestamp"`
		} `json:"status"`
	}
	decoder := json.NewDecoder(out)
	if err := decoder.Decode(&result); err != nil || decoder.Decode(new(any)) != io.EOF || result.Kind != "ExecCredential" || result.Status.Token != "automatic-access-sentinel" || !result.Status.Expiry.After(time.Now()) {
		t.Fatal("invalid expiring credential", err)
	}
	if requests.Load() != 1 {
		t.Fatal("unexpected allocation request")
	}
	if err := c.Login.clear(); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := c.credential(context.Background()); err == nil || out.Len() != 0 {
		t.Fatal("missing login emitted credential")
	}
	if requests.Load() != 1 {
		t.Fatal("noninteractive missing login opened authentication")
	}
}

func TestPrimarySwitchPreservesKubeconfigAndCallsServerOnly(t *testing.T) {
	identity := testAccessIdentity()
	var switches atomic.Int32
	c, out := testAccessClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/primary" {
			t.Error("unexpected request")
			w.WriteHeader(400)
			return
		}
		var body struct {
			Cluster string `json:"cluster"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Cluster != "cluster-b" {
			t.Error("wrong selected cluster")
		}
		switches.Add(1)
		_ = json.NewEncoder(w).Encode(developerProfile{OwnerID: identity.Key(), User: identity, MaxBookings: 2, SelectionVersion: 2})
	})
	saveAccessTestToken(t, c)
	path, err := c.setupGateway(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	root := &cobra.Command{Use: "devctl", SilenceErrors: true, SilenceUsage: true}
	c.addGatewayCommands(root)
	root.SetArgs([]string{"select", "cluster-b"})
	if err = root.Execute(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if switches.Load() != 1 || !bytes.Equal(before, after) || !strings.Contains(out.String(), "selection_version") {
		t.Fatal("switch changed config rather than server primary")
	}
}

func TestPrimaryGatewayRefusesRetiredAndInsecureMetadata(t *testing.T) {
	for _, server := range []string{"http://gateway.test/k8s", "https://gateway.test/k8s/sessions/" + sessionA, "https://gateway.test/k8s/auto/a-123", "https://gateway.test/k8s?target=evil", "https://user:password@gateway.test/k8s"} {
		if err := validateConnection(Connection{Server: server}); err == nil {
			t.Fatal("unsafe or retired connection accepted", server)
		}
	}
	if err := validateConnection(Connection{Server: "https://gateway.test/k8s"}); err != nil {
		t.Fatal(err)
	}
	c, _ := testAccessClient(t, func(http.ResponseWriter, *http.Request) {})
	if _, err := c.gatewayConfig(Connection{Server: "https://gateway.test/k8s", CertificateAuthorityData: "not-base64"}); err == nil {
		t.Fatal("invalid CA accepted")
	}
	tlsServer := httptest.NewTLSServer(http.NotFoundHandler())
	defer tlsServer.Close()
	publicCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caPath, publicCA, 0600); err != nil {
		t.Fatal(err)
	}
	c.APICAFile = caPath
	if _, err := c.setupGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, append(publicCA, []byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.setupGateway(context.Background()); err == nil {
		t.Fatal("mixed public/private CA accepted")
	}
}

func TestPrimaryHeartbeatStopsOnSelectionChangeAndNeverBooks(t *testing.T) {
	identity := testAccessIdentity()
	now := time.Now()
	var heartbeats atomic.Int32
	c, _ := testAccessClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/v1/access" {
			_ = json.NewEncoder(w).Encode(primaryAccess{Session: model.Session{ID: sessionB, Owner: identity.Key(), State: "ACTIVE", LastActivityAt: &now}, SelectionVersion: 2})
			return
		}
		heartbeats.Add(1)
		w.WriteHeader(400)
	})
	saveAccessTestToken(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.runPrimaryHeartbeat(ctx, identity.Key(), sessionA, 1, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if heartbeats.Load() != 0 {
		t.Fatal("worker renewed a different selection or booked")
	}
}
