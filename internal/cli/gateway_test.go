package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"devctl.local/devctl/internal/auth"
	"golang.org/x/oauth2"
	"k8s.io/client-go/tools/clientcmd"
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
func metadataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer devctl-api-token-sentinel" {
		http.Error(w, "not authenticated", 401)
		return
	}
	if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/connection") {
		http.Error(w, "wrong endpoint", 404)
		return
	}
	json.NewEncoder(w).Encode(Connection{Server: "https://gateway.example.test/k8s/sessions/" + strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/sessions/"), "/connection")})
}

func TestGatewayKubeconfigContainsNoCredentialsAndPreservesProfile(t *testing.T) {
	c, _ := testGatewayClient(t, metadataHandler)
	path, e := c.download(context.Background(), sessionA)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{"devctl-api-token-sentinel", "refresh-token-sentinel", "client-key-data:", "client-certificate-data:", "token:"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("credential leaked to gateway kubeconfig: %s", secret)
		}
	}
	cfg, e := clientcmd.Load(raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = clientcmd.Validate(*cfg); e != nil {
		t.Fatal(e)
	}
	cluster := cfg.Clusters["devctl"]
	if cluster.Server != "https://gateway.example.test/k8s/sessions/"+sessionA || cluster.InsecureSkipTLSVerify {
		t.Fatal("wrong gateway endpoint or TLS", cluster.Server)
	}
	user := cfg.AuthInfos["devctl"]
	if user.Exec == nil || user.Token != "" || len(user.ClientKeyData) > 0 {
		t.Fatal("credential-bearing auth info")
	}
	if !filepath.IsAbs(user.Exec.Command) || user.Exec.APIVersion != "client.authentication.k8s.io/v1" || user.Exec.InteractiveMode != "Never" {
		t.Fatal("exec plugin command not portable", user.Exec)
	}
	if strings.Join(user.Exec.Args, "|") != "--api|"+c.URL+"|credential|--session|"+sessionA {
		t.Fatal("wrong plugin args", user.Exec.Args)
	}
	vars := map[string]string{}
	for _, v := range user.Exec.Env {
		vars[v.Name] = v.Value
	}
	if vars["DEVCTL_CONFIG_DIR"] != filepath.Dir(c.Login.Dir) || vars["DEVCTL_DEV_HTTP"] != "1" || vars["DEVCTL_DEV_TOKEN_FILE"] != "1" {
		t.Fatal("profile not preserved", vars)
	}
	var settings auth.Config
	if e = json.Unmarshal([]byte(vars["DEVCTL_OIDC_CONFIG"]), &settings); e != nil || settings.Issuer != c.Login.Config.Issuer {
		t.Fatal("issuer profile missing", e)
	}
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("gateway config permissions", e)
	}
}

func TestCredentialReturnsOnlyExpiringDevctlTokenAndRefusesEndedSession(t *testing.T) {
	ended := false
	c, out := testGatewayClient(t, func(w http.ResponseWriter, r *http.Request) {
		if ended {
			w.WriteHeader(409)
			json.NewEncoder(w).Encode(map[string]string{"error": "session ended"})
			return
		}
		metadataHandler(w, r)
	})
	if e := c.credential(context.Background(), sessionA); e != nil {
		t.Fatal(e)
	}
	var document struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     struct {
			Token      string    `json:"token"`
			Expiration time.Time `json:"expirationTimestamp"`
		} `json:"status"`
	}
	decoder := json.NewDecoder(out)
	if e := decoder.Decode(&document); e != nil {
		t.Fatal(e)
	}
	if e := decoder.Decode(new(any)); e != io.EOF {
		t.Fatal("extra plugin stdout", e)
	}
	if document.APIVersion != "client.authentication.k8s.io/v1" || document.Kind != "ExecCredential" || document.Status.Token != "devctl-api-token-sentinel" || !document.Status.Expiration.After(time.Now()) {
		t.Fatal("invalid exec credential")
	}
	out.Reset()
	ended = true
	e := c.credential(context.Background(), sessionA)
	var exit *ExitError
	if !errors.As(e, &exit) || exit.Code != 4 || out.Len() != 0 {
		t.Fatal("ended session exposed credentials", e)
	}
	if e = c.Login.clear(); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	e = c.credential(context.Background(), sessionA)
	if !errors.As(e, &exit) || exit.Code != 3 || out.Len() != 0 {
		t.Fatal("missing login exposed credentials", e)
	}
}

func TestSelectionSwitchingAndLogoutFailClosed(t *testing.T) {
	c, _ := testGatewayClient(t, metadataHandler)
	if _, e := c.selectSession(context.Background(), sessionA); e != nil {
		t.Fatal(e)
	}
	if _, e := c.selectSession(context.Background(), sessionB); e != nil {
		t.Fatal(e)
	}
	if e := c.clearActive(context.Background(), sessionA); e != nil {
		t.Fatal(e)
	}
	cfg, e := clientcmd.LoadFromFile(c.activePath())
	if e != nil || cfg.CurrentContext != sessionB {
		t.Fatal("stopping another session changed active selection", e)
	}
	if e = c.clearActive(context.Background(), sessionB); e != nil {
		t.Fatal(e)
	}
	cfg, e = clientcmd.LoadFromFile(c.activePath())
	if e != nil {
		t.Fatal(e)
	}
	if e = clientcmd.Validate(*cfg); e == nil {
		t.Fatal("inactive configuration unexpectedly usable")
	}
	if cfg.CurrentContext != "devctl-no-active-session" {
		t.Fatal("wrong inactive context")
	}
	if _, e = os.Stat(c.activePath()); e != nil {
		t.Fatal("active path removed, allowing unexpected fallback", e)
	}
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

func TestGatewayRejectsInsecureMetadata(t *testing.T) {
	c, _ := testGatewayClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Connection{Server: "http://untrusted.example.test"})
	})
	if _, e := c.download(context.Background(), sessionA); e == nil {
		t.Fatal("insecure non-loopback gateway accepted")
	}
	if _, e := c.gatewayConfig(sessionA, Connection{Server: "https://gateway.example.test", CertificateAuthorityData: "not-base64"}); e == nil {
		t.Fatal("malformed gateway CA accepted")
	}
	ca := base64.StdEncoding.EncodeToString([]byte("public-ca-data"))
	raw, e := c.gatewayConfig(sessionA, Connection{Server: "https://gateway.example.test", CertificateAuthorityData: ca})
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := clientcmd.Load(raw)
	if e != nil || string(cfg.Clusters["devctl"].CertificateAuthorityData) != "public-ca-data" {
		t.Fatal("gateway public CA not preserved", e)
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
