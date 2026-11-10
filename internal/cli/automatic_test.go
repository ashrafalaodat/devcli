package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/auth"
	"devctl.local/devctl/internal/model"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
	"k8s.io/client-go/tools/clientcmd"
)

func automaticTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *bytes.Buffer) {
	t.Helper()
	t.Setenv("DEVCTL_CONFIG_DIR", filepath.Join(t.TempDir(), "profile's directory"))
	t.Setenv("DEVCTL_DEV_TOKEN_FILE", "1")
	t.Setenv("DEVCTL_DEV_HTTP", "1")
	t.Setenv("DEVCTL_NO_BROWSER", "1")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent-devctl-automatic-test")
	t.Setenv("KUBERNETES_EXEC_INFO", "")
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	login, err := newLoginStore(server.URL, auth.DefaultConfig("https://identity.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	return &Client{URL: server.URL, Login: login, HTTP: server.Client(), Out: out, Err: io.Discard}, out
}

func automaticTestIdentity() model.Identity {
	return model.Identity{Issuer: "https://identity.example.test", Subject: "alice", Name: "alice", DisplayName: "Alice"}
}

func saveAutomaticTestToken(t *testing.T, c *Client) {
	t.Helper()
	if err := c.Login.save(&oauth2.Token{AccessToken: "automatic-access-sentinel", RefreshToken: "automatic-refresh-sentinel", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

func TestAutomaticSetupIsOfflinePrivateStableAndExplicitlyReactivated(t *testing.T) {
	var requests atomic.Int32
	c, _ := automaticTestClient(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) })
	booking := model.Booking{Cluster: "cluster-a", Selector: map[string]string{"type": "test"}, TTL: "60m"}
	path, err := c.setupAutomatic(context.Background(), booking, false, true)
	if err != nil {
		t.Fatal(err)
	}
	state, err := c.readAutomaticState()
	if err != nil {
		t.Fatal(err)
	}
	if !automaticID.MatchString(state.Binding) || state.Booking.TTL != "1h0m0s" || state.Owner != "" {
		t.Fatal("unexpected initial automatic selection")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := clientcmd.Load(raw)
	if err != nil || clientcmd.Validate(*cfg) != nil {
		t.Fatal("invalid automatic kubeconfig", err)
	}
	plugin := cfg.AuthInfos["devctl"].Exec
	if cfg.CurrentContext != state.Binding || cfg.Clusters["devctl"].Server != c.automaticServer(state.Binding) || plugin == nil || plugin.InteractiveMode != "IfAvailable" ||
		strings.Join(plugin.Args, "|") != "--api|"+c.URL+"|credential|--auto|"+state.Binding {
		t.Fatal("automatic routing or credential invocation is wrong")
	}
	for _, secret := range []string{"token:", "client-key-data:", "client-certificate-data:", "refresh_token"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("automatic kubeconfig contains private credential fields")
		}
	}
	for _, file := range []string{path, c.automaticStatePath()} {
		info, err := os.Stat(file)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("automatic profile file is not private", err)
		}
	}
	var wg sync.WaitGroup
	errorsOut := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.setupAutomatic(context.Background(), model.Booking{}, false, false)
			errorsOut <- err
		}()
	}
	wg.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	stable, err := c.readAutomaticState()
	if err != nil || stable.Binding != state.Binding {
		t.Fatal("concurrent setup changed its reservation binding", err)
	}
	if _, err = c.setupAutomatic(context.Background(), model.Booking{Cluster: "other"}, false, true); err == nil {
		t.Fatal("selection changed without explicit reactivation")
	}
	if _, err = c.setupAutomatic(context.Background(), model.Booking{}, true, false); err != nil {
		t.Fatal(err)
	}
	reset, err := c.readAutomaticState()
	if err != nil || reset.Binding == state.Binding || reset.Booking.Cluster != booking.Cluster {
		t.Fatal("reactivation did not retain selection and replace the binding", err)
	}
	if requests.Load() != 0 {
		t.Fatal("setup contacted a service before the first kubectl request")
	}
	if _, err = c.Login.read(); err == nil {
		t.Fatal("setup created a login")
	}
}

func TestAutomaticSetupRejectsPrivateCABundlesAndUnsafeState(t *testing.T) {
	c, _ := automaticTestClient(t, func(http.ResponseWriter, *http.Request) {})
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	ca = append(ca, []byte("-----BEGIN PRIVATE KEY-----\nZHVtbXk=\n-----END PRIVATE KEY-----\n")...)
	path := filepath.Join(t.TempDir(), "mixed.pem")
	if err := os.WriteFile(path, ca, 0600); err != nil {
		t.Fatal(err)
	}
	c.APICAFile = path
	if _, err := c.setupAutomatic(context.Background(), model.Booking{}, false, true); err == nil {
		t.Fatal("setup published a mixed public/private bundle")
	}
	if _, err := os.Stat(c.automaticStatePath()); !os.IsNotExist(err) {
		t.Fatal("failed setup wrote reservation metadata")
	}
	c.APICAFile = ""
	if _, err := c.setupAutomatic(context.Background(), model.Booking{}, false, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(c.automaticStatePath(), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.readAutomaticState(); err == nil {
		t.Fatal("world-readable automatic state accepted")
	}
	if err := os.Remove(c.automaticStatePath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, c.automaticStatePath()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.readAutomaticState(); err == nil {
		t.Fatal("symlink automatic state accepted")
	}
}

func TestAutomaticCredentialWithoutInteractiveLoginFailsClosed(t *testing.T) {
	var requests atomic.Int32
	c, out := automaticTestClient(t, func(http.ResponseWriter, *http.Request) { requests.Add(1) })
	if _, err := c.setupAutomatic(context.Background(), model.Booking{}, false, true); err != nil {
		t.Fatal(err)
	}
	state, _ := c.readAutomaticState()
	for _, info := range []string{"", `{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","spec":{"interactive":false}}`, "malformed"} {
		t.Setenv("KUBERNETES_EXEC_INFO", info)
		err := c.automaticCredential(context.Background(), state.Binding)
		var exit *ExitError
		if !errors.As(err, &exit) || exit.Code != 3 || out.Len() != 0 {
			t.Fatal("noninteractive login did not fail without credentials", err)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("noninteractive missing login contacted a backend")
	}
}

func TestAutomaticCredentialRejectsBackendDenialWithoutAllocating(t *testing.T) {
	for _, test := range []struct {
		name        string
		status      int
		interactive bool
	}{
		{"invalid_token_noninteractive", http.StatusUnauthorized, false},
		{"unapproved_user_interactive", http.StatusForbidden, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			c, out := automaticTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != "/v1/whoami" {
					t.Error("denied login attempted allocation")
				}
				w.WriteHeader(test.status)
				json.NewEncoder(w).Encode(map[string]string{"error": "login denied"})
			})
			saveAutomaticTestToken(t, c)
			if _, err := c.setupAutomatic(context.Background(), model.Booking{}, false, true); err != nil {
				t.Fatal(err)
			}
			state, _ := c.readAutomaticState()
			info, _ := json.Marshal(map[string]any{"apiVersion": "client.authentication.k8s.io/v1", "kind": "ExecCredential", "spec": map[string]bool{"interactive": test.interactive}})
			t.Setenv("KUBERNETES_EXEC_INFO", string(info))
			var diagnostics bytes.Buffer
			c.Err = &diagnostics
			err := c.automaticCredential(context.Background(), state.Binding)
			var exit *ExitError
			if !errors.As(err, &exit) || exit.Code != 3 || out.Len() != 0 || requests.Load() != 1 || strings.Contains(diagnostics.String(), "Open this URL") {
				t.Fatal("backend denial opened login or emitted a credential", err)
			}
		})
	}
}

func TestAutomaticCredentialPinsIdentityAndEmitsOnlyBoundCredentials(t *testing.T) {
	identity := automaticTestIdentity()
	var ended, otherIdentity atomic.Bool
	var ensures atomic.Int32
	expiry := time.Now().Add(9 * time.Minute).UTC().Truncate(time.Second)
	var c *Client
	c, out := automaticTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer automatic-access-sentinel" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/v1/whoami" {
			u := identity
			if otherIdentity.Load() {
				u.Subject = "bob"
			}
			json.NewEncoder(w).Encode(u)
			return
		}
		if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/ensure") {
			w.WriteHeader(404)
			return
		}
		ensures.Add(1)
		if ended.Load() {
			w.WriteHeader(409)
			json.NewEncoder(w).Encode(map[string]string{"error": "binding ended; reactivate explicitly"})
			return
		}
		binding := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/auto/"), "/ensure")
		json.NewEncoder(w).Encode(map[string]any{"session": map[string]any{"id": sessionA, "owner": identity.Key(), "cluster": "cluster-a", "state": "ACTIVE"}, "server": c.automaticServer(binding), "authorization_expires_at": expiry})
	})
	saveAutomaticTestToken(t, c)
	if _, err := c.setupAutomatic(context.Background(), model.Booking{Cluster: "cluster-a"}, false, true); err != nil {
		t.Fatal(err)
	}
	state, _ := c.readAutomaticState()
	// Simulate an already running worker so this unit test cannot spawn itself.
	worker := c.heartbeatLock(state.Binding, sessionA)
	if ok, err := worker.TryLock(); err != nil || !ok {
		t.Fatal(err)
	}
	defer worker.Unlock()
	if err := c.automaticCredential(context.Background(), state.Binding); err != nil {
		t.Fatal(err)
	}
	var document struct {
		APIVersion, Kind string
		Status           struct {
			Token      string
			Expiration time.Time `json:"expirationTimestamp"`
		}
	}
	decoder := json.NewDecoder(out)
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	if decoder.Decode(new(any)) != io.EOF || document.Kind != "ExecCredential" || document.APIVersion != "client.authentication.k8s.io/v1" || document.Status.Token != "automatic-access-sentinel" || !document.Status.Expiration.Equal(expiry) {
		t.Fatal("invalid or extra credential output")
	}
	pinned, _ := c.readAutomaticState()
	if pinned.Owner != identity.Key() {
		t.Fatal("automatic profile did not pin its first authenticated owner")
	}
	out.Reset()
	ended.Store(true)
	if err := c.automaticCredential(context.Background(), state.Binding); err == nil || out.Len() != 0 {
		t.Fatal("ended binding emitted a credential")
	}
	ended.Store(false)
	otherIdentity.Store(true)
	out.Reset()
	before := ensures.Load()
	if err := c.automaticCredential(context.Background(), state.Binding); err == nil || out.Len() != 0 || ensures.Load() != before {
		t.Fatal("another identity could silently allocate through an already pinned profile")
	}
}

func TestAutomaticHeartbeatCountsOnlyExistingRecentWork(t *testing.T) {
	for _, test := range []struct {
		name             string
		activity         *time.Time
		state, id, owner string
	}{
		{name: "no_activity", state: "ACTIVE", id: sessionA},
		{name: "idle", activity: func() *time.Time { v := time.Now().Add(-3 * time.Minute); return &v }(), state: "ACTIVE", id: sessionA},
		{name: "ended", activity: func() *time.Time { v := time.Now(); return &v }(), state: "RELEASED", id: sessionA},
		{name: "identity_changed", activity: func() *time.Time { v := time.Now(); return &v }(), state: "ACTIVE", id: sessionB},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity := automaticTestIdentity()
			var posts atomic.Int32
			c, _ := automaticTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					posts.Add(1)
				}
				json.NewEncoder(w).Encode(map[string]any{"session": map[string]any{"id": test.id, "owner": identity.Key(), "state": test.state, "last_activity_at": test.activity}})
			})
			saveAutomaticTestToken(t, c)
			if _, err := c.setupAutomatic(context.Background(), model.Booking{}, false, true); err != nil {
				t.Fatal(err)
			}
			state, _ := c.readAutomaticState()
			state.Owner = identity.Key()
			if err := c.saveAutomaticState(state); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := c.runAutomaticHeartbeat(ctx, state.Binding, sessionA, time.Millisecond); err != nil {
				t.Fatal(err)
			}
			if posts.Load() != 0 {
				t.Fatal("worker renewed despite absent activity or changed reservation")
			}
		})
	}
	t.Run("active_and_single_instance", func(t *testing.T) {
		identity := automaticTestIdentity()
		var gets, posts atomic.Int32
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		c, _ := automaticTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				posts.Add(1)
				defer cancel()
			} else {
				gets.Add(1)
			}
			json.NewEncoder(w).Encode(map[string]any{"session": map[string]any{"id": sessionA, "owner": identity.Key(), "state": "ACTIVE", "last_activity_at": time.Now()}})
		})
		saveAutomaticTestToken(t, c)
		if _, err := c.setupAutomatic(context.Background(), model.Booking{}, false, true); err != nil {
			t.Fatal(err)
		}
		state, _ := c.readAutomaticState()
		state.Owner = identity.Key()
		c.saveAutomaticState(state)
		lock := c.heartbeatLock(state.Binding, sessionA)
		ok, err := lock.TryLock()
		if err != nil || !ok {
			t.Fatal(err)
		}
		if err = c.runAutomaticHeartbeat(ctx, state.Binding, sessionA, time.Millisecond); err != nil || gets.Load() != 0 {
			t.Fatal("duplicate worker performed requests", err)
		}
		lock.Unlock()
		if err = c.runAutomaticHeartbeat(ctx, state.Binding, sessionA, time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if gets.Load() != 1 || posts.Load() != 1 {
			t.Fatal("active worker did not perform exactly one activity check and renewal", gets.Load(), posts.Load())
		}
	})
}

func TestProactiveRefreshRotatesOnceAcrossConcurrentCommands(t *testing.T) {
	t.Setenv("DEVCTL_CONFIG_DIR", t.TempDir())
	t.Setenv("DEVCTL_DEV_TOKEN_FILE", "1")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent-devctl-refresh-test")
	var issuer string
	var exchanges atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "old-refresh" || r.Form.Get("client_secret") != "" {
			w.WriteHeader(400)
			return
		}
		exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "fresh-access", "refresh_token": "rotated-refresh", "expires_in": 600, "token_type": "Bearer"})
	})
	provider := httptest.NewServer(mux)
	defer provider.Close()
	issuer = provider.URL
	login, err := newLoginStore("https://api.example.test", auth.DefaultConfig(issuer))
	if err != nil {
		t.Fatal(err)
	}
	if err = login.save(&oauth2.Token{AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer", Expiry: time.Now().Add(20 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := login.token(context.Background())
			if err == nil && token.AccessToken != "fresh-access" {
				err = errors.New("near-expiry credential was reused")
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	stored, err := login.read()
	if err != nil || stored.RefreshToken != "rotated-refresh" || exchanges.Load() != 1 {
		t.Fatal("refresh rotation was lost or performed more than once", err, exchanges.Load())
	}
}

func TestConcurrentAutomaticFirstLoginUsesOneCodeFlow(t *testing.T) {
	c, _ := automaticTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/whoami" || r.Header.Get("Authorization") != "Bearer browser-access" {
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(automaticTestIdentity())
	})
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "automatic"))
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	var nonce, challenge atomic.Value
	nonce.Store("")
	challenge.Store("")
	var exchanges atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "automatic", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if r.Form.Get("grant_type") != "authorization_code" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge.Load().(string) || r.Form.Get("client_secret") != "" {
			w.WriteHeader(400)
			return
		}
		exchanges.Add(1)
		raw, _ := json.Marshal(map[string]any{"iss": issuer, "sub": "alice", "aud": "devctl-cli", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": nonce.Load().(string)})
		signed, _ := signer.Sign(raw)
		id, _ := signed.CompactSerialize()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "browser-access", "refresh_token": "browser-refresh", "expires_in": 600, "token_type": "Bearer", "id_token": id})
	})
	provider := httptest.NewServer(mux)
	defer provider.Close()
	issuer = provider.URL
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	callback := "http://" + listener.Addr().String() + "/callback"
	listener.Close()
	c.Login.Config = auth.DefaultConfig(issuer)
	c.Login.Config.Redirect = callback
	links := make(chan string, 8)
	c.Err = urlWriter{links}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			token, err := c.automaticToken(ctx, true, "")
			if err == nil && token.AccessToken != "browser-access" {
				err = errors.New("wrong token after automatic login")
			}
			results <- err
		}()
	}
	var address string
	select {
	case address = <-links:
	case <-ctx.Done():
		t.Fatal("no automatic login URL")
	}
	u, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	nonce.Store(u.Query().Get("nonce"))
	challenge.Store(u.Query().Get("code_challenge"))
	response, err := http.Get(callback + "?" + url.Values{"state": {u.Query().Get("state")}, "code": {"approved-code"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	for i := 0; i < 8; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if exchanges.Load() != 1 || len(links) != 0 {
		t.Fatal("concurrent commands opened more than one browser login", exchanges.Load(), len(links))
	}
}
