package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"devctl.local/devctl/internal/auth"
	"devctl.local/devctl/internal/model"
	"encoding/base64"
	"encoding/json"
	"errors"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testAccessClient(t *testing.T, handler http.HandlerFunc) (*Client, *bytes.Buffer) {
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

func testAccessIdentity() model.Identity {
	return model.Identity{Issuer: "https://identity.example.test", Subject: "alice", Name: "alice", DisplayName: "Alice"}
}

func saveAccessTestToken(t *testing.T, c *Client) {
	t.Helper()
	if err := c.Login.save(&oauth2.Token{AccessToken: "automatic-access-sentinel", RefreshToken: "automatic-refresh-sentinel", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
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

func TestConcurrentInteractiveFirstLoginUsesOneCodeFlow(t *testing.T) {
	c, _ := testAccessClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/whoami" || r.Header.Get("Authorization") != "Bearer browser-access" {
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(testAccessIdentity())
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
			token, err := c.loginToken(ctx, true, "")
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
