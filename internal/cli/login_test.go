package cli

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"devctl.local/devctl/internal/auth"
	"encoding/base64"
	"encoding/json"
	jose "github.com/go-jose/go-jose/v4"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type urlWriter struct{ urls chan string }

func (w urlWriter) Write(b []byte) (int, error) {
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "http://") {
			w.urls <- line
		}
	}
	return len(b), nil
}
func TestLoginNonceAndPKCE(t *testing.T) {
	t.Setenv("DEVCTL_NO_BROWSER", "1")
	t.Setenv("DEVCTL_DEV_TOKEN_FILE", "1")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent-devctl-nonce-test")
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
	if e != nil {
		t.Fatal(e)
	}
	for _, good := range []bool{false, true} {
		name := "reject incorrect nonce"
		if good {
			name = "accept correct nonce"
		}
		t.Run(name, func(t *testing.T) {
			var issuer string
			var nonce, challenge atomic.Value
			nonce.Store("")
			challenge.Store("")
			mux := http.NewServeMux()
			mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/keys", "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token", "id_token_signing_alg_values_supported": []string{"RS256"}})
			})
			mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
			})
			mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
				r.ParseForm()
				sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("client_secret") != "" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge.Load().(string) {
					http.Error(w, "PKCE or public client invalid", 400)
					return
				}
				claimNonce := "wrong-nonce"
				if good {
					claimNonce = nonce.Load().(string)
				}
				raw, _ := json.Marshal(map[string]any{"iss": issuer, "sub": "alice", "aud": "devctl-cli", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": claimNonce})
				signed, _ := signer.Sign(raw)
				id, _ := signed.CompactSerialize()
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"access_token": "test-access", "refresh_token": "test-refresh", "token_type": "Bearer", "expires_in": 300, "id_token": id})
			})
			provider := httptest.NewServer(mux)
			defer provider.Close()
			issuer = provider.URL
			listener, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			callback := "http://" + listener.Addr().String() + "/callback"
			listener.Close()
			cfg := auth.DefaultConfig(issuer)
			cfg.Redirect = callback
			t.Setenv("DEVCTL_CONFIG_DIR", t.TempDir())
			store, e := newLoginStore("http://127.0.0.1:8080", cfg)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			links := make(chan string, 1)
			done := make(chan error, 1)
			go func() { done <- store.login(ctx, urlWriter{links}) }()
			var address string
			select {
			case address = <-links:
			case <-ctx.Done():
				t.Fatal("login timed out")
			}
			u, e := url.Parse(address)
			if e != nil {
				t.Fatal(e)
			}
			nonce.Store(u.Query().Get("nonce"))
			challenge.Store(u.Query().Get("code_challenge"))
			if u.Query().Get("code_challenge_method") != "S256" {
				t.Fatal("PKCE S256 missing")
			}
			r, e := http.Get(callback + "?state=forged&code=fake")
			if e != nil {
				t.Fatal(e)
			}
			r.Body.Close()
			if r.StatusCode != 400 {
				t.Fatal("forged state accepted")
			}
			r, e = http.Get(callback + "?" + url.Values{"state": {u.Query().Get("state")}, "code": {"test-code"}}.Encode())
			if e != nil {
				t.Fatal(e)
			}
			r.Body.Close()
			e = <-done
			if (e == nil) != good {
				t.Fatalf("unexpected nonce validation result %v", e)
			}
			_, readErr := store.read()
			if good && readErr != nil {
				t.Fatal(readErr)
			}
			if !good && readErr == nil {
				t.Fatal("credentials saved despite invalid nonce")
			}
		})
	}
}
