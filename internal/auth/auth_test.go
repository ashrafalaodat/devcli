package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	jose "github.com/go-jose/go-jose/v4"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAccessTokenValidation(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/keys", "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	issuer = srv.URL
	v, e := New(context.Background(), DefaultConfig(issuer))
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
	if e != nil {
		t.Fatal(e)
	}
	for _, tt := range []struct {
		name   string
		change func(map[string]any)
		ok     bool
	}{
		{"valid developer", func(m map[string]any) {}, true},
		{"expired", func(m map[string]any) { m["exp"] = time.Now().Add(-time.Hour).Unix() }, false},
		{"wrong issuer", func(m map[string]any) { m["iss"] = "https://wrong.test" }, false},
		{"wrong audience", func(m map[string]any) { m["aud"] = "devctl-cli" }, false},
		{"ID token with API audience", func(m map[string]any) { m["typ"] = "ID" }, false},
		{"unapproved", func(m map[string]any) { m["groups"] = []string{} }, false},
		{"no subject", func(m map[string]any) { delete(m, "sub") }, false},
		{"admin", func(m map[string]any) { m["groups"] = []string{"/administrators"} }, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := map[string]any{"iss": issuer, "sub": "123", "aud": "devctl-api", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "typ": "Bearer", "groups": []string{"/developers"}, "preferred_username": "alice", "name": "Alice Developer", "email": "alice@example.test"}
			tt.change(m)
			raw, _ := json.Marshal(m)
			signed, e := signer.Sign(raw)
			if e != nil {
				t.Fatal(e)
			}
			token, e := signed.CompactSerialize()
			if e != nil {
				t.Fatal(e)
			}
			u, e := v.Verify(context.Background(), token)
			if (e == nil) != tt.ok {
				t.Fatalf("verify %v", e)
			}
			if tt.ok && (u.Subject != "123" || u.DisplayName != "Alice Developer") {
				t.Fatal(u)
			}
			if tt.ok {
				if u.TokenExpiresAt.Unix() != m["exp"].(int64) {
					t.Fatal("trusted identity did not retain the verified token expiry")
				}
				encoded, err := json.Marshal(u)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]any
				if err := json.Unmarshal(encoded, &fields); err != nil {
					t.Fatal(err)
				}
				if fields["TokenExpiresAt"] != nil || fields["token_expires_at"] != nil {
					t.Fatal("trusted expiry leaked into stored/public identity JSON")
				}
			}
			if tt.name == "valid developer" {
				bad := token[:len(token)-8] + "AAAAAAAA"
				if _, e = v.Verify(context.Background(), bad); e == nil {
					t.Fatal("invalid signature accepted")
				}
			}
		})
	}
	if _, e = v.Verify(context.Background(), "not-a-jwt"); e == nil {
		t.Fatal("malformed token accepted")
	}
}
