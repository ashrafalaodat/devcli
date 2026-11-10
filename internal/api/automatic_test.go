package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"github.com/google/uuid"
)

type automaticAuth struct{ expiry time.Time }

func (a automaticAuth) Verify(_ context.Context, token string) (model.Identity, error) {
	if token != "alice" && token != "bob" && token != "missing-expiry" && token != "expired" {
		return model.Identity{}, errors.New("invalid token")
	}
	u := model.Identity{Issuer: "https://issuer.test", Subject: token, Name: token, TokenExpiresAt: a.expiry}
	if token == "missing-expiry" {
		u.TokenExpiresAt = time.Time{}
	}
	if token == "expired" {
		u.TokenExpiresAt = time.Now().Add(-time.Minute)
	}
	return u, nil
}

func TestAutomaticAPIProtectsMetadataAndActivity(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"gitVersion":"fixture"}`))
	}), false)
	g.frontend.Close()
	expiry := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	g.app.Auth = automaticAuth{expiry}
	g.frontend = httptest.NewServer(g.app.Handler())
	t.Cleanup(g.frontend.Close)
	binding := "a-" + uuid.NewString()
	path := g.frontend.URL + "/v1/auto/" + binding
	resp := request(t, "GET", path, "alice", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatal("unknown binding was not rejected", readResponse(t, resp))
	}
	resp.Body.Close()
	resp = request(t, "POST", path+"/ensure", "alice", `{}`)
	body := readResponse(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("automatic ensure failed", resp.StatusCode, body)
	}
	var access struct {
		store.AutomaticAccess
		Server string `json:"server"`
	}
	if err := json.Unmarshal([]byte(body), &access); err != nil {
		t.Fatal(err)
	}
	if access.Session.ID != g.session.ID || access.Server != g.app.PublicURL+"/k8s/auto/"+binding || !access.AuthorizationExpiresAt.Equal(expiry) {
		t.Fatal("automatic metadata did not reuse the same owned booking")
	}
	if strings.Contains(body, "upstream-secret-only") || strings.Contains(body, g.upstream.URL) {
		t.Fatal("original Kubernetes configuration leaked into automatic metadata")
	}
	for _, test := range []struct {
		method, suffix, token, body string
		want                        int
	}{
		{"GET", "", "bob", "", http.StatusNotFound},
		{"POST", "/heartbeat", "bob", `{}`, http.StatusNotFound},
		{"POST", "/heartbeat", "alice", `{}`, http.StatusConflict},
		{"POST", "/heartbeat", "alice", `{"authorization_expires_at":"2099-01-01T00:00:00Z"}`, http.StatusBadRequest},
		{"POST", "/ensure", "alice", `{"token_expires_at":"2099-01-01T00:00:00Z"}`, http.StatusBadRequest},
		{"POST", "/ensure", "alice", `{"ttl":"0s"}`, http.StatusBadRequest},
		{"POST", "/ensure", "missing-expiry", `{}`, http.StatusUnauthorized},
		{"POST", "/ensure", "expired", `{}`, http.StatusUnauthorized},
		{"POST", "/ensure", "alice", `{"cluster":"different"}`, http.StatusConflict},
	} {
		t.Run(test.method+test.suffix+"/"+test.token+"/"+test.body, func(t *testing.T) {
			resp := request(t, test.method, path+test.suffix, test.token, test.body)
			body := readResponse(t, resp)
			if resp.StatusCode != test.want {
				t.Fatal("unexpected automatic endpoint status", resp.StatusCode, test.want, body)
			}
		})
	}
	metadata, err := g.db.Automatic(context.Background(), model.Identity{Issuer: "https://issuer.test", Subject: "alice"}, binding)
	if err != nil || metadata.Session.LastActivityAt != nil {
		t.Fatal("control-plane requests or rejected heartbeats counted as work", err)
	}
	resp = request(t, "GET", g.frontend.URL+"/k8s/auto/"+binding+"/version", "alice", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatal("automatic gateway did not forward", readResponse(t, resp))
	}
	resp.Body.Close()
	resp = request(t, "POST", path+"/heartbeat", "alice", "")
	body = readResponse(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "last_activity_at") {
		t.Fatal("real gateway activity did not permit renewal", resp.StatusCode, body)
	}
	resp = request(t, "GET", g.frontend.URL+"/k8s/auto/"+binding+"/version", "expired", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("an expired JWT was accepted for a new gateway request", readResponse(t, resp))
	}
	resp.Body.Close()
	if err := g.db.Stop(context.Background(), g.alice, g.session.ID, "explicitly stopped", false); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"/ensure", "/heartbeat"} {
		resp := request(t, "POST", path+suffix, "alice", `{}`)
		if resp.StatusCode != http.StatusConflict {
			t.Fatal("ended automatic booking was silently reactivated", readResponse(t, resp))
		}
		resp.Body.Close()
	}
}
