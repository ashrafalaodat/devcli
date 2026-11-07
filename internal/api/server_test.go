package api_test

import (
	"context"
	"devctl.local/devctl/internal/api"
	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/testutil"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type auth struct{}

func (auth) Verify(ctx context.Context, raw string) (model.Identity, error) {
	if raw != "valid" {
		return model.Identity{}, errors.New("invalid token")
	}
	return model.Identity{Issuer: "https://issuer.test", Subject: "alice"}, nil
}
func TestProtectedRoutes(t *testing.T) {
	db, _ := testutil.Database(t)
	v, _ := kube.NewVault(make([]byte, 32))
	h := (&api.Server{Store: db, Auth: auth{}, Vault: v}).Handler()
	for _, path := range []string{"/v1/whoami", "/v1/clusters", "/v1/sessions", "/v1/sessions/x/kubeconfig", "/v1/admin/clusters"} {
		for _, token := range []string{"", "Bearer invalid"} {
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("Authorization", token)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatalf("%s unexpectedly public: %d", path, w.Code)
			}
		}
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(path, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/v1/admin/clusters", nil)
	r.Header.Set("Authorization", "Bearer valid")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("non-admin registration allowed", w.Code)
	}
}
