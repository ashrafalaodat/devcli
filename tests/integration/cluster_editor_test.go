package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/testutil"
)

// Exercise original-config disclosure and full editor writes through the real
// browser SSO/CSRF boundary, with an owned verified-TLS API and isolated schema.
func TestBrowserClusterEditor(t *testing.T) {
	api, issuer := os.Getenv("DEVCTL_TEST_WEB_URL"), os.Getenv("DEVCTL_TEST_ISSUER")
	if api == "" || issuer == "" {
		t.Skip("set disposable browser integration configuration")
	}
	db, dsn := testutil.Database(t)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	e := &environment{t: t, root: root, api: api, issuer: issuer, dsn: dsn, key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{53}, 32))}
	configureGatewayTLS(t, e)
	e.start()
	defer e.stop()
	admin, alice := e.browserLogin("admin", true), e.browserLogin("alice", true)
	fixture, original := newHealthFixture(t, 200)
	e.browserRequest(admin, "POST", "/v1/admin/clusters", map[string]any{"id": "editor", "name": "Editor fixture", "kubeconfig": original}, 200)
	path := "/v1/admin/clusters/editor"
	var baseline model.Cluster
	if json.Unmarshal(e.browserRequest(admin, "GET", path, nil, 200), &baseline) != nil || baseline.RegistryVersion < 1 {
		t.Fatal("missing editor snapshot")
	}
	e.browserRequest(alice, "GET", path, nil, 403)
	e.browserRequest(alice, "POST", path+"/kubeconfig", map[string]string{"reason": "inspect"}, 403)
	for _, endpoint := range []string{path + "/kubeconfig", path} {
		method, payload := "POST", `{"reason":"inspect"}`
		if endpoint == path {
			method, payload = "PATCH", `{"name":"unapproved edit","expected_version":1,"reason":"inspect"}`
		}
		for _, origin := range []string{e.api, "https://unapproved.example.test"} {
			req, _ := http.NewRequest(method, e.api+endpoint, strings.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", origin)
			if origin != e.api {
				req.Header.Set("X-CSRF-Token", admin.csrf)
			}
			response, err := admin.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != 403 {
				t.Fatal("admin config operation bypassed CSRF/Origin")
			}
		}
	}
	var reveal struct {
		Kubeconfig      string `json:"kubeconfig"`
		RegistryVersion int64  `json:"registry_version"`
	}
	if json.Unmarshal(e.browserRequest(admin, "POST", path+"/kubeconfig", map[string]string{"reason": "review original connection"}, 200), &reveal) != nil || reveal.Kubeconfig != original || reveal.RegistryVersion != baseline.RegistryVersion {
		t.Fatal("admin reveal did not return recorded config/version")
	}
	_, replacement := newHealthFixture(t, 200)
	update := map[string]any{"name": "Edited fixture", "labels": map[string]string{"purpose": "editor"}, "maintenance": true, "max_participants": 4, "health_profile": "api-ready.v1", "expected_version": baseline.RegistryVersion, "kubeconfig": replacement, "reason": "replace approved connection"}
	e.browserRequest(admin, "PATCH", path, update, 200)
	e.browserRequest(admin, "PATCH", path, update, 409)
	var current model.Cluster
	if json.Unmarshal(e.browserRequest(admin, "GET", path, nil, 200), &current) != nil || current.Name != "Edited fixture" || current.MaxParticipants != 4 || !current.Maintenance || current.RegistryVersion != baseline.RegistryVersion+1 || current.ConfigurationGeneration != baseline.ConfigurationGeneration+1 {
		t.Fatal("full browser update not persisted/versioned")
	}
	if json.Unmarshal(e.browserRequest(admin, "POST", path+"/kubeconfig", map[string]string{"reason": "verify new connection"}, 200), &reveal) != nil || reveal.Kubeconfig != replacement {
		t.Fatal("new configuration was not stored")
	}
	var leaked bool
	if err := db.Pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM audit WHERE detail LIKE '%health-fixture-secret%' OR detail LIKE '%certificate-authority-data%')").Scan(&leaked); err != nil || leaked {
		t.Fatal("credential leaked to audit", err)
	}
	for _, address := range []string{"/v1/clusters", "/v1/admin/audit"} {
		body := e.browserRequest(admin, "GET", address, nil, 200)
		if bytes.Contains(body, []byte("health-fixture-secret")) {
			t.Fatal("credential leaked to ordinary metadata")
		}
	}
	if fixture.unsafe.Load() != 0 {
		t.Fatal("health worker changed Kubernetes")
	}
	e.stop()
	e.start()
	if json.Unmarshal(e.browserRequest(admin, "POST", path+"/kubeconfig", map[string]string{"reason": "verify after restart"}, 200), &reveal) != nil || reveal.Kubeconfig != replacement {
		t.Fatal("restart lost encrypted configuration")
	}
}
