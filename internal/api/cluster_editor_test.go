package api_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"k8s.io/client-go/tools/clientcmd"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestAdminClusterEditorProtectsOriginalCredentials(t *testing.T) {
	var hits atomic.Int64
	g := newGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }), false)
	path := "/v1/admin/clusters/cluster"
	for _, token := range []string{"", "invalid", "alice", "bob"} {
		code := 403
		if token == "" || token == "invalid" {
			code = 401
		}
		expectAPI(t, g, "GET", path, token, "", code)
		expectAPI(t, g, "POST", path+"/kubeconfig", token, `{"reason":"inspect connection"}`, code)
	}
	pat := createPersonal(t, g, "alice")
	expectAPI(t, g, "POST", path+"/kubeconfig", personalSecret(t, pat), `{"reason":"inspect connection"}`, 401)
	for _, body := range []string{``, `{}`, `null`, `{"reason":" "}`, `{"reason":null}`, `{"reason":"inspect","url":"https://other.test"}`} {
		expectAPI(t, g, "POST", path+"/kubeconfig", "admin", body, 400)
	}
	metadata := expectAPI(t, g, "GET", path, "admin", "", 200)
	var cluster model.Cluster
	if json.Unmarshal([]byte(metadata), &cluster) != nil || cluster.RegistryVersion < 1 || strings.Contains(metadata, "upstream-secret-only") || strings.Contains(metadata, "kubeconfig_ciphertext") {
		t.Fatal("administrator metadata must include a version but no credentials")
	}
	var before, after []byte
	if err := g.db.Pool.QueryRow(t.Context(), "SELECT kubeconfig_ciphertext FROM clusters WHERE id='cluster'").Scan(&before); err != nil {
		t.Fatal(err)
	}
	resp := request(t, "POST", g.frontend.URL+path+"/kubeconfig", "admin", `{"reason":"inspect connection"}`)
	var reveal struct {
		Kubeconfig      string `json:"kubeconfig"`
		RegistryVersion int64  `json:"registry_version"`
	}
	if err := json.Unmarshal([]byte(readResponse(t, resp)), &reveal); err != nil || resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(reveal.Kubeconfig, "upstream-secret-only") || reveal.RegistryVersion != cluster.RegistryVersion {
		t.Fatal("protected reveal failed", err)
	}
	if _, err := clientcmd.Load([]byte(reveal.Kubeconfig)); err != nil {
		t.Fatal("reveal is not original YAML")
	}
	if err := g.db.Pool.QueryRow(t.Context(), "SELECT kubeconfig_ciphertext FROM clusters WHERE id='cluster'").Scan(&after); err != nil || !bytes.Equal(before, after) {
		t.Fatal("view changed credential")
	}
	var count int
	if err := g.db.Pool.QueryRow(t.Context(), "SELECT count(*) FROM audit WHERE action='cluster_kubeconfig_view' AND actor=$1", (model.Identity{Issuer: g.alice.Issuer, Subject: "admin"}).Key()).Scan(&count); err != nil || count != 1 {
		t.Fatal("credential reveal missing trusted audit", count, err)
	}
	for _, address := range []string{"/v1/clusters", "/v1/sessions/" + g.session.ID, path} {
		token := "alice"
		if address == path {
			token = "admin"
		}
		body := expectAPI(t, g, "GET", address, token, "", 200)
		if strings.Contains(body, "upstream-secret-only") || strings.Contains(body, "certificate-authority-data") {
			t.Fatal("credential leaked into metadata")
		}
	}
	if hits.Load() != 0 {
		t.Fatal("editing/viewing registry contacted Kubernetes")
	}
}

func TestAdminClusterEditorValidatesAndFencesDrafts(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected upstream request") }), false)
	path := "/v1/admin/clusters/cluster"
	for _, body := range []string{
		`{"name":"updated","reason":"missing version"}`,
		`{"name":null,"expected_version":1,"reason":"null"}`,
		`{"name":" ","expected_version":1,"reason":"empty"}`,
		`{"max_participants":1,"expected_version":1,"reason":"too small"}`,
		`{"max_participants":2.5,"expected_version":1,"reason":"fraction"}`,
		`{"health_profile":"none","expected_version":1,"reason":"unsupported"}`,
		`{"expected_version":null,"name":"changed","reason":"null"}`,
		`{"expected_version":0,"name":"changed","reason":"invalid version"}`,
		`{"kubeconfig":null,"expected_version":1,"reason":"null"}`,
		`{"kubeconfig":"","expected_version":1,"reason":"empty"}`,
		`{"kubeconfig":"token: sensitive-not-yaml","expected_version":1,"reason":"invalid"}`,
		`{"id":"different","expected_version":1,"reason":"immutable"}`,
	} {
		expectAPI(t, g, "PATCH", path, "admin", body, 400)
	}
	var initial model.Cluster
	json.Unmarshal([]byte(expectAPI(t, g, "GET", path, "admin", "", 200)), &initial)
	body, _ := json.Marshal(map[string]any{"name": "Updated cluster", "labels": map[string]string{"region": "eu"}, "max_participants": 3, "maintenance": true, "health_profile": "discovery-only.v1", "expected_version": initial.RegistryVersion, "reason": "update registration"})
	var updated model.Cluster
	if err := json.Unmarshal([]byte(expectAPI(t, g, "PATCH", path, "admin", string(body), 200)), &updated); err != nil || updated.RegistryVersion != initial.RegistryVersion+1 || updated.Name != "Updated cluster" || updated.MaxParticipants != 3 || !updated.Maintenance || updated.Labels["region"] != "eu" || updated.Health.Profile != model.HealthProfileDiscoveryOnly || updated.Health.State != "UNKNOWN" {
		t.Fatal("full update was not atomic/versioned", err)
	}
	stale, _ := json.Marshal(map[string]any{"name": "stale", "maintenance": false, "expected_version": initial.RegistryVersion, "reason": "stale edit"})
	expectAPI(t, g, "PATCH", path, "admin", string(stale), 409)
	current, err := g.db.Cluster(t.Context(), "cluster")
	if err != nil || current.Name != updated.Name || !current.Maintenance {
		t.Fatal("stale update changed fields", err)
	}
	var secretAudits int
	if err = g.db.Pool.QueryRow(t.Context(), "SELECT count(*) FROM audit WHERE detail LIKE '%upstream-secret-only%' OR detail LIKE '%sensitive-not-yaml%'").Scan(&secretAudits); err != nil || secretAudits != 0 {
		t.Fatal("credential contents were audited", err)
	}
}

func TestAdminCredentialReplacementClosesOldStreamAndKeepsBooking(t *testing.T) {
	started, ended := make(chan struct{}), make(chan struct{})
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "original stream")
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(ended)
	}), false)
	pat := createPersonal(t, g, "alice")
	resp := request(t, "GET", g.url("/api/v1/pods?watch=true"), personalSecret(t, pat), "")
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "original stream\n" {
		t.Fatal("old stream did not start", err)
	}
	<-started
	var newHits atomic.Int64
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		newHits.Add(1)
		if r.Header.Get("Authorization") != "Bearer replacement-secret-only" {
			http.Error(w, "wrong identity", 401)
			return
		}
		fmt.Fprint(w, "replacement upstream")
	}))
	defer up.Close()
	config := clientapi.NewConfig()
	config.CurrentContext = "new"
	config.Clusters["new"] = &clientapi.Cluster{Server: up.URL, CertificateAuthorityData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.Certificate().Raw})}
	config.AuthInfos["new"] = &clientapi.AuthInfo{Token: "replacement-secret-only"}
	config.Contexts["new"] = &clientapi.Context{Cluster: "new", AuthInfo: "new"}
	raw, err := clientcmd.Write(*config)
	if err != nil {
		t.Fatal(err)
	}
	before, err := g.db.Profile(t.Context(), g.alice)
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := g.db.Cluster(t.Context(), "cluster")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"kubeconfig": string(raw), "expected_version": cluster.RegistryVersion, "reason": "rotate connection"})
	response := expectAPI(t, g, "PATCH", "/v1/admin/clusters/cluster", "admin", string(payload), 200)
	if strings.Contains(response, "replacement-secret-only") {
		t.Fatal("update response disclosed credentials")
	}
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Fatal("replaced transport retained active stream")
	}
	_, _ = io.Copy(io.Discard, reader)
	after, err := g.db.Profile(t.Context(), g.alice)
	if err != nil || after.PrimarySession == nil || after.PrimarySession.ID != before.PrimarySession.ID || after.SelectionVersion != before.SelectionVersion {
		t.Fatal("credential edit changed booking or selection", err)
	}
	updated, err := g.db.Cluster(t.Context(), "cluster")
	if err != nil || updated.Health.State != "UNKNOWN" || updated.ConfigurationGeneration != cluster.ConfigurationGeneration+1 {
		t.Fatal("old health survived credential replacement", err)
	}
	response = readResponse(t, request(t, "GET", g.url("/version"), personalSecret(t, pat), ""))
	if response != "replacement upstream" || newHits.Load() != 1 {
		t.Fatal("same PAT did not use new connection")
	}
	var auditLeak bool
	if err = g.db.Pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM audit WHERE detail LIKE '%replacement-secret-only%' OR detail LIKE '%PRIVATE KEY%')").Scan(&auditLeak); err != nil || auditLeak {
		t.Fatal("replacement leaked into audit", err)
	}
}
