package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"devctl.local/devctl/internal/model"
)

func TestClusterLabelPatchRejectsInvalidInputAndUnapprovedUsers(t *testing.T) {
	var upstream atomic.Int64
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstream.Add(1) }), false)
	path := "/v1/admin/clusters/cluster"
	valid := `{"labels":{"region":"eu"},"expected_labels":{},"reason":"placement metadata"}`
	for _, token := range []string{"", "invalid"} {
		expectAPI(t, g, "PATCH", path, token, valid, 401)
	}
	for _, token := range []string{"alice", "bob"} {
		expectAPI(t, g, "PATCH", path, token, valid, 403)
	}
	pat := createPersonal(t, g, "alice")
	expectAPI(t, g, "PATCH", path, personalSecret(t, pat), valid, 401)
	for _, body := range []string{
		``, `{}`, `null`, `{"reason":"only a reason"}`,
		`{"labels":{},"reason":"missing snapshot"}`,
		`{"expected_labels":{},"reason":"missing labels"}`,
		`{"labels":null,"expected_labels":{},"reason":"null labels"}`,
		`{"labels":{},"expected_labels":null,"reason":"null snapshot"}`,
		`{"labels":[],"expected_labels":{},"reason":"array"}`,
		`{"labels":{"test":null},"expected_labels":{},"reason":"null string"}`,
		`{"labels":{"test":1},"expected_labels":{},"reason":"numeric value"}`,
		`{"labels":{"test":true},"expected_labels":{},"reason":"boolean value"}`,
		`{"labels":{"test":"first","test":"second"},"expected_labels":{},"reason":"duplicate key"}`,
		`{"labels":{},"expected_labels":{"old":1},"reason":"invalid snapshot"}`,
		`{"labels":{"bad key":"test"},"expected_labels":{},"reason":"invalid key"}`,
		`{"labels":{"key":"invalid,value"},"expected_labels":{},"reason":"invalid value"}`,
		`{"labels":{},"expected_labels":{},"reason":" \t\n "}`,
		`{"labels":{},"expected_labels":{},"reason":null}`,
		`{"labels":{},"expected_labels":{},"reason":"valid","admin":true}`,
		`{"maintenance":null,"reason":"must not coerce null"}`,
		`{"maintenance":"false","reason":"wrong type"}`,
		`{"maintenance":false,"expected_labels":{},"reason":"unused snapshot"}`,
		`{"maintenance":false,"reason":"valid"} {}`,
		fmt.Sprintf(`{"labels":{},"expected_labels":{},"reason":%q}`, strings.Repeat("r", 1001)),
	} {
		expectAPI(t, g, "PATCH", path, "admin", body, 400)
	}
	tooMany := map[string]string{}
	for index := range 33 {
		tooMany[fmt.Sprintf("key-%d", index)] = "value"
	}
	body, _ := json.Marshal(map[string]any{"labels": tooMany, "expected_labels": map[string]string{}, "reason": "too many labels"})
	expectAPI(t, g, "PATCH", path, "admin", string(body), 400)
	expectAPI(t, g, "PATCH", "/v1/admin/clusters/missing", "admin", valid, 404)
	c, err := g.db.Cluster(t.Context(), "cluster")
	if err != nil || len(c.Labels) != 0 || c.Maintenance {
		t.Fatal("rejected input changed metadata", err)
	}
	var audits int
	if err = g.db.Pool.QueryRow(t.Context(), "SELECT count(*) FROM audit WHERE action='cluster_labels_update'").Scan(&audits); err != nil || audits != 0 {
		t.Fatal("rejected request created success audit", err)
	}
	if upstream.Load() != 0 {
		t.Fatal("metadata validation contacted Kubernetes")
	}
}

func TestClusterLabelPatchPreservesOmittedFieldsAndCredentials(t *testing.T) {
	var upstream atomic.Int64
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstream.Add(1) }), false)
	path := "/v1/admin/clusters/cluster"
	pat := createPersonal(t, g, "alice")
	before, err := g.db.Profile(t.Context(), g.alice)
	if err != nil {
		t.Fatal(err)
	}
	var encrypted []byte
	if err = g.db.Pool.QueryRow(t.Context(), "SELECT kubeconfig_ciphertext FROM clusters WHERE id='cluster'").Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	expectAPI(t, g, "PATCH", path, "admin", `{"labels":{"example.com/team":"platform","region":"eu","marker":""},"expected_labels":{},"reason":"  team placement  "}`, 200)
	labels := map[string]string{"example.com/team": "platform", "region": "eu", "marker": ""}
	c, err := g.db.Cluster(t.Context(), "cluster")
	if err != nil || c.Maintenance || !maps.Equal(c.Labels, labels) || c.ControllerSession != g.session.ID {
		t.Fatal("label replacement changed omitted placement/holder", err)
	}
	after, err := g.db.Profile(t.Context(), g.alice)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("label replacement altered booking or primary", err)
	}
	var stillEncrypted []byte
	if err = g.db.Pool.QueryRow(t.Context(), "SELECT kubeconfig_ciphertext FROM clusters WHERE id='cluster'").Scan(&stillEncrypted); err != nil || !bytes.Equal(encrypted, stillEncrypted) {
		t.Fatal("label edit changed upstream credential", err)
	}
	if _, err = g.db.VerifyPAT(t.Context(), personalSecret(t, pat)); err != nil {
		t.Fatal("label edit invalidated PAT", err)
	}
	conflict := expectAPI(t, g, "PATCH", path, "admin", `{"labels":{},"expected_labels":{},"maintenance":true,"reason":"stale editor"}`, 409)
	if !strings.Contains(conflict, "reload") {
		t.Fatal("conflict lacks recovery instruction")
	}
	c, err = g.db.Cluster(t.Context(), "cluster")
	if err != nil || c.Maintenance || !maps.Equal(c.Labels, labels) {
		t.Fatal("stale combined edit partially applied", err)
	}
	// Existing maintenance clients need no new field, and never replace labels.
	expectAPI(t, g, "PATCH", path, "admin", `{"maintenance":true,"reason":"existing maintenance client"}`, 200)
	body, _ := json.Marshal(map[string]any{"labels": map[string]string{}, "expected_labels": labels, "reason": "clear every label"})
	expectAPI(t, g, "PATCH", path, "admin", string(body), 200)
	c, err = g.db.Cluster(t.Context(), "cluster")
	if err != nil || !c.Maintenance || len(c.Labels) != 0 {
		t.Fatal("clear reset omitted maintenance", err)
	}
	expectAPI(t, g, "PATCH", path, "admin", `{"labels":{},"expected_labels":{},"reason":"same value"}`, 200)
	var changes int
	if err = g.db.Pool.QueryRow(t.Context(), "SELECT count(*) FROM audit WHERE action='cluster_labels_update'").Scan(&changes); err != nil || changes != 2 {
		t.Fatal("label audit/no-op mismatch", changes, err)
	}
	var actor, detail string
	if err = g.db.Pool.QueryRow(t.Context(), "SELECT actor,detail FROM audit WHERE action='cluster_labels_update' ORDER BY id LIMIT 1").Scan(&actor, &detail); err != nil || actor != (model.Identity{Issuer: g.alice.Issuer, Subject: "admin"}).Key() || !strings.Contains(detail, `"reason":"team placement"`) {
		t.Fatal("audit lacks trusted identity or normalized reason", err)
	}
	if strings.Contains(detail, "upstream-secret") || strings.Contains(detail, "kubeconfig") {
		t.Fatal("audit exposed imported credential")
	}
	expectAPI(t, g, "POST", "/v1/sessions/"+g.session.ID+"/stop", "alice", "", 200)
	expectAPI(t, g, "DELETE", path, "admin", `{"reason":"retire"}`, 200)
	expectAPI(t, g, "PATCH", path, "admin", `{"labels":{"region":"eu"},"expected_labels":{},"reason":"cannot restore retired"}`, 404)
	if upstream.Load() != 0 {
		t.Fatal("label/maintenance/history operations contacted Kubernetes")
	}
}

func TestClusterLabelPatchUnavailableDoesNotExposeDatabaseErrors(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected Kubernetes call") }), false)
	g.db.Pool.Close()
	body := expectAPI(t, g, "PATCH", "/v1/admin/clusters/cluster", "admin", `{"labels":{},"expected_labels":{},"reason":"pool unavailable"}`, 503)
	if !strings.Contains(body, "unavailable") || strings.Contains(body, "closed") || strings.Contains(body, "SELECT") || strings.Contains(body, "kubeconfig") {
		t.Fatal("database failure not safely classified")
	}
}

func TestNewClusterRegistrationValidatesLabelsBeforeCredentials(t *testing.T) {
	var upstream atomic.Int64
	g := newGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstream.Add(1) }), false)
	many := map[string]string{}
	for index := range 33 {
		many[fmt.Sprintf("key-%d", index)] = "value"
	}
	for _, labels := range []map[string]string{{"bad key": "value"}, {"region": "invalid,value"}, many} {
		body, _ := json.Marshal(map[string]any{"id": "invalid-labels", "name": "Invalid label fixture", "labels": labels, "kubeconfig": "not-a-kubeconfig"})
		response := expectAPI(t, g, "POST", "/v1/admin/clusters", "admin", string(body), 400)
		if !strings.Contains(response, "label") || strings.Contains(response, "kubeconfig") {
			t.Fatal("registration parsed credentials before rejecting invalid placement labels")
		}
	}
	var created int
	if err := g.db.Pool.QueryRow(t.Context(), "SELECT count(*) FROM clusters WHERE id='invalid-labels'").Scan(&created); err != nil || created != 0 {
		t.Fatal("invalid registration created metadata", err)
	}
	if upstream.Load() != 0 {
		t.Fatal("registration validation contacted Kubernetes")
	}
}
