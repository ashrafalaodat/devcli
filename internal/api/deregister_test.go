package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
)

func TestDeregisterRequiresAdministratorAndAuditedReason(t *testing.T) {
	var upstreamRequests atomic.Int64
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		fmt.Fprint(w, "upstream")
	}), false)
	path := "/v1/admin/clusters/cluster"
	for _, token := range []string{"", "invalid"} {
		expectAPI(t, g, "DELETE", path, token, `{"reason":"retire"}`, 401)
	}
	for _, token := range []string{"alice", "bob"} {
		expectAPI(t, g, "DELETE", path, token, `{"reason":"forged administrator"}`, 403)
	}
	pat := createPersonal(t, g, "alice")
	expectAPI(t, g, "DELETE", path, personalSecret(t, pat), `{"reason":"PAT has no administration scope"}`, 401)
	for _, body := range []string{
		``, `{}`, `{"reason":null}`, `{"reason":""}`, `{"reason":" \t\n "}`,
		`{"reason":123}`, `{"reason":"retire","force":true}`,
		`{"reason":"retire"} {"reason":"second document"}`,
		fmt.Sprintf(`{"reason":%q}`, strings.Repeat("x", 1001)),
	} {
		expectAPI(t, g, "DELETE", path, "admin", body, 400)
	}
	expectAPI(t, g, "DELETE", "/v1/admin/clusters/unknown", "admin", `{"reason":"unknown registry entry"}`, 404)
	var registered bool
	var audits int
	if err := g.db.Pool.QueryRow(t.Context(), "SELECT deregistered_at IS NULL AND kubeconfig_ciphertext IS NOT NULL FROM clusters WHERE id='cluster'").Scan(&registered); err != nil || !registered {
		t.Fatal("rejected deregistration changed registry credentials", err)
	}
	if err := g.db.Pool.QueryRow(t.Context(), "SELECT count(*) FROM audit WHERE action='deregister'").Scan(&audits); err != nil || audits != 0 {
		t.Fatal("rejected deregistration created a success audit", err)
	}
	if upstreamRequests.Load() != 0 {
		t.Fatal("administration contacted Kubernetes")
	}
}

func TestDeregisterPreservesHistoryAndPATsWithoutContactingKubernetes(t *testing.T) {
	var upstreamRequests atomic.Int64
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		fmt.Fprint(w, "upstream")
	}), false)
	addPrimaryFixture(t, g, "untouched", "another cluster")
	pat := createPersonal(t, g, "alice")
	secret := personalSecret(t, pat)
	path := "/v1/admin/clusters/cluster"
	if body := expectAPI(t, g, "DELETE", path, "admin", `{"reason":"retire private cluster"}`, 409); !strings.Contains(strings.ToLower(body), "booking") {
		t.Fatal("active booking conflict did not explain what must end first")
	}
	if err := g.db.Share(t.Context(), g.alice, g.session.ID, true); err != nil {
		t.Fatal(err)
	}
	bob := model.Identity{Issuer: g.alice.Issuer, Subject: "bob", Name: "bob"}
	joined, _, err := g.db.Book(t.Context(), bob, model.Booking{Cluster: "cluster"}, "bob-shared")
	if err != nil {
		t.Fatal(err)
	}
	expectAPI(t, g, "DELETE", path, "admin", `{"reason":"retire shared cluster"}`, 409)
	expectAPI(t, g, "POST", "/v1/sessions/"+g.session.ID+"/stop", "alice", "", 200)
	expectAPI(t, g, "DELETE", path, "admin", `{"reason":"other holder still active"}`, 409)
	expectAPI(t, g, "POST", "/v1/sessions/"+joined.ID+"/stop", "bob", "", 200)
	result := expectAPI(t, g, "DELETE", path, "admin", `{"reason":"  retired after tests  "}`, 200)
	var status struct {
		Status string `json:"status"`
	}
	if json.Unmarshal([]byte(result), &status) != nil || !strings.HasPrefix(status.Status, "deregistered") {
		t.Fatal("deregistration did not return its outcome")
	}
	var removedCredentials bool
	var archivedAt time.Time
	if err = g.db.Pool.QueryRow(t.Context(), "SELECT kubeconfig_ciphertext IS NULL,deregistered_at FROM clusters WHERE id='cluster'").Scan(&removedCredentials, &archivedAt); err != nil || !removedCredentials || archivedAt.IsZero() {
		t.Fatal("deregistration retained encrypted upstream credentials", err)
	}
	expectAPI(t, g, "DELETE", path, "admin", `{"reason":"retry after lost response"}`, 200)
	var again time.Time
	if err = g.db.Pool.QueryRow(t.Context(), "SELECT deregistered_at FROM clusters WHERE id='cluster'").Scan(&again); err != nil || !again.Equal(archivedAt) {
		t.Fatal("retry changed the original deregistration time", err)
	}
	var audits int
	var actor, auditDetail string
	if err = g.db.Pool.QueryRow(t.Context(), "SELECT count(*) FROM audit WHERE action='deregister' AND object_id='cluster'").Scan(&audits); err != nil || audits != 1 {
		t.Fatal("deregistration was not audited exactly once", err)
	}
	if err = g.db.Pool.QueryRow(t.Context(), "SELECT actor,detail FROM audit WHERE action='deregister' AND object_id='cluster'").Scan(&actor, &auditDetail); err != nil || actor != (model.Identity{Issuer: g.alice.Issuer, Subject: "admin"}).Key() || !strings.Contains(auditDetail, "reason: retired after tests") {
		t.Fatal("administrator identity or audit reason missing", err)
	}
	var clusters []model.Cluster
	if json.Unmarshal([]byte(expectAPI(t, g, "GET", "/v1/clusters", "alice", "", 200)), &clusters) != nil || len(clusters) != 1 || clusters[0].ID != "untouched" {
		t.Fatal("deregistered cluster remained listed or another cluster disappeared")
	}
	var detail struct {
		Session model.Session `json:"session"`
		Cluster model.Cluster `json:"cluster"`
	}
	history := expectAPI(t, g, "GET", "/v1/sessions/"+g.session.ID, "alice", "", 200)
	if json.Unmarshal([]byte(history), &detail) != nil || detail.Session.State != "RELEASED" || detail.Session.ID != g.session.ID || detail.Cluster.ID != "cluster" || detail.Cluster.Name != "Cluster" || detail.Cluster.DeregisteredAt == nil {
		t.Fatal("historical booking lost its archived cluster metadata")
	}
	if strings.Contains(history, "kubeconfig") || strings.Contains(history, "upstream-secret") {
		t.Fatal("history exposed credential material")
	}
	old, created, err := g.db.Book(t.Context(), g.alice, model.Booking{}, "one")
	if err != nil || created || old.ID != g.session.ID || old.State != "RELEASED" {
		t.Fatal("old idempotency key did not preserve the historical booking", err)
	}
	if _, _, err = g.db.Book(t.Context(), g.alice, model.Booking{Cluster: "cluster"}, "fresh-archived-request"); err == nil {
		t.Fatal("new booking allocated a deregistered cluster")
	}
	expectAPI(t, g, "PATCH", path, "admin", `{"maintenance":false,"reason":"cannot reactivate through maintenance"}`, 404)
	if _, err = g.db.VerifyPAT(t.Context(), secret); err != nil {
		t.Fatal("deregistering cluster revoked a developer-wide PAT", err)
	}
	rows, err := g.db.PATs(t.Context(), g.alice, false)
	if err != nil || len(rows) != 1 || rows[0].RevokedAt != nil || !rows[0].ExpiresAt.Equal(pat.PAT.ExpiresAt) {
		t.Fatal("deregistration changed independent PAT metadata", err)
	}
	if body := expectAPI(t, g, "GET", "/k8s/version", secret, "", 403); !strings.Contains(body, "no cluster is booked") {
		t.Fatal("retained PAT obtained access to an archived cluster")
	}
	if upstreamRequests.Load() != 0 {
		t.Fatal("deregistration or metadata/history operations contacted Kubernetes")
	}
}
