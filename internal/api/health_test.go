package api_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
)

func TestHealthAPIAuthenticationValidationAndReadOnlyObservations(t *testing.T) {
	var upstream atomic.Int64
	g := newGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstream.Add(1) }), false)
	const path = "/v1/admin/clusters/cluster/health-check"
	for _, endpoint := range []struct{ method, path, body string }{
		{"GET", "/v1/clusters/cluster/health", ""},
		{"GET", "/v1/admin/health", ""},
		{"PATCH", "/v1/admin/health", `{"mode":"observe","reason":"monitor fixtures"}`},
		{"POST", path, `{"reason":"check fixture"}`},
		{"PATCH", "/v1/admin/clusters/cluster/health-profile", `{"profile":"discovery-only.v1","expected_revision":1,"reason":"fixture permission policy"}`},
	} {
		for _, token := range []string{"", "invalid"} {
			expectAPI(t, g, endpoint.method, endpoint.path, token, endpoint.body, 401)
		}
		if strings.HasPrefix(endpoint.path, "/v1/admin/") {
			for _, token := range []string{"alice", "bob"} {
				expectAPI(t, g, endpoint.method, endpoint.path, token, endpoint.body, 403)
			}
		}
	}
	pat := createPersonal(t, g, "alice")
	expectAPI(t, g, "GET", "/v1/clusters/cluster/health", personalSecret(t, pat), "", 401)
	var initial model.ClusterHealth
	if err := json.Unmarshal([]byte(expectAPI(t, g, "GET", "/v1/clusters/cluster/health", "alice", "", 200)), &initial); err != nil || initial.Mode != "disabled" || initial.State != "UNKNOWN" || initial.Profile != "api-ready.v1" || initial.IdentityVerification != "NOT_CHECKED" {
		t.Fatal("initial observation did not describe disabled, unknown monitoring", err)
	}
	expectAPI(t, g, "POST", path, "admin", `{"reason":"disabled must not trigger a probe"}`, 409)
	expectAPI(t, g, "GET", "/v1/clusters/missing/health", "alice", "", 404)
	for _, body := range []string{
		``, `{}`, `null`, `{"mode":null,"reason":"null"}`, `{"mode":"invalid","reason":"unknown"}`,
		`{"mode":"observe","reason":" "}`, `{"mode":"observe","reason":null}`,
		`{"mode":"observe","reason":"valid","url":"https://outside.example.test"}`,
		`{"mode":"observe","reason":"valid"} {}`,
	} {
		expectAPI(t, g, "PATCH", "/v1/admin/health", "admin", body, 400)
	}
	for _, body := range []string{``, `{}`, `null`, `{"reason":" "}`, `{"reason":null}`, `{"reason":"check","path":"/arbitrary"}`} {
		expectAPI(t, g, "POST", path, "admin", body, 400)
	}
	for _, body := range []string{
		`{}`, `null`, `{"profile":"discovery-only.v1","reason":"missing version"}`,
		`{"profile":"discovery-only.v1","expected_revision":null,"reason":"null version"}`,
		`{"profile":"discovery-only.v1","expected_revision":0,"reason":"zero version"}`,
		`{"profile":"custom","expected_revision":1,"reason":"custom paths not permitted"}`,
		`{"profile":"api-ready.v1","expected_revision":1,"reason":" "}`,
		`{"profile":"api-ready.v1","expected_revision":1,"reason":"valid","url":"https://outside.example.test"}`,
	} {
		expectAPI(t, g, "PATCH", "/v1/admin/clusters/cluster/health-profile", "admin", body, 400)
	}
	if upstream.Load() != 0 {
		t.Fatal("health metadata API or rejected request contacted Kubernetes")
	}
}

func TestHealthAPIQueuesChecksAndPreservesReservationIdentityAndCredentials(t *testing.T) {
	var upstream atomic.Int64
	g := newGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstream.Add(1) }), false)
	pat := createPersonal(t, g, "alice")
	type bookingState struct {
		Expiry    time.Time
		Activity  *time.Time
		Primary   string
		Version   int64
		LastUsed  *time.Time
		Encrypted []byte
	}
	read := func() bookingState {
		t.Helper()
		var v bookingState
		if err := g.db.Pool.QueryRow(t.Context(), `SELECT s.expires_at,s.last_activity_at,d.primary_session_id,d.selection_version,p.last_used_at,c.kubeconfig_ciphertext
 FROM sessions s JOIN developers d ON d.owner_id=s.owner_id JOIN clusters c ON c.id=s.cluster_id
 JOIN personal_access_tokens p ON p.owner_id=s.owner_id WHERE s.id=$1 AND p.id=$2`, g.session.ID, pat.PAT.ID).Scan(&v.Expiry, &v.Activity, &v.Primary, &v.Version, &v.LastUsed, &v.Encrypted); err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := read()
	expectAPI(t, g, "PATCH", "/v1/admin/health", "admin", `{"mode":"observe","reason":"enable fixed checks for owned fixture"}`, 200)
	var mode struct {
		Mode string `json:"mode"`
	}
	if json.Unmarshal([]byte(expectAPI(t, g, "GET", "/v1/admin/health", "admin", "", 200)), &mode) != nil || mode.Mode != "observe" {
		t.Fatal("monitoring policy was not persisted")
	}
	path := "/v1/admin/clusters/cluster/health-check"
	var first, second struct {
		ID      string              `json:"id"`
		Pending bool                `json:"pending"`
		Health  model.ClusterHealth `json:"health"`
	}
	if json.Unmarshal([]byte(expectAPI(t, g, "POST", path, "admin", `{"reason":"first requested refresh"}`, 202)), &first) != nil || first.ID == "" || !first.Pending {
		t.Fatal("refresh was not accepted as a pending observation")
	}
	if json.Unmarshal([]byte(expectAPI(t, g, "POST", path, "admin", `{"reason":"coalesce repeated refresh"}`, 202)), &second) != nil || second.ID != first.ID {
		t.Fatal("repeated refresh did not coalesce")
	}
	expectAPI(t, g, "PATCH", "/v1/admin/clusters/cluster/health-profile", "admin", `{"profile":"discovery-only.v1","expected_revision":1,"reason":"explicit lower-assurance profile for fixture"}`, 200)
	expectAPI(t, g, "PATCH", "/v1/admin/clusters/cluster/health-profile", "admin", `{"profile":"api-ready.v1","expected_revision":1,"reason":"stale editor must not replace the policy"}`, 409)
	var health model.ClusterHealth
	if json.Unmarshal([]byte(expectAPI(t, g, "GET", "/v1/clusters/cluster/health", "alice", "", 200)), &health) != nil || health.Profile != "discovery-only.v1" || health.PolicyRevision != 2 || health.State != "UNKNOWN" || health.ReadinessConfirmed {
		t.Fatal("profile change was not versioned and invalidated")
	}
	expectAPI(t, g, "GET", "/readyz", "", "", 200)
	if after := read(); !reflect.DeepEqual(before, after) {
		t.Fatal("health administration changed a booking, primary, token or cluster credentials")
	}
	if upstream.Load() != 0 {
		t.Fatal("health queueing performed synchronous Kubernetes calls")
	}
	var changes int
	if err := g.db.Pool.QueryRow(t.Context(), "SELECT count(*) FROM audit WHERE action LIKE 'cluster_health_%' AND actor<>'system'").Scan(&changes); err != nil || changes < 3 {
		t.Fatal("health administration lacked audit records", err)
	}
}

func TestHealthAPIDatabaseFailuresAreGeneric(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), false)
	g.db.Pool.Close()
	for _, endpoint := range []struct{ method, path, body string }{
		{"GET", "/v1/clusters/cluster/health", ""},
		{"PATCH", "/v1/admin/health", `{"mode":"observe","reason":"valid"}`},
		{"POST", "/v1/admin/clusters/cluster/health-check", `{"reason":"valid"}`},
	} {
		body := expectAPI(t, g, endpoint.method, endpoint.path, "admin", endpoint.body, 503)
		for _, secret := range []string{"postgres://", "devctl-dev-only", "upstream-secret-only", "PRIVATE KEY", "SQLSTATE"} {
			if strings.Contains(string(body), secret) {
				t.Fatal("health API exposed internal configuration")
			}
		}
	}
}
