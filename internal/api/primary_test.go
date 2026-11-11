package api_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"devctl.local/devctl/internal/model"
	"k8s.io/client-go/tools/clientcmd"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
)

func addPrimaryFixture(t *testing.T, g *gatewayTest, id, response string) {
	t.Helper()
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, response) }))
	t.Cleanup(up.Close)
	cfg := clientapi.NewConfig()
	cfg.CurrentContext = "fixture"
	cfg.Clusters["fixture"] = &clientapi.Cluster{Server: up.URL, CertificateAuthorityData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.Certificate().Raw})}
	cfg.AuthInfos["fixture"] = &clientapi.AuthInfo{Token: "upstream-secret-only"}
	cfg.Contexts["fixture"] = &clientapi.Context{Cluster: "fixture", AuthInfo: "fixture"}
	raw, e := clientcmd.Write(*cfg)
	if e != nil {
		t.Fatal(e)
	}
	encrypted, e := g.app.Vault.Seal(id, raw)
	if e != nil {
		t.Fatal(e)
	}
	admin := model.Identity{Issuer: g.alice.Issuer, Subject: "admin", Admin: true}
	if e = g.db.Register(t.Context(), admin, model.Cluster{ID: id, Name: id, MaxParticipants: 2}, encrypted); e != nil {
		t.Fatal(e)
	}
}

func expectAPI(t *testing.T, g *gatewayTest, method, path, token, body string, want int) string {
	t.Helper()
	r := request(t, method, g.frontend.URL+path, token, body)
	got := readResponse(t, r)
	if r.StatusCode != want {
		t.Fatalf("%s %s: got%d want%d: %s", method, path, r.StatusCode, want, got)
	}
	return got
}

func TestPrimaryPolicyAndStableGateway(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "alpha") }), false)
	addPrimaryFixture(t, g, "beta", "beta")
	var profile model.DeveloperProfile
	raw := expectAPI(t, g, "GET", "/v1/profile", "alice", "", 200)
	if json.Unmarshal([]byte(raw), &profile) != nil || profile.MaxBookings != 1 || profile.ActiveBookings != 1 || profile.PrimarySession == nil || profile.PrimarySession.ID != g.session.ID {
		t.Fatal("first booking/default primary policy missing")
	}
	denied := request(t, "POST", g.frontend.URL+"/v1/sessions", "alice", `{"cluster":"beta"}`)
	// Creation requires an idempotency key independently of the booking policy.
	if denied.StatusCode != 400 {
		t.Fatal(denied.StatusCode)
	}
	denied.Body.Close()
	if _, _, e := g.db.Book(t.Context(), g.alice, model.Booking{Cluster: "beta"}, "blocked"); e == nil {
		t.Fatal("default limit not enforced")
	}
	expectAPI(t, g, "PATCH", "/v1/admin/settings", "alice", `{"default_max_bookings":2,"reason":"forged admin"}`, 403)
	expectAPI(t, g, "PATCH", "/v1/admin/settings", "admin", `{"default_max_bookings":0,"reason":"invalid"}`, 400)
	expectAPI(t, g, "PATCH", "/v1/admin/settings", "admin", `{"default_max_bookings":2,"reason":"allow two"}`, 200)
	b, _, e := g.db.Book(t.Context(), g.alice, model.Booking{Cluster: "beta"}, "second")
	if e != nil {
		t.Fatal(e)
	}
	profile, e = g.db.Profile(t.Context(), g.alice)
	if e != nil || profile.PrimarySession == nil || profile.PrimarySession.ID != g.session.ID {
		t.Fatal("second booking unexpectedly switched primary")
	}
	p := createPersonal(t, g, "alice")
	secret := personalSecret(t, p)
	cfg, e := clientcmd.Load([]byte(p.Kubeconfig))
	if e != nil || cfg.Clusters["devctl-gateway"].Server != g.app.PublicURL+"/k8s" {
		t.Fatal("PAT is not a stable developer gateway")
	}
	if got := expectAPI(t, g, "GET", "/k8s/version", secret, "", 200); got != "alpha" {
		t.Fatal(got)
	}
	expectAPI(t, g, "POST", "/v1/primary", "bob", fmt.Sprintf(`{"cluster":%q}`, b.ID), 403)
	expectAPI(t, g, "POST", "/v1/primary", "alice", `{"cluster":"beta"}`, 200)
	if got := expectAPI(t, g, "GET", "/k8s/version", secret, "", 200); got != "beta" {
		t.Fatal("same PAT did not follow primary", got)
	}
	expectAPI(t, g, "PATCH", "/v1/admin/developers/"+g.alice.Key(), "admin", `{"max_bookings":1,"reason":"reduce without eviction"}`, 200)
	profile, e = g.db.Profile(t.Context(), g.alice)
	if e != nil || profile.ActiveBookings != 2 || profile.MaxBookings != 1 {
		t.Fatal("limit reduction evicted bookings or was ignored")
	}
	expectAPI(t, g, "PATCH", "/v1/admin/developers/"+g.alice.Key(), "admin", `{"max_bookings":null,"reason":"inherit"}`, 200)
	expectAPI(t, g, "POST", "/v1/sessions/"+b.ID+"/stop", "alice", "", 200)
	if got := expectAPI(t, g, "GET", "/k8s/version", secret, "", 200); got != "alpha" {
		t.Fatal("oldest remaining booking was not promoted")
	}
	expectAPI(t, g, "POST", "/v1/sessions/"+g.session.ID+"/stop", "alice", "", 200)
	if body := expectAPI(t, g, "GET", "/k8s/version", secret, "", 403); !strings.Contains(body, "no cluster is booked") {
		t.Fatal("no-booking error is not useful to kubectl")
	}
	if _, e = g.db.VerifyPAT(t.Context(), secret); e != nil {
		t.Fatal("ending bookings revoked reusable PAT")
	}
	if _, _, e = g.db.Book(t.Context(), g.alice, model.Booking{Cluster: "beta"}, "third"); e != nil {
		t.Fatal(e)
	}
	if got := expectAPI(t, g, "GET", "/k8s/version", secret, "", 200); got != "beta" {
		t.Fatal("existing PAT did not resume after explicit booking")
	}
	expectAPI(t, g, "GET", "/v1/connection", "alice", "", 200)
	for _, path := range []string{"/k8s/sessions/" + g.session.ID + "/version", "/k8s/auto/a-11111111-2222-4333-8444-555555555555/version", "/v1/sessions/" + g.session.ID + "/connection", "/v1/auto/a-11111111-2222-4333-8444-555555555555/ensure"} {
		expectAPI(t, g, "GET", path, "alice", "", 410)
	}
}

func TestPrimaryCredentialCanBeIssuedBeforeBooking(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }), false)
	if e := g.db.Stop(context.Background(), g.alice, g.session.ID, "test", false); e != nil {
		t.Fatal(e)
	}
	p := createPersonal(t, g, "alice")
	secret := personalSecret(t, p)
	expectAPI(t, g, "GET", "/k8s/version", secret, "", 403)
	expectAPI(t, g, "POST", "/v1/pats", "alice", `{"session_id":"retired","name":"legacy"}`, 400)
}
