package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"devctl.local/devctl/internal/api"
	"devctl.local/devctl/internal/model"
)

func createAutomaticPersonal(t *testing.T, g *gatewayTest, region string) api.PATCreation {
	t.Helper()
	var out api.PATCreation
	raw := expectAPI(t, g, "POST", "/v1/pats", "alice", fmt.Sprintf(`{"name":"fallback","ttl":"1h","auto_booking":{"enabled":true,"selector":{"region":%q}}}`, region), 201)
	if json.Unmarshal([]byte(raw), &out) != nil || !out.PAT.AutoBooking.Enabled {
		t.Fatal("automatic PAT preferences missing")
	}
	return out
}

func TestPATAutomaticPolicyAPIValidationAndAuthorization(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "alpha") }), false)
	p := createPersonal(t, g, "alice")
	secret := personalSecret(t, p)
	path := "/v1/pats/" + p.PAT.ID
	beforeHash := []byte{}
	if err := g.db.Pool.QueryRow(t.Context(), "SELECT token_digest FROM personal_access_tokens WHERE id=$1", p.PAT.ID).Scan(&beforeHash); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{}`, `{"auto_booking":null}`, `{"auto_booking":{}}`,
		`{"auto_booking":{"selector":{"region":"eu"}}}`,
		`{"auto_booking":{"enabled":"yes"}}`,
		`{"auto_booking":{"enabled":true,"selector":{"bad/key/again":"eu"}}}`,
		`{"auto_booking":{"enabled":true,"selector":{"region":"invalid value"}}}`,
		`{"auto_booking":{"enabled":true,"selector":[]}}`,
		`{"auto_booking":{"enabled":true,"unknown":true}}`,
		`{"auto_booking":{"enabled":true},"ttl":"168h"}`,
		`{"auto_booking":{"enabled":true},"token":"replacement"}`,
	} {
		expectAPI(t, g, "PATCH", path, "alice", body, 400)
	}
	for _, body := range []string{
		`{"name":"bad","auto_booking":{}}`,
		`{"name":"bad","auto_booking":{"enabled":true,"selector":{"region":"invalid value"}}}`,
		`{"name":"bad","auto_booking":{"enabled":true,"selector":{"":"test"}}}`,
	} {
		expectAPI(t, g, "POST", "/v1/pats", "alice", body, 400)
	}
	policy := `{"auto_booking":{"enabled":true,"selector":{"region":"eu"}}}`
	expectAPI(t, g, "GET", path, "bob", "", 403)
	expectAPI(t, g, "PATCH", path, "bob", policy, 403)
	expectAPI(t, g, "GET", path, secret, "", 401)
	expectAPI(t, g, "PATCH", path, secret, policy, 401)
	expectAPI(t, g, "PATCH", path, "admin", policy, 409)
	changed := expectAPI(t, g, "PATCH", path, "admin", `{"auto_booking":{"enabled":true,"selector":{"region":"eu"}},"reason":"approved configuration"}`, 200)
	var after struct {
		ID          string                  `json:"id"`
		CreatedAt   time.Time               `json:"created_at"`
		ExpiresAt   time.Time               `json:"expires_at"`
		AutoBooking model.AutoBookingPolicy `json:"auto_booking"`
	}
	if json.Unmarshal([]byte(changed), &after) != nil || after.ID != p.PAT.ID || !after.ExpiresAt.Equal(p.PAT.ExpiresAt) || !after.CreatedAt.Equal(p.PAT.CreatedAt) || !after.AutoBooking.Enabled || strings.Contains(changed, secret) || strings.Contains(changed, "token_digest") || strings.Contains(changed, "kubeconfig") {
		t.Fatal("preference editing changed credentials or returned secret material")
	}
	expectAPI(t, g, "GET", path, "alice", "", 200)
	expectAPI(t, g, "GET", "/v1/pats/missing", "alice", "", 404)
	var afterHash []byte
	if err := g.db.Pool.QueryRow(t.Context(), "SELECT token_digest FROM personal_access_tokens WHERE id=$1", p.PAT.ID).Scan(&afterHash); err != nil || !bytes.Equal(afterHash, beforeHash) {
		t.Fatal("metadata edit rotated the token", err)
	}
	_, sessions, err := g.db.Snapshot(t.Context())
	if err != nil || len(sessions) != 1 || sessions[0].ID != g.session.ID {
		t.Fatal("metadata reads/edits allocated a cluster", err)
	}
	expectAPI(t, g, "DELETE", path, "alice", `{}`, 200)
	expectAPI(t, g, "PATCH", path, "alice", policy, 409)
}

func TestPATGatewayAutomaticBookingConcurrencyAndEditableFallback(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "alpha") }), false)
	addPrimaryFixture(t, g, "beta", "beta")
	if _, err := g.db.Pool.Exec(t.Context(), `UPDATE clusters SET labels=CASE WHEN id='cluster' THEN '{"region":"eu"}'::jsonb ELSE '{"region":"us"}'::jsonb END`); err != nil {
		t.Fatal(err)
	}
	if err := g.db.Stop(t.Context(), g.alice, g.session.ID, "automatic test", false); err != nil {
		t.Fatal(err)
	}
	p := createAutomaticPersonal(t, g, "eu")
	secret := personalSecret(t, p)
	_, sessions, err := g.db.Snapshot(t.Context())
	if err != nil || len(sessions) != 1 || sessions[0].State != "RELEASED" {
		t.Fatal("issuing an opted-in PAT allocated before Kubernetes use")
	}
	var wg sync.WaitGroup
	failures := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest("GET", g.url("/version"), nil)
			if err != nil {
				failures <- err
				return
			}
			req.Header.Set("Authorization", "Bearer "+secret)
			response, err := g.frontend.Client().Do(req)
			if err != nil {
				failures <- err
				return
			}
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr != nil || response.StatusCode != 200 || string(body) != "alpha" {
				failures <- fmt.Errorf("concurrent gateway request failed with status %d", response.StatusCode)
				return
			}
			failures <- nil
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	profile, err := g.db.Profile(t.Context(), g.alice)
	if err != nil || profile.ActiveBookings != 1 || profile.PrimarySession == nil || profile.PrimarySession.Cluster != "cluster" {
		t.Fatal("concurrent requests did not create one owned primary", err)
	}
	_, sessions, err = g.db.Snapshot(t.Context())
	if err != nil || len(sessions) != 2 {
		t.Fatal("automatic gateway requests duplicated reservations")
	}
	path := "/v1/pats/" + p.PAT.ID
	expectAPI(t, g, "PATCH", path, "alice", `{"auto_booking":{"enabled":true,"selector":{"region":"us"}}}`, 200)
	if got := expectAPI(t, g, "GET", "/k8s/version", secret, "", 200); got != "alpha" {
		t.Fatal("preference edit switched the current primary")
	}
	expectAPI(t, g, "POST", "/v1/sessions/"+profile.PrimarySession.ID+"/stop", "alice", "", 200)
	if got := expectAPI(t, g, "GET", "/k8s/version", secret, "", 200); got != "beta" {
		t.Fatal("same PAT did not apply new selector to next booking")
	}
	profile, err = g.db.Profile(t.Context(), g.alice)
	if err != nil {
		t.Fatal(err)
	}
	expectAPI(t, g, "PATCH", path, "alice", `{"auto_booking":{"enabled":true,"selector":{"region":"nowhere"}}}`, 200)
	expectAPI(t, g, "POST", "/v1/sessions/"+profile.PrimarySession.ID+"/stop", "alice", "", 200)
	// User request parameters cannot override the server-side PAT preference.
	if body := expectAPI(t, g, "GET", "/k8s/version?selector=region%3Deu&auto_booking=true", secret, "", 403); !strings.Contains(body, "no matching available cluster for automatic booking") {
		t.Fatal("automatic placement error was not useful or request selector overrode metadata")
	}
	expectAPI(t, g, "PATCH", path, "alice", `{"auto_booking":{"enabled":false,"selector":{}}}`, 200)
	if body := expectAPI(t, g, "GET", "/k8s/version", secret, "", 403); !strings.Contains(body, "no cluster is booked") {
		t.Fatal("disabled fallback did not preserve explicit-booking behavior")
	}
}
