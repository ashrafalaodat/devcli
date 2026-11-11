package api_test

import (
	"bufio"
	"context"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type primaryStreamAuth struct {
	initial, renewed, bob model.Identity
}

func (a *primaryStreamAuth) Verify(_ context.Context, raw string) (model.Identity, error) {
	var identity model.Identity
	switch raw {
	case "initial":
		identity = a.initial
	case "renewed":
		identity = a.renewed
	case "other-owner":
		identity = a.bob
	default:
		return identity, errors.New("invalid token")
	}
	if !identity.TokenExpiresAt.After(time.Now()) {
		return model.Identity{}, errors.New("expired token")
	}
	return identity, nil
}

func primaryStreamGateway(t *testing.T, lifetime time.Duration) (*gatewayTest, *primaryStreamAuth) {
	t.Helper()
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stream" {
			fmt.Fprintln(w, "ok")
			return
		}
		fmt.Fprintln(w, "stream ready")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}), false)
	now := time.Now()
	a := &primaryStreamAuth{initial: g.alice, renewed: g.alice, bob: model.Identity{Issuer: g.alice.Issuer, Subject: "bob", Name: "bob"}}
	a.initial.TokenExpiresAt = now.Add(lifetime)
	a.renewed.TokenExpiresAt = now.Add(8 * time.Second)
	a.bob.TokenExpiresAt = a.renewed.TokenExpiresAt
	g.app.Auth = a
	access, e := g.db.AuthorizePrimary(t.Context(), a.initial)
	if e != nil || access.Session.ID != g.session.ID || access.Session.LastActivityAt != nil || access.AuthorizationExpiresAt.After(a.initial.TokenExpiresAt) {
		t.Fatal("invalid initial primary authorization", e)
	}
	return g, a
}
func openPrimaryStream(t *testing.T, address, token string) <-chan struct{} {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, address, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatal("stream was rejected", response.StatusCode)
	}
	reader := bufio.NewReader(response.Body)
	line, err := reader.ReadString('\n')
	if err != nil || line != "stream ready\n" {
		t.Fatal("upstream stream did not become ready")
	}
	closed := make(chan struct{})
	go func() {
		io.Copy(io.Discard, reader)
		response.Body.Close()
		close(closed)
	}()
	return closed
}

func waitForPrimaryStreamClose(t *testing.T, closed <-chan struct{}) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not terminate the unauthorized automatic stream")
	}
}

func TestPrimaryStreamFreshJWTLeaseAndExpiredRequests(t *testing.T) {
	g, a := primaryStreamGateway(t, 1200*time.Millisecond)
	active := openPrimaryStream(t, g.url("/stream"), "initial")
	before, e := g.db.PrimaryAccess(t.Context(), a.initial)
	if e != nil || before.Session.LastActivityAt == nil {
		t.Fatal("stream activity missing", e)
	}
	expectAPI(t, g, "POST", "/v1/access/heartbeat", "other-owner", "{}", 409)
	raw := expectAPI(t, g, "POST", "/v1/access/heartbeat", "renewed", "{}", 200)
	var after store.PrimaryAccess
	if json.Unmarshal([]byte(raw), &after) != nil || !after.AuthorizationExpiresAt.After(before.AuthorizationExpiresAt) || after.AuthorizationExpiresAt.After(a.renewed.TokenExpiresAt) || after.Session.ID != before.Session.ID {
		t.Fatal("invalid fresh JWT authorization")
	}
	if after.Session.LastActivityAt == nil || !after.Session.LastActivityAt.Equal(*before.Session.LastActivityAt) {
		t.Fatal("heartbeat counted as Kubernetes activity")
	}
	if delay := time.Until(a.initial.TokenExpiresAt.Add(100 * time.Millisecond)); delay > 0 {
		time.Sleep(delay)
	}
	select {
	case <-active:
		t.Fatal("fresh lease failed to keep primary stream alive")
	default:
	}
	expectAPI(t, g, "GET", "/k8s/version", "initial", "", 401)
	expectAPI(t, g, "GET", "/k8s/version", "renewed", "", 200)
	if e = g.db.Stop(t.Context(), g.alice, g.session.ID, "stop", false); e != nil {
		t.Fatal(e)
	}
	waitForPrimaryStreamClose(t, active)
	expectAPI(t, g, "POST", "/v1/access/heartbeat", "renewed", "{}", 409)
}
func TestPrimaryStreamLeaseAndDatabaseFailures(t *testing.T) {
	for _, kind := range []string{"expiry", "database"} {
		t.Run(kind, func(t *testing.T) {
			g, _ := primaryStreamGateway(t, 900*time.Millisecond)
			closed := openPrimaryStream(t, g.url("/stream"), "initial")
			if kind == "database" {
				g.db.Pool.Close()
			}
			waitForPrimaryStreamClose(t, closed)
		})
	}
}
func TestPrimaryHeartbeatRejectsClientExpiryAndIdleActivity(t *testing.T) {
	g, a := primaryStreamGateway(t, 5*time.Second)
	before, e := g.db.PrimaryAccess(t.Context(), a.initial)
	if e != nil {
		t.Fatal(e)
	}
	expectAPI(t, g, "POST", "/v1/access/heartbeat", "renewed", `{"authorization_expires_at":"2099-01-01T00:00:00Z"}`, 400)
	if _, e = g.db.Pool.Exec(t.Context(), "UPDATE sessions SET last_activity_at=clock_timestamp()-interval '3 minutes' WHERE id=$1", g.session.ID); e != nil {
		t.Fatal(e)
	}
	expectAPI(t, g, "POST", "/v1/access/heartbeat", "renewed", "{}", 409)
	after, e := g.db.PrimaryAccess(t.Context(), a.renewed)
	if e != nil || !before.AuthorizationExpiresAt.Equal(after.AuthorizationExpiresAt) {
		t.Fatal("rejected heartbeat changed lease")
	}
	body := expectAPI(t, g, "GET", "/k8s/%2e%2e/version", "renewed", "", 400)
	if strings.Contains(body, "upstream-secret") {
		t.Fatal("secret leaked")
	}
}
func TestPrimarySwitchClosesEstablishedStreamsEvenAfterSwitchBack(t *testing.T) {
	g, _ := primaryStreamGateway(t, 5*time.Second)
	addPrimaryFixture(t, g, "beta", "beta")
	two := 2
	admin := model.Identity{Issuer: g.alice.Issuer, Subject: "admin", Admin: true}
	if e := g.db.UpdateDeveloperLimit(t.Context(), admin, g.alice.Key(), &two, "test two"); e != nil {
		t.Fatal(e)
	}
	if _, _, e := g.db.Book(t.Context(), g.alice, model.Booking{Cluster: "beta"}, "second"); e != nil {
		t.Fatal(e)
	}
	stream := openPrimaryStream(t, g.url("/stream"), "initial")
	if _, e := g.db.SelectPrimary(t.Context(), g.alice, "beta"); e != nil {
		t.Fatal(e)
	}
	if _, e := g.db.SelectPrimary(t.Context(), g.alice, "cluster"); e != nil {
		t.Fatal(e)
	}
	waitForPrimaryStreamClose(t, stream)
}
