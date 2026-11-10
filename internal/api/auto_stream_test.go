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

type automaticStreamAuth struct {
	initial, renewed, bob model.Identity
}

func (a *automaticStreamAuth) Verify(_ context.Context, raw string) (model.Identity, error) {
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

const streamBinding = "a-11111111-2222-4333-8444-555555555555"

func automaticStreamGateway(t *testing.T, lifetime time.Duration) (*gatewayTest, *automaticStreamAuth) {
	t.Helper()
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stream" {
			fmt.Fprintln(w, "ok")
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "stream ready")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}), false)
	now := time.Now()
	a := &automaticStreamAuth{initial: g.alice, renewed: g.alice, bob: model.Identity{Issuer: g.alice.Issuer, Subject: "bob", Name: "bob"}}
	a.initial.TokenExpiresAt = now.Add(lifetime)
	a.renewed.TokenExpiresAt = now.Add(8 * time.Second)
	a.bob.TokenExpiresAt = a.renewed.TokenExpiresAt
	g.app.Auth = a
	response := request(t, "POST", g.frontend.URL+"/v1/auto/"+streamBinding+"/ensure", "initial", `{"cluster":"cluster"}`)
	if response.StatusCode != http.StatusOK {
		readResponse(t, response)
		t.Fatal("initial authenticated automatic binding failed", response.StatusCode)
	}
	var access store.AutomaticAccess
	if err := json.NewDecoder(response.Body).Decode(&access); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if access.Session.ID != g.session.ID || access.Session.LastActivityAt != nil || access.AuthorizationExpiresAt.After(a.initial.TokenExpiresAt) {
		t.Fatal("binding did not reuse the exact own reservation with a token-bounded lease and no fabricated activity")
	}
	return g, a
}

func openAutomaticStream(t *testing.T, address, token string) <-chan struct{} {
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

func waitForAutomaticStreamClose(t *testing.T, closed <-chan struct{}) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not terminate the unauthorized automatic stream")
	}
}

func TestAutomaticStreamAcceptsFreshReauthorizationWithoutAcceptingExpiredRequests(t *testing.T) {
	g, auth := automaticStreamGateway(t, 1200*time.Millisecond)
	autoURL := g.frontend.URL + "/k8s/auto/" + streamBinding
	automatic := openAutomaticStream(t, autoURL+"/stream", "initial")
	// Existing UUID routes deliberately keep their original token-expiry rule.
	manual := openAutomaticStream(t, g.url("/stream"), "initial")
	before, err := g.db.Automatic(context.Background(), auth.initial, streamBinding)
	if err != nil || before.Session.LastActivityAt == nil {
		t.Fatal("actual Kubernetes stream did not record activity", err)
	}
	wrong := request(t, http.MethodPost, g.frontend.URL+"/v1/auto/"+streamBinding+"/heartbeat", "other-owner", "{}")
	readResponse(t, wrong)
	if wrong.StatusCode != http.StatusNotFound && wrong.StatusCode != http.StatusForbidden {
		t.Fatal("another owner renewed an automatic authorization lease", wrong.StatusCode)
	}
	response := request(t, http.MethodPost, g.frontend.URL+"/v1/auto/"+streamBinding+"/heartbeat", "renewed", "{}")
	if response.StatusCode != http.StatusOK {
		readResponse(t, response)
		t.Fatal("fresh authenticated renewal failed", response.StatusCode)
	}
	var renewed store.AutomaticAccess
	if err := json.NewDecoder(response.Body).Decode(&renewed); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if !renewed.AuthorizationExpiresAt.After(before.AuthorizationExpiresAt) || renewed.AuthorizationExpiresAt.After(auth.renewed.TokenExpiresAt) || renewed.Session.ID != before.Session.ID {
		t.Fatal("renewal did not retain the booking or exceeded the verified token expiry")
	}
	// GET activity and token renewal must not manufacture new Kubernetes activity.
	if renewed.Session.LastActivityAt == nil || !renewed.Session.LastActivityAt.Equal(*before.Session.LastActivityAt) {
		t.Fatal("the heartbeat itself extended Kubernetes activity")
	}
	if delay := time.Until(auth.initial.TokenExpiresAt.Add(100 * time.Millisecond)); delay > 0 {
		time.Sleep(delay)
	}
	waitForAutomaticStreamClose(t, manual)
	select {
	case <-automatic:
		t.Fatal("a freshly reauthorized automatic stream ended with its original access token")
	default:
	}
	old := request(t, http.MethodGet, autoURL+"/version", "initial", "")
	readResponse(t, old)
	if old.StatusCode != http.StatusUnauthorized {
		t.Fatal("the expired bearer was accepted for a new request", old.StatusCode)
	}
	fresh := request(t, http.MethodGet, autoURL+"/version", "renewed", "")
	readResponse(t, fresh)
	if fresh.StatusCode != http.StatusOK {
		t.Fatal("fresh token did not retain access to the same booking", fresh.StatusCode)
	}
	if err := g.db.Stop(context.Background(), g.alice, g.session.ID, "stop renewed automatic stream", false); err != nil {
		t.Fatal(err)
	}
	waitForAutomaticStreamClose(t, automatic)
	response = request(t, http.MethodPost, g.frontend.URL+"/v1/auto/"+streamBinding+"/ensure", "renewed", `{"cluster":"cluster"}`)
	readResponse(t, response)
	if response.StatusCode != http.StatusConflict {
		t.Fatal("a stopped automatic binding silently allocated a replacement", response.StatusCode)
	}
}

func TestAutomaticStreamClosesWhenAuthorizationLeaseExpires(t *testing.T) {
	g, _ := automaticStreamGateway(t, 900*time.Millisecond)
	closed := openAutomaticStream(t, g.frontend.URL+"/k8s/auto/"+streamBinding+"/stream", "initial")
	waitForAutomaticStreamClose(t, closed)
}

func TestAutomaticStreamClosesWhenReservationDatabaseIsUnavailable(t *testing.T) {
	g, _ := automaticStreamGateway(t, 5*time.Second)
	closed := openAutomaticStream(t, g.frontend.URL+"/k8s/auto/"+streamBinding+"/stream", "initial")
	g.db.Pool.Close()
	waitForAutomaticStreamClose(t, closed)
}

func TestAutomaticHeartbeatCannotChooseItsExpiryOrRenewIdleActivity(t *testing.T) {
	g, auth := automaticStreamGateway(t, 5*time.Second)
	before, err := g.db.Automatic(context.Background(), auth.initial, streamBinding)
	if err != nil {
		t.Fatal(err)
	}
	response := request(t, http.MethodPost, g.frontend.URL+"/v1/auto/"+streamBinding+"/heartbeat", "renewed", `{"authorization_expires_at":"2099-01-01T00:00:00Z"}`)
	readResponse(t, response)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatal("client-controlled authorization expiry was accepted", response.StatusCode)
	}
	if _, err := g.db.Pool.Exec(context.Background(), "UPDATE sessions SET last_activity_at=clock_timestamp()-interval '3 minutes' WHERE id=$1", g.session.ID); err != nil {
		t.Fatal(err)
	}
	response = request(t, http.MethodPost, g.frontend.URL+"/v1/auto/"+streamBinding+"/heartbeat", "renewed", "{}")
	readResponse(t, response)
	if response.StatusCode != http.StatusConflict {
		t.Fatal("an idle heartbeat could prolong its own activity window", response.StatusCode)
	}
	access, err := g.db.Automatic(context.Background(), auth.renewed, streamBinding)
	if err != nil || !access.AuthorizationExpiresAt.Equal(before.AuthorizationExpiresAt) {
		t.Fatal("rejected renewal altered authorization", err)
	}
	// Prefix traversal must remain blocked for the new stable gateway route.
	response = request(t, http.MethodGet, g.frontend.URL+"/k8s/auto/"+streamBinding+"/%2e%2e/version", "renewed", "")
	defer response.Body.Close()
	if response.StatusCode < 400 || response.StatusCode >= 500 {
		t.Fatal("automatic route accepted path traversal", response.StatusCode)
	}
	if strings.Contains(readResponse(t, response), "upstream-secret") {
		t.Fatal("automatic denial exposed upstream credentials")
	}
}
