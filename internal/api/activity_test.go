package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
)

func activitySession(t *testing.T, g *gatewayTest, id string) model.Session {
	t.Helper()
	var detail struct {
		Session model.Session `json:"session"`
	}
	raw := expectAPI(t, g, "GET", "/v1/sessions/"+id, "alice", "", 200)
	if err := json.Unmarshal([]byte(raw), &detail); err != nil {
		t.Fatal(err)
	}
	return detail.Session
}

func ageActivity(t *testing.T, g *gatewayTest, id string) {
	t.Helper()
	// Keep a valid reservation, but simulate time since the last actual use.
	_, err := g.db.Pool.Exec(t.Context(), `UPDATE sessions SET
 last_activity_at=clock_timestamp()-interval '90 seconds',
 expires_at=clock_timestamp()+interval '2 minutes' WHERE id=$1`, id)
	if err != nil {
		t.Fatal(err)
	}
}

func TestInactivityPolicyAPIAndRetiredBookingDuration(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), false)
	var settings model.Settings
	readSettings := func() {
		t.Helper()
		raw := expectAPI(t, g, "GET", "/v1/admin/settings", "admin", "", 200)
		if json.Unmarshal([]byte(raw), &settings) != nil {
			t.Fatal("invalid reservation policy")
		}
	}
	readSettings()
	if settings.DefaultMaxBookings != 1 || settings.InactivityGracePeriod != "4h0m0s" {
		t.Fatal("missing conservative defaults", settings)
	}
	for _, body := range []string{
		`{"inactivity_grace_period":"0s","reason":"test"}`,
		`{"inactivity_grace_period":"169h","reason":"test"}`,
		`{"inactivity_grace_period":"60.1s","reason":"test"}`,
		`{"inactivity_grace_period":"2h"}`,
		`{"reason":"empty patch"}`,
		`{"inactivity_grace_period":null,"reason":"null patch"}`,
		`{"inactivity_grace_period":"2h","client_time":"2099-01-01","reason":"forged"}`,
	} {
		expectAPI(t, g, "PATCH", "/v1/admin/settings", "admin", body, 400)
	}
	expectAPI(t, g, "PATCH", "/v1/admin/settings", "alice", `{"inactivity_grace_period":"2h","reason":"forged admin"}`, 403)
	expectAPI(t, g, "PATCH", "/v1/admin/settings", "admin", `{"inactivity_grace_period":"2h","reason":"set grace only"}`, 200)
	readSettings()
	if settings.DefaultMaxBookings != 1 || settings.InactivityGracePeriod != "2h0m0s" {
		t.Fatal("grace patch overwrote booking limit")
	}
	expectAPI(t, g, "PATCH", "/v1/admin/settings", "admin", `{"default_max_bookings":2,"reason":"set limit only"}`, 200)
	readSettings()
	if settings.DefaultMaxBookings != 2 || settings.InactivityGracePeriod != "2h0m0s" {
		t.Fatal("limit patch overwrote grace")
	}
	expectAPI(t, g, "POST", "/v1/sessions", "alice", `{"ttl":"1h"}`, 400)
	expectAPI(t, g, "POST", "/v1/sessions/"+g.session.ID+"/renew", "alice", `{"ttl":"1h"}`, 410)
	// PAT lifetime remains a separate supported control.
	expectAPI(t, g, "POST", "/v1/pats", "alice", `{"name":"independent lifetime","ttl":"30m"}`, 201)
}

func TestPresenceExtendsOnlyExactOwnedPrimary(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), false)
	addPrimaryFixture(t, g, "beta", "beta")
	expectAPI(t, g, "PATCH", "/v1/admin/settings", "admin", `{"default_max_bookings":2,"reason":"two clusters"}`, 200)
	b, _, err := g.db.Book(t.Context(), g.alice, model.Booking{Cluster: "beta"}, "beta")
	if err != nil {
		t.Fatal(err)
	}
	ageActivity(t, g, g.session.ID)
	ageActivity(t, g, b.ID)
	beforeA, beforeB := activitySession(t, g, g.session.ID), activitySession(t, g, b.ID)
	profile, err := g.db.Profile(t.Context(), g.alice)
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"session_id":%q,"selection_version":%d}`, g.session.ID, profile.SelectionVersion)
	expectAPI(t, g, "POST", "/v1/activity", "bob", body, 409)
	expectAPI(t, g, "POST", "/v1/activity", "alice", `{"session_id":"missing","selection_version":1}`, 409)
	expectAPI(t, g, "POST", "/v1/activity", "alice", `{"session_id":"missing","selection_version":1,"timestamp":"2099-01-01"}`, 400)
	expectAPI(t, g, "POST", "/v1/activity", "alice", body, 200)
	afterA, afterB := activitySession(t, g, g.session.ID), activitySession(t, g, b.ID)
	if !afterA.ExpiresAt.After(*beforeA.ExpiresAt) || time.Until(*afterA.ExpiresAt) < 3*time.Hour || !afterB.ExpiresAt.Equal(*beforeB.ExpiresAt) || !afterB.LastActivityAt.Equal(*beforeB.LastActivityAt) {
		t.Fatal("presence did not extend only the used booking")
	}
	// Polling, token identity checks, and OAuth authorization renewal are passive.
	for _, path := range []string{"/v1/profile", "/v1/sessions", "/v1/clusters", "/v1/access", "/v1/whoami", "/v1/connection"} {
		expectAPI(t, g, "GET", path, "alice", "", 200)
	}
	expectAPI(t, g, "POST", "/v1/access/heartbeat", "alice", `{}`, 200)
	passive := activitySession(t, g, g.session.ID)
	if !passive.ExpiresAt.Equal(*afterA.ExpiresAt) || !passive.LastActivityAt.Equal(*afterA.LastActivityAt) {
		t.Fatal("passive polling/refresh kept a reservation alive")
	}
	expectAPI(t, g, "POST", "/v1/primary", "alice", `{"cluster":"beta"}`, 200)
	expectAPI(t, g, "POST", "/v1/activity", "alice", body, 409)
	selected := activitySession(t, g, b.ID)
	if !selected.ExpiresAt.After(*afterB.ExpiresAt) {
		t.Fatal("explicit cluster selection did not record activity")
	}
	// Switching back does not make a heartbeat from the old tab valid again.
	expectAPI(t, g, "POST", "/v1/primary", "alice", `{"cluster":"cluster"}`, 200)
	expectAPI(t, g, "POST", "/v1/activity", "alice", body, 409)
}

func TestActiveGatewayStreamExtendsReservationBeyondOldDeadline(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "stream ready")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}), false)
	// The request arrives just before idle release; extending the booking must
	// also permit the stream to outlive the previous fixed deadline.
	_, err := g.db.Pool.Exec(t.Context(), `UPDATE sessions SET last_activity_at=NULL,
 expires_at=clock_timestamp()+interval '500 milliseconds' WHERE id=$1`, g.session.ID)
	if err != nil {
		t.Fatal(err)
	}
	active := openPrimaryStream(t, g.url("/stream"), "alice")
	after := activitySession(t, g, g.session.ID)
	if after.LastActivityAt == nil || time.Until(*after.ExpiresAt) < 3*time.Hour {
		t.Fatal("actual gateway traffic did not extend reservation")
	}
	time.Sleep(600 * time.Millisecond)
	select {
	case <-active:
		t.Fatal("active stream incorrectly retained old idle deadline")
	default:
	}
	if err = g.db.Stop(t.Context(), g.alice, g.session.ID, "test release", false); err != nil {
		t.Fatal(err)
	}
	waitForPrimaryStreamClose(t, active)
}
