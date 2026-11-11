package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
)

func TestStatusShowsInactivityDeadlineWithoutRecordingActivity(t *testing.T) {
	activity := time.Date(2026, time.November, 11, 10, 0, 0, 0, time.UTC)
	release := activity.Add(4 * time.Hour)
	identity := testAccessIdentity()
	session := model.Session{ID: sessionA, Owner: identity.Key(), Cluster: "cluster-a", DisplayName: "Developer", State: "ACTIVE", Primary: true, LastActivityAt: &activity, ExpiresAt: &release}
	for _, test := range []struct {
		name   string
		args   []string
		plugin bool
		json   bool
	}{
		{name: "list", args: []string{"sessions", "--all"}},
		{name: "session", args: []string{"status", sessionA}},
		{name: "profile", args: []string{"status"}},
		{name: "plugin", args: []string{"status"}, plugin: true},
		{name: "session JSON", args: []string{"status", sessionA, "--json"}, json: true},
		{name: "plugin JSON", args: []string{"status", "--json"}, plugin: true, json: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			c, out := testAccessClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != "GET" {
					t.Error("status recorded activity")
				}
				switch r.URL.Path {
				case "/v1/sessions":
					_ = json.NewEncoder(w).Encode([]model.Session{session})
				case "/v1/sessions/" + sessionA:
					_ = json.NewEncoder(w).Encode(map[string]any{"session": session, "cluster": model.Cluster{ID: "cluster-a"}})
				case "/v1/profile":
					_ = json.NewEncoder(w).Encode(developerProfile{User: identity, OwnerID: identity.Key(), MaxBookings: 2, ActiveBookings: 1, PrimarySession: &session, SelectionVersion: 1})
				default:
					t.Error("unexpected status operation", r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
				}
			})
			saveAccessTestToken(t, c)
			root := newCommand(c)
			if test.plugin {
				root = newPluginCommand(c)
			}
			root.PersistentPreRunE = nil
			root.SetArgs(test.args)
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 1 || !strings.Contains(out.String(), release.Format(time.RFC3339)) {
				t.Fatal("status omitted inactivity deadline or performed extra operations", out.String())
			}
			if test.json {
				if !json.Valid(out.Bytes()) || !strings.Contains(out.String(), `"expires_at"`) {
					t.Fatal("JSON status compatibility lost", out.String())
				}
			} else if !strings.Contains(out.String(), "AUTO-RELEASE (INACTIVE)") || !strings.Contains(out.String(), activity.Format(time.RFC3339)) || strings.Contains(out.String(), "until stop/logout") {
				t.Fatal("human status did not explain inactivity release", out.String())
			}
		})
	}
}
