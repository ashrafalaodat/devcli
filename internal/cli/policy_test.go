package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdminBookingLimitCommandsSendAuditedPolicyChanges(t *testing.T) {
	for _, test := range []struct {
		args []string
		path string
		key  string
		want any
	}{
		{[]string{"admin", "settings", "--max-bookings", "3", "--reason", "team allowance"}, "/v1/admin/settings", "default_max_bookings", float64(3)},
		{[]string{"admin", "limit", "developer-id", "--max-bookings", "2", "--reason", "integration work"}, "/v1/admin/developers/developer-id", "max_bookings", float64(2)},
		{[]string{"admin", "limit", "developer-id", "--reset", "--reason", "restore default"}, "/v1/admin/developers/developer-id", "max_bookings", nil},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			c, _ := testAccessClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "PATCH" || r.URL.Path != test.path {
					t.Error("wrong policy operation")
					w.WriteHeader(400)
					return
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				value, present := body[test.key]
				if !present || value != test.want || body["reason"] == "" {
					t.Error("missing audited policy payload", body)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"status":"updated"}`))
			})
			saveAccessTestToken(t, c)
			root := newCommand(c)
			root.PersistentPreRunE = nil
			root.SetArgs(test.args)
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRetiredConnectionArgumentsAreRejected(t *testing.T) {
	for _, args := range [][]string{
		{"setup", "--cluster", "cluster-a"}, {"setup", "--new-booking"},
		{"credential", "--session", sessionA}, {"credential", "--auto", "a-legacy"},
		{"kubeconfig", sessionA}, {"token", "create", "--session", sessionA},
		{"start", "--ttl", "4h"}, {"renew", sessionA, "--ttl", "4h"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			root := NewCommand()
			root.PersistentPreRunE = nil
			root.SetArgs(args)
			if err := root.Execute(); err == nil {
				t.Fatal("retired session-specific flow accepted")
			}
		})
	}
}

func TestAdminReservationPolicyPartialAndAtomicChanges(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want map[string]any
	}{
		{"read policy", nil, nil},
		{"limit only", []string{"--max-bookings", "3"}, map[string]any{"default_max_bookings": float64(3)}},
		{"grace only", []string{"--inactive-grace", "90m"}, map[string]any{"inactivity_grace_period": "1h30m0s"}},
		{"atomic update", []string{"--inactive-grace", "4h", "--max-bookings", "2"}, map[string]any{"default_max_bookings": float64(2), "inactivity_grace_period": "4h0m0s"}},
		{"minimum grace", []string{"--inactive-grace", "1m"}, map[string]any{"inactivity_grace_period": time.Minute.String()}},
		{"maximum grace", []string{"--inactive-grace", "168h"}, map[string]any{"inactivity_grace_period": (168 * time.Hour).String()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			c, out := testAccessClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != "/v1/admin/settings" {
					t.Error("unexpected policy endpoint", r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if test.want == nil {
					if r.Method != "GET" {
						t.Error("reading policy must not update it")
					}
				} else {
					if r.Method != "PATCH" {
						t.Error("policy update was not atomic PATCH")
					}
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if len(body) != len(test.want)+1 || body["reason"] != "reservation policy" {
						t.Error("update unexpectedly replaced other settings or omitted reason", body)
					}
					for key, want := range test.want {
						if body[key] != want {
							t.Error("wrong policy value", key, body[key], want)
						}
					}
				}
				_, _ = w.Write([]byte(`{"default_max_bookings":2,"inactivity_grace_period":"4h0m0s"}`))
			})
			saveAccessTestToken(t, c)
			root := newCommand(c)
			root.PersistentPreRunE = nil
			args := append([]string{"admin", "settings"}, test.args...)
			if test.want != nil {
				args = append(args, "--reason", "reservation policy")
			}
			root.SetArgs(args)
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 1 || !strings.Contains(out.String(), `"inactivity_grace_period": "4h0m0s"`) {
				t.Fatal("policy was not returned after exactly one operation", out.String())
			}
		})
	}
}

func TestAdminReservationPolicyRejectsInvalidUpdatesLocally(t *testing.T) {
	for _, args := range [][]string{
		{"--inactive-grace", "4h"},
		{"--inactive-grace", "4h", "--reason", "  "},
		{"--inactive-grace", "0", "--reason", "change"},
		{"--inactive-grace", "59s", "--reason", "change"},
		{"--inactive-grace", "60.1s", "--reason", "change"},
		{"--inactive-grace", "168h1s", "--reason", "change"},
		{"--inactive-grace", "not-a-duration", "--reason", "change"},
		{"--inactive-grace", "-1h", "--reason", "change"},
		{"--max-bookings", "0", "--inactive-grace", "4h", "--reason", "change"},
		{"--max-bookings", "101", "--reason", "change"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			c, _ := testAccessClient(t, func(http.ResponseWriter, *http.Request) {
				t.Error("invalid policy reached backend")
			})
			root := newCommand(c)
			root.PersistentPreRunE = nil
			root.SetArgs(append([]string{"admin", "settings"}, args...))
			if err := root.Execute(); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}
