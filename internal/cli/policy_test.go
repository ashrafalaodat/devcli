package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
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
