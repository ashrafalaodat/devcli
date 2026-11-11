package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAdminDeregisterSendsAuditedDelete(t *testing.T) {
	var calls atomic.Int32
	c, output := testAccessClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "DELETE" || r.URL.Path != "/v1/admin/clusters/cluster-a" || r.Header.Get("Authorization") == "" {
			t.Error("wrong deregistration operation")
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 || body["reason"] != "retired test cluster" {
			t.Error("invalid audit reason payload", body, err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deregistered"})
	})
	saveAccessTestToken(t, c)
	root := newCommand(c)
	root.PersistentPreRunE = nil
	root.SetArgs([]string{"admin", "deregister", "cluster-a", "--reason", "  retired test cluster  ", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || !json.Valid(output.Bytes()) || !strings.Contains(output.String(), `"deregistered"`) {
		t.Fatal("deregistration did not return a single JSON operation")
	}
}

func TestAdminDeregisterValidatesBeforeRequest(t *testing.T) {
	for _, args := range [][]string{
		{"cluster-a"},
		{"cluster-a", "--reason", "   "},
		{"cluster-a", "--reason", strings.Repeat("x", 1001)},
		{"", "--reason", "retire"},
		{"--reason", "retire"},
		{"one", "two", "--reason", "retire"},
		{"cluster-a", "--reason", "retire", "--force"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			c, _ := testAccessClient(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid deletion reached backend") })
			root := newCommand(c)
			root.PersistentPreRunE = nil
			root.SetArgs(append([]string{"admin", "deregister"}, args...))
			if err := root.Execute(); err == nil {
				t.Fatal("invalid deregistration command accepted")
			}
		})
	}
}

func TestAdminDeregisterReportsBackendDenialAndKeepsStdoutEmpty(t *testing.T) {
	for _, test := range []struct {
		status, exit int
		message      string
	}{
		{403, 3, "administrator required"},
		{404, 5, "not found"},
		{409, 4, "release active bookings before deregistering this cluster"},
	} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			c, output := testAccessClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.status)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": test.message})
			})
			saveAccessTestToken(t, c)
			root := newCommand(c)
			root.PersistentPreRunE = nil
			root.SetArgs([]string{"admin", "deregister", "cluster-a", "--reason", "retire"})
			var exit *ExitError
			if err := root.Execute(); !errors.As(err, &exit) || exit.Code != test.exit || !strings.Contains(err.Error(), test.message) {
				t.Fatal("wrong deregistration failure", err)
			}
			if output.Len() != 0 {
				t.Fatal("failed deregistration polluted stdout")
			}
		})
	}
}
