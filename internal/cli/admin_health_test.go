package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func runHealthCommand(t *testing.T, handler http.HandlerFunc, args ...string) (string, error) {
	t.Helper()
	c, out := testAccessClient(t, handler)
	saveAccessTestToken(t, c)
	command := newCommand(c)
	command.PersistentPreRunE = nil
	command.SetArgs(args)
	err := command.Execute()
	return out.String(), err
}

func TestAdminHealthModeRequiresAuditedChoice(t *testing.T) {
	var changes atomic.Int32
	output, err := runHealthCommand(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" || r.URL.Path != "/v1/admin/health" {
			t.Error("wrong policy operation")
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["mode"] != "observe" || body["reason"] != "Approved read-only checks" {
			t.Error("invalid policy", body)
		}
		changes.Add(1)
		json.NewEncoder(w).Encode(map[string]string{"mode": "observe"})
	}, "admin", "health", "--mode", "observe", "--reason", "  Approved read-only checks  ", "--json")
	if err != nil || changes.Load() != 1 || !json.Valid([]byte(output)) {
		t.Fatal(output, err)
	}
}

func TestAdminHealthValidatesBeforeNetwork(t *testing.T) {
	for _, args := range [][]string{
		{"health", "--mode", "healthy", "--reason", "fixture"},
		{"health", "--mode", "enforce"},
		{"health", "--reason", "ignored"},
		{"cluster", "check", "cluster-a"},
		{"cluster", "check", "cluster-a", "--reason", "   "},
		{"cluster", "check", "cluster-a", "--reason", "fixture", "--timeout", "2s"},
		{"cluster", "check", "../secret", "--reason", "fixture"},
		{"cluster", "check", "cluster-a", "--reason", "fixture", "--wait", "--timeout", "0s"},
		{"cluster", "profile", "cluster-a", "--profile", "unsafe", "--reason", "fixture"},
		{"cluster", "profile", "cluster-a", "--profile", "api-ready.v1", "--reason", "fixture", "--expected-revision", "0"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			output, err := runHealthCommand(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid request contacted backend") }, append([]string{"admin"}, args...)...)
			if err == nil || output != "" {
				t.Fatal("invalid command accepted", output, err)
			}
		})
	}
}

func TestAdminHealthProfileSnapshotsRevisionAndPreservesConflict(t *testing.T) {
	var calls []string
	output, err := runHealthCommand(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(map[string]any{"profile": "api-ready.v1", "policy_revision": 7})
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["expected_revision"] != float64(7) || body["profile"] != "discovery-only.v1" || body["reason"] != "Readiness explicitly excluded" {
			t.Error("invalid stale-write snapshot", body)
		}
		w.WriteHeader(409)
		json.NewEncoder(w).Encode(map[string]string{"error": "health profile changed; reload and review"})
	}, "admin", "cluster", "profile", "cluster-a", "--profile", "discovery-only.v1", "--reason", "Readiness explicitly excluded", "--json")
	var failure *ExitError
	if !errors.As(err, &failure) || failure.Code != 4 || output != "" || len(calls) != 2 {
		t.Fatal("conflict was retried or hidden", calls, output, err)
	}
}

func TestAdminHealthCheckWaitCompletesRecoveringCycle(t *testing.T) {
	before := time.Now().UTC().Add(-time.Minute)
	after := time.Now().UTC()
	var posts, gets atomic.Int32
	output, err := runHealthCommand(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			posts.Add(1)
			w.WriteHeader(202)
			json.NewEncoder(w).Encode(map[string]any{"id": "hc-fixture", "pending": true, "health": map[string]any{"checked_at": before, "check_pending": true, "state": "UNKNOWN"}})
			return
		}
		gets.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"checked_at": after, "check_pending": false, "state": "RECOVERING", "mode": "enforce", "reason_code": "recovering"})
	}, "admin", "cluster", "check", "cluster-a", "--reason", "Verify API", "--wait", "--timeout", "2s", "--json")
	if err != nil || posts.Load() != 1 || gets.Load() != 1 || !json.Valid([]byte(output)) || !strings.Contains(output, `"RECOVERING"`) {
		t.Fatal("wait did not finish one completed cycle", output, err)
	}
}

func TestAdminHealthFailedCheckProducesJSONAndNonzeroExit(t *testing.T) {
	output, err := runHealthCommand(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(map[string]any{"id": "hc-fixture", "pending": false, "health": map[string]any{"checked_at": time.Now().UTC(), "check_pending": false, "state": "FAILING", "mode": "observe", "reason_code": "tls_untrusted"}})
	}, "admin", "cluster", "check", "cluster-a", "--reason", "Inspect TLS", "--wait", "--json")
	var failure *ExitError
	if !errors.As(err, &failure) || failure.Code != 4 || !json.Valid([]byte(output)) || !strings.Contains(output, "tls_untrusted") {
		t.Fatal("failed cycle lost machine output or exit status", output, err)
	}
}

func TestAdminHealthWaitIsBoundedAndDoesNotRepeatRequest(t *testing.T) {
	var posts atomic.Int32
	old := time.Now().UTC().Add(-time.Minute)
	output, err := runHealthCommand(t, func(w http.ResponseWriter, r *http.Request) {
		h := map[string]any{"checked_at": old, "check_pending": true, "state": "UNKNOWN"}
		if r.Method == "POST" {
			posts.Add(1)
			w.WriteHeader(202)
			json.NewEncoder(w).Encode(map[string]any{"id": "hc-fixture", "pending": true, "health": h})
			return
		}
		json.NewEncoder(w).Encode(h)
	}, "admin", "cluster", "check", "cluster-a", "--reason", "Bounded request", "--wait", "--timeout", "1s", "--json")
	if err == nil || posts.Load() != 1 || output != "" {
		t.Fatal("wait was unbounded or retriggered work", output, err)
	}
}

func TestAdminHealthWaitRejectsReconfiguredCycle(t *testing.T) {
	output, err := runHealthCommand(t, func(w http.ResponseWriter, r *http.Request) {
		h := map[string]any{"mode": "observe", "configuration_generation": 1, "policy_revision": 1, "checked_at": time.Now().UTC().Add(-time.Minute), "check_pending": true, "state": "UNKNOWN"}
		if r.Method == "POST" {
			w.WriteHeader(202)
			json.NewEncoder(w).Encode(map[string]any{"id": "hc-fixture", "pending": true, "health": h})
			return
		}
		h["policy_revision"] = 2
		h["check_pending"] = false
		h["state"] = "PASSING"
		h["checked_at"] = time.Now().UTC()
		json.NewEncoder(w).Encode(h)
	}, "admin", "cluster", "check", "cluster-a", "--reason", "Versioned request", "--wait", "--timeout", "2s", "--json")
	var failure *ExitError
	if !errors.As(err, &failure) || failure.Code != 4 || output != "" || !strings.Contains(err.Error(), "changed while waiting") {
		t.Fatal("new policy result was accepted for an old request", output, err)
	}
}
