package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebhookCreateIsDisabledAndReturnsSecretOnce(t *testing.T) {
	output, err := runHealthCommand(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/admin/webhooks" {
			t.Error("wrong webhook request")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["enabled"] != false || body["name"] != "Notify team" || body["reason"] != "Owned receiver" || body["timeout_seconds"] != float64(3600) {
			t.Error("invalid webhook body", body)
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"rule": map[string]any{"id": "w-fixture", "enabled": false}, "secret": "inert-test-signing-key"})
	}, "admin", "webhooks", "create", "--name", "Notify team", "--url", "https://ci.example.test/events", "--event", "book", "--reason", " Owned receiver ", "--json")
	if err != nil || !json.Valid([]byte(output)) || !strings.Contains(output, "inert-test-signing-key") {
		t.Fatal("creation did not return one-time response", err)
	}
}

func TestWebhookInvalidInputDoesNotContactBackend(t *testing.T) {
	cases := [][]string{
		{"create", "--name", "Notify", "--url", "https://ci.example.test/events", "--event", "book"},
		{"create", "--name", "Notify", "--url", "http://ci.example.test/events", "--event", "book", "--reason", "test"},
		{"create", "--name", "Notify", "--url", "https://user:secret@ci.example.test/events", "--event", "book", "--reason", "test"},
		{"create", "--name", "Notify", "--url", "https://ci.example.test/events?token=secret", "--event", "book", "--reason", "test"},
		{"create", "--name", "Notify", "--url", "https://ci.example.test/events", "--event", "book", "--blocking", "--idempotent", "--reason", "test"},
		{"create", "--name", "Notify", "--url", "https://ci.example.test/events", "--event", "cluster_idle", "--blocking", "--reason", "test"},
		{"create", "--name", "Notify", "--url", "https://ci.example.test/events", "--event", "book", "--timeout", "1m", "--reason", "test"},
		{"update", "w-fixture", "--reason", "test"},
		{"disable", "../elsewhere", "--reason", "test"},
		{"retry", "d-fixture", "--reason", "test"},
		{"resolve", "d-fixture", "--expected-state", "FAILED", "--reason", "test"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out, err := runHealthCommand(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid input contacted backend") }, append([]string{"admin", "webhooks"}, args...)...)
			if err == nil || out != "" {
				t.Fatal("invalid request accepted", out, err)
			}
		})
	}
}

func TestWebhookDisablePreservesRuleAndRejectsStaleVersion(t *testing.T) {
	var requests int
	output, err := runHealthCommand(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(map[string]any{"rules": []map[string]any{{"id": "w-fixture", "name": "Existing", "url": "https://ci.example.test/events", "events": []string{"cluster_idle"}, "cluster_id": "lab", "selector": map[string]string{"region": "eu"}, "blocking": true, "idempotent": true, "enabled": true, "timeout_seconds": 900, "version": 7}}})
			return
		}
		if r.Method != "PATCH" || r.URL.Path != "/v1/admin/webhooks/w-fixture" {
			t.Error("wrong disable request")
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["enabled"] != false || body["expected_version"] != float64(7) || body["blocking"] != true || body["url"] != "https://ci.example.test/events" || body["timeout_seconds"] != float64(900) {
			t.Error("disable overwrote rule configuration", body)
		}
		w.WriteHeader(409)
		json.NewEncoder(w).Encode(map[string]string{"error": "rule changed; reload"})
	}, "admin", "webhooks", "disable", "w-fixture", "--reason", "Pause future events", "--json")
	var conflict *ExitError
	if !errors.As(err, &conflict) || conflict.Code != 4 || output != "" || requests != 2 {
		t.Fatal("disable conflict retried or hidden", requests, output, err)
	}
}

func TestWebhookUpdateUsesWholeMetadataFileAndExplicitVersion(t *testing.T) {
	file := filepath.Join(t.TempDir(), "rule.json")
	if err := os.WriteFile(file, []byte(`{"name":"Edited","url":"https://ci.example.test/events","events":["book"],"selector":{},"blocking":false,"idempotent":false,"enabled":false,"timeout_seconds":900}`), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := runHealthCommand(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" || r.URL.Path != "/v1/admin/webhooks/w-fixture" {
			t.Error("wrong update request")
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["expected_version"] != float64(3) || body["name"] != "Edited" || body["reason"] != "Review new filters" {
			t.Error("invalid replacement body", body)
		}
		json.NewEncoder(w).Encode(map[string]any{"rule": map[string]any{"id": "w-fixture", "version": 4}})
	}, "admin", "webhooks", "update", "w-fixture", "--file", file, "--expected-version", "3", "--reason", "Review new filters", "--json")
	if err != nil || !json.Valid([]byte(output)) {
		t.Fatal(output, err)
	}
}

func TestWebhookResolveRequiresScopedStateAndExternalStopConfirmation(t *testing.T) {
	out, err := runHealthCommand(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/admin/webhook-deliveries/d-fixture/resolve" {
			t.Error("wrong resolution request")
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["confirmed_stopped"] != true || body["expected_state"] != "TIMED_OUT" || body["reason"] != "Pipeline stopped and cluster reviewed" {
			t.Error("resolution omitted scope/confirmation", body)
		}
		json.NewEncoder(w).Encode(map[string]string{"state": "RESOLVED"})
	}, "admin", "webhooks", "resolve", "d-fixture", "--expected-state", "TIMED_OUT", "--confirmed-stopped", "--reason", "Pipeline stopped and cluster reviewed", "--json")
	if err != nil || !strings.Contains(out, "RESOLVED") {
		t.Fatal(out, err)
	}
}

func TestWebhookListsRemainReadOnly(t *testing.T) {
	for _, name := range []string{"list", "runs"} {
		t.Run(name, func(t *testing.T) {
			out, err := runHealthCommand(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Error("listing mutated backend")
				}
				json.NewEncoder(w).Encode([]any{})
			}, "admin", "webhooks", name, "--json")
			if err != nil || !json.Valid([]byte(out)) {
				t.Fatal(out, err)
			}
		})
	}
}
