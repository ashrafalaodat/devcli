package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"github.com/spf13/cobra"
)

func executePATUpdate(c *Client, args ...string) error {
	root := &cobra.Command{Use: "devctl", SilenceErrors: true, SilenceUsage: true}
	c.addPATCommands(root)
	root.SetArgs(append([]string{"token", "update"}, args...))
	return root.Execute()
}

func TestPersonalCreateAutomaticBookingIsExplicitAndValidatesSelectors(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want *model.AutoBookingPolicy
	}{
		{name: "default remains manual"},
		{name: "explicit opt in matches any free cluster", args: []string{"--auto-book"}, want: &model.AutoBookingPolicy{Enabled: true, Selector: map[string]string{}}},
		{name: "matching labels", args: []string{"--auto-book", "--selector", "region=eu,environment=testing"}, want: &model.AutoBookingPolicy{Enabled: true, Selector: map[string]string{"region": "eu", "environment": "testing"}}},
		{name: "saved rule does not implicitly opt in", args: []string{"--selector", "example.com/purpose="}, want: &model.AutoBookingPolicy{Selector: map[string]string{"example.com/purpose": ""}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var posts atomic.Int32
			c, out, diagnostics := personalTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				if r.Method != "POST" || r.URL.Path != "/v1/pats" {
					t.Error("preferences attempted a booking or unexpected request")
				}
				var body struct {
					Name   string                   `json:"name"`
					TTL    string                   `json:"ttl"`
					Policy *model.AutoBookingPolicy `json:"auto_booking"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.TTL != "8h" || !reflect.DeepEqual(body.Policy, test.want) {
					t.Error("unexpected creation preferences", body.Policy, err)
				}
				personalResponse(w, personalTestID)
			})
			if err := executePersonal(t, c, test.args...); err != nil {
				t.Fatal(err)
			}
			if posts.Load() != 1 {
				t.Fatal("creation made unexpected API calls")
			}
			assertPersonalSecretHidden(t, out, diagnostics, nil)
		})
	}
	for _, selector := range []string{"region", "=eu", "region=eu,region=us", "bad key=value", "region=bad/value"} {
		t.Run("invalid "+selector, func(t *testing.T) {
			c, _, _ := personalTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid selector reached API") })
			if err := executePersonal(t, c, "--auto-book", "--selector", selector); err == nil {
				t.Fatal("invalid selector accepted")
			}
		})
	}
}

func TestPersonalUpdateChangesOnlyRequestedPreferencesAndPreservesConfig(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want model.AutoBookingPolicy
	}{
		{name: "replace selector", args: []string{"--selector", "region=us,purpose=tests"}, want: model.AutoBookingPolicy{Enabled: true, Selector: map[string]string{"region": "us", "purpose": "tests"}}},
		{name: "disable preserves selector", args: []string{"--auto-book=false"}, want: model.AutoBookingPolicy{Enabled: false, Selector: map[string]string{"region": "eu"}}},
		{name: "clear preserves enabled", args: []string{"--clear-selector"}, want: model.AutoBookingPolicy{Enabled: true, Selector: map[string]string{}}},
		{name: "both explicitly", args: []string{"--auto-book=false", "--selector", "region=us", "--reason", "  Administrator policy change  "}, want: model.AutoBookingPolicy{Enabled: false, Selector: map[string]string{"region": "us"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			expiry := time.Now().UTC().Add(8 * time.Hour)
			existing := store.PAT{ID: personalTestID, Name: "Existing laptop", Scope: "kubernetes:primary", ExpiresAt: expiry, AutoBooking: model.AutoBookingPolicy{Enabled: true, Selector: map[string]string{"region": "eu"}}}
			var gets, patches atomic.Int32
			c, out, _ := personalTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/pats/"+personalTestID {
					t.Error("update used unexpected endpoint", r.URL.Path)
				}
				switch r.Method {
				case "GET":
					gets.Add(1)
					_ = json.NewEncoder(w).Encode(existing)
				case "PATCH":
					patches.Add(1)
					var body struct {
						Policy model.AutoBookingPolicy `json:"auto_booking"`
						Reason string                  `json:"reason"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !reflect.DeepEqual(body.Policy, test.want) {
						t.Error("omitted fields lost or supplied selector ignored", body.Policy, err)
					}
					if len(test.args) > 2 && test.args[len(test.args)-2] == "--reason" && body.Reason != "Administrator policy change" {
						t.Error("audit reason not sent or normalized")
					}
					existing.AutoBooking = body.Policy
					_ = json.NewEncoder(w).Encode(existing)
				default:
					t.Error("update allocated, rotated or revoked a credential", r.Method)
				}
			})
			config := filepath.Join(c.Login.Dir, personalTestID+".yaml")
			if err := os.WriteFile(config, []byte(personalTestConfig), 0600); err != nil {
				t.Fatal(err)
			}
			if err := executePATUpdate(c, append([]string{personalTestID}, test.args...)...); err != nil {
				t.Fatal(err)
			}
			if gets.Load() != 1 || patches.Load() != 1 {
				t.Fatal("update did not read then patch one credential")
			}
			var result store.PAT
			if json.Unmarshal(out.Bytes(), &result) != nil || result.ID != personalTestID || !result.ExpiresAt.Equal(expiry) || !reflect.DeepEqual(result.AutoBooking, test.want) {
				t.Fatal("update replaced identity, expiry or preferences")
			}
			content, err := os.ReadFile(config)
			if err != nil || string(content) != personalTestConfig {
				t.Fatal("editing server preferences changed downloaded kubeconfig", err)
			}
		})
	}
}

func TestPersonalUpdateRejectsInvalidInputWithoutNetwork(t *testing.T) {
	for _, args := range [][]string{
		{personalTestID},
		{personalTestID, "--reason", "reason alone"},
		{"../other", "--auto-book"},
		{personalTestID, "--selector", "region=us", "--clear-selector"},
		{personalTestID, "--selector", "region"},
		{personalTestID, "--selector", "region=eu,region=us"},
		{personalTestID, "--selector", "bad key=value"},
		{personalTestID, "--auto-book", "--reason", strings.Repeat("x", 1001)},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			c, _, _ := personalTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid update reached backend") })
			if err := executePATUpdate(c, args...); err == nil {
				t.Fatal("invalid preferences accepted")
			}
		})
	}
}

func TestPersonalUpdateReportsPermissionsAndUnavailableCredentials(t *testing.T) {
	for _, status := range []int{403, 404, 409} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			c, out, _ := personalTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					_ = json.NewEncoder(w).Encode(store.PAT{ID: personalTestID, AutoBooking: model.AutoBookingPolicy{Selector: map[string]string{}}})
					return
				}
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "preferences cannot be changed"})
			})
			var exit *ExitError
			err := executePATUpdate(c, personalTestID, "--auto-book", "--reason", "Administrative rule")
			want := map[int]int{403: 3, 404: 5, 409: 4}[status]
			if !errors.As(err, &exit) || exit.Code != want || out.Len() != 0 {
				t.Fatal("update failure lost exit code or printed success", err)
			}
		})
	}
}
