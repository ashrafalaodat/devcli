package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/auth"
	"devctl.local/devctl/internal/store"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

const personalTestID = "p-12345678-1234-1234-1234-123456789abc"
const personalTestSecret = "dcpat_PRIVATE_CREDENTIAL_RESPONSE_CONTENT"
const personalTestConfig = "apiVersion: v1\nkind: Config\nusers:\n- name: gateway\n  user:\n    token: " + personalTestSecret + "\n"

func personalTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	t.Setenv("DEVCTL_CONFIG_DIR", t.TempDir())
	t.Setenv("DEVCTL_DEV_TOKEN_FILE", "1")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent-devctl-pat-test")
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	login, err := newLoginStore(srv.URL, auth.DefaultConfig("http://127.0.0.1:1/issuer"))
	if err != nil {
		t.Fatal(err)
	}
	if err = login.save(&oauth2.Token{AccessToken: "personal-test-access", RefreshToken: "personal-test-refresh", Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	out, diagnostics := new(bytes.Buffer), new(bytes.Buffer)
	return &Client{URL: srv.URL, HTTP: srv.Client(), Login: login, Out: out, Err: diagnostics}, out, diagnostics
}

func executePersonal(t *testing.T, c *Client, args ...string) error {
	t.Helper()
	root := &cobra.Command{Use: "devctl", SilenceErrors: true, SilenceUsage: true}
	c.addPATCommands(root)
	root.SetArgs(append([]string{"token", "create", "--session", sessionA}, args...))
	return root.Execute()
}

func personalResponse(w http.ResponseWriter, id string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"pat": store.PAT{ID: id, SessionID: sessionA, Name: "Test laptop", ExpiresAt: time.Now().Add(time.Hour)}, "kubeconfig": personalTestConfig})
}

func assertPersonalSecretHidden(t *testing.T, out, diagnostics *bytes.Buffer, err error) {
	t.Helper()
	message := out.String() + diagnostics.String()
	if err != nil {
		message += err.Error()
	}
	if strings.Contains(message, personalTestSecret) || strings.Contains(message, "apiVersion: v1") {
		t.Fatal("credential response body leaked to stdout, stderr, or an error")
	}
}

func TestPersonalCreateWritesPrivateFileAndOnlyPath(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "default profile", true: "explicit output"}[explicit], func(t *testing.T) {
			var posts atomic.Int32
			c, out, diagnostics := personalTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/v1/pats" || r.Header.Get("Authorization") != "Bearer personal-test-access" {
					t.Error("unexpected credential request")
					w.WriteHeader(400)
					return
				}
				posts.Add(1)
				personalResponse(w, personalTestID)
			})
			c.JSON = true // Path output remains suitable for KUBECONFIG even in JSON mode.
			want := filepath.Join(c.Login.Dir, personalTestID+".yaml")
			var args []string
			if explicit {
				want = filepath.Join(t.TempDir(), "personal gateway.yaml")
				args = []string{"--output", want}
			}
			if err := executePersonal(t, c, args...); err != nil {
				t.Fatal(err)
			}
			if posts.Load() != 1 || out.String() != want+"\n" {
				t.Fatal("credential command did not print exactly one absolute path")
			}
			info, err := os.Stat(want)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				t.Fatal("credential file was not private and regular", err)
			}
			stored, err := os.ReadFile(want)
			if err != nil || string(stored) != personalTestConfig {
				t.Fatal("credential file contents lost", err)
			}
			assertPersonalSecretHidden(t, out, diagnostics, nil)
		})
	}
}

func TestPersonalCreatePreservesFilesAndReportsRevocation(t *testing.T) {
	for _, kind := range []string{"regular", "symlink"} {
		for _, revoked := range []bool{false, true} {
			name := kind + map[bool]string{false: " revocation failure", true: " revoked"}[revoked]
			t.Run(name, func(t *testing.T) {
				var deletes atomic.Int32
				c, out, diagnostics := personalTestClient(t, func(w http.ResponseWriter, r *http.Request) {
					switch r.Method {
					case "POST":
						personalResponse(w, personalTestID)
					case "DELETE":
						deletes.Add(1)
						if r.URL.Path != "/v1/pats/"+personalTestID {
							t.Error("cleanup revoked a different credential")
						}
						w.Header().Set("Content-Type", "application/json")
						if !revoked {
							w.WriteHeader(http.StatusServiceUnavailable)
							_ = json.NewEncoder(w).Encode(map[string]string{"error": personalTestSecret})
							return
						}
						_ = json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
					default:
						w.WriteHeader(400)
					}
				})
				dir := t.TempDir()
				target := filepath.Join(dir, "original.yaml")
				if err := os.WriteFile(target, []byte("keep this original config"), 0640); err != nil {
					t.Fatal(err)
				}
				output := target
				if kind == "symlink" {
					output = filepath.Join(dir, "selected.yaml")
					if err := os.Symlink(target, output); err != nil {
						t.Fatal(err)
					}
				}
				err := executePersonal(t, c, "--output", output)
				if err == nil || deletes.Load() != 1 || out.Len() != 0 {
					t.Fatal("existing target was overwritten or failed cleanup went unreported")
				}
				if revoked && !strings.Contains(err.Error(), "issued PAT was revoked") {
					t.Fatal("successful revocation was not reported")
				}
				if !revoked && (!strings.Contains(err.Error(), "could not revoke issued PAT "+personalTestID) || strings.Contains(err.Error(), "was revoked")) {
					t.Fatal("failed revocation was reported as success")
				}
				stored, readErr := os.ReadFile(target)
				if readErr != nil || string(stored) != "keep this original config" {
					t.Fatal("original config changed", readErr)
				}
				if kind == "symlink" {
					link, readErr := os.Readlink(output)
					if readErr != nil || link != target {
						t.Fatal("existing symlink changed", readErr)
					}
				}
				assertPersonalSecretHidden(t, out, diagnostics, err)
			})
		}
	}
}

func TestPersonalCreateRejectsUnsafeReturnedIDs(t *testing.T) {
	for _, id := range []string{"", "../../escaped", "p-not-a-uuid", "p-12345678-1234-1234-1234-123456789abc/escape"} {
		t.Run(id, func(t *testing.T) {
			var deletes atomic.Int32
			c, out, diagnostics := personalTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "DELETE" {
					deletes.Add(1)
				}
				personalResponse(w, id)
			})
			err := executePersonal(t, c)
			if err == nil || !strings.Contains(err.Error(), "invalid personal credential response") || deletes.Load() != 0 || out.Len() != 0 {
				t.Fatal("unsafe identifier became a local path or API route")
			}
			files, globErr := filepath.Glob(filepath.Join(c.Login.Dir, "*.yaml"))
			if globErr != nil || len(files) != 0 {
				t.Fatal("invalid credential response wrote a file", globErr)
			}
			assertPersonalSecretHidden(t, out, diagnostics, err)
		})
	}
}

func TestPersonalCreateFailureHidesResponseAndPreservesExitCode(t *testing.T) {
	c, out, diagnostics := personalTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": personalTestSecret, "kubeconfig": personalTestConfig})
	})
	err := executePersonal(t, c)
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 4 || out.Len() != 0 {
		t.Fatal("credential issuance failure lost its conflict exit code")
	}
	assertPersonalSecretHidden(t, out, diagnostics, err)
}
