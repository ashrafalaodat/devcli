package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"devctl.local/devctl/internal/auth"
	"k8s.io/client-go/tools/clientcmd"
)

const legacyConfig = `apiVersion: v1
kind: Config
current-context: old
clusters:
- name: old
  cluster:
    server: https://original-cluster.example.test
contexts:
- name: old
  context:
    cluster: old
    user: old
users:
- name: old
  user:
    token: old-cluster-token-sentinel
    client-key-data: cHJpdmF0ZS1rZXktc2VudGluZWw=
`

func TestProfileInitializationScrubsOnlyKnownLegacyCopies(t *testing.T) {
	root := t.TempDir()
	t.Setenv("DEVCTL_CONFIG_DIR", root)
	config := auth.DefaultConfig("https://identity.example.test")
	first, e := newLoginStore("https://devctl.example.test", config)
	if e != nil {
		t.Fatal(e)
	}
	legacy := filepath.Join(first.Dir, sessionA+".yaml")
	active := filepath.Join(first.Dir, "active-kubeconfig")
	for _, path := range []string{legacy, active} {
		if e = os.WriteFile(path, []byte(legacyConfig), 0600); e != nil {
			t.Fatal(e)
		}
	}
	// Unrelated files and copies outside the private generated profile are not
	// migration targets, even when their content or name resembles a kubeconfig.
	unrelated := filepath.Join(first.Dir, "my-original-config.yaml")
	outside := filepath.Join(root, sessionA+".yaml")
	for _, path := range []string{unrelated, outside} {
		if e = os.WriteFile(path, []byte(legacyConfig), 0600); e != nil {
			t.Fatal(e)
		}
	}
	public := filepath.Join(first.Dir, sessionB+".yaml")
	safe := []byte("apiVersion: v1\nkind: Config\ncurrent-context: empty\n")
	if e = os.WriteFile(public, safe, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = newLoginStore("https://devctl.example.test", config); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{legacy, active} {
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(raw, []byte("sentinel")) || bytes.Contains(raw, []byte("original-cluster")) || !bytes.Equal(raw, inactiveConfig) {
			t.Fatal("legacy credentials survived migration")
		}
		parsed, e := clientcmd.Load(raw)
		if e != nil {
			t.Fatal(e)
		}
		if clientcmd.Validate(*parsed) == nil {
			t.Fatal("migration did not disable old config")
		}
	}
	for _, path := range []string{unrelated, outside} {
		raw, e := os.ReadFile(path)
		if e != nil || string(raw) != legacyConfig {
			t.Fatal("unrelated original configuration changed", e)
		}
	}
	raw, e := os.ReadFile(public)
	if e != nil || !bytes.Equal(raw, safe) {
		t.Fatal("nonsecret gateway metadata changed", e)
	}
}
func TestLegacyMigrationRefusesSymlinksAndOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "original")
	if e := os.WriteFile(target, []byte(legacyConfig), 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, sessionA+".yaml")
	if e := os.Symlink(target, link); e != nil {
		t.Fatal(e)
	}
	if e := scrubLegacySessionConfigs(dir); e == nil {
		t.Fatal("migration followed a symlink")
	}
	raw, e := os.ReadFile(target)
	if e != nil || string(raw) != legacyConfig {
		t.Fatal("symlink target modified", e)
	}
	if e = os.Remove(link); e != nil {
		t.Fatal(e)
	}
	file, e := os.Create(link)
	if e != nil {
		t.Fatal(e)
	}
	if e = file.Truncate((2 << 20) + 1); e != nil {
		file.Close()
		t.Fatal(e)
	}
	file.Close()
	if e = scrubLegacySessionConfigs(dir); e == nil {
		t.Fatal("migration accepted an unbounded file")
	}
}
