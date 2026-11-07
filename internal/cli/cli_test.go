package cli

import (
	"context"
	"devctl.local/devctl/internal/auth"
	"golang.org/x/oauth2"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrivateFilesAndSessionPaths(t *testing.T) {
	root := t.TempDir()
	t.Setenv("DEVCTL_CONFIG_DIR", root)
	t.Setenv("DEVCTL_DEV_TOKEN_FILE", "1")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent-devctl-test")
	s, e := newLoginStore("http://127.0.0.1:8080", auth.DefaultConfig("http://127.0.0.1:8081"))
	if e != nil {
		t.Fatal(e)
	}
	token := &oauth2.Token{AccessToken: "private-access", RefreshToken: "private-refresh", Expiry: time.Now().Add(time.Hour)}
	if e = s.save(token); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(filepath.Join(s.Dir, "tokens.json"))
	if e != nil {
		t.Fatal(e)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("token file permissions", info.Mode())
	}
	got, e := s.token(context.Background())
	if e != nil || got.AccessToken != token.AccessToken {
		t.Fatal(e)
	}
	c := &Client{Login: s}
	for _, id := range []string{"../../escape", "s-../../bad", "anything"} {
		if _, e = c.configPath(id); e == nil {
			t.Fatal("unsafe session filename")
		}
	}
	id := "s-12345678-1234-1234-1234-123456789abc"
	p, e := c.configPath(id)
	if e != nil {
		t.Fatal(e)
	}
	if e = atomicPrivate(p, []byte("secret")); e != nil {
		t.Fatal(e)
	}
	info, _ = os.Stat(p)
	if info.Mode().Perm() != 0600 {
		t.Fatal("kubeconfig mode")
	}
	if e = s.clear(); e != nil {
		t.Fatal(e)
	}
	if _, e = s.read(); e == nil {
		t.Fatal("logout retained token")
	}
}
func TestStrictLabelParsing(t *testing.T) {
	if _, e := labelMap([]string{"missing-value"}); e == nil {
		t.Fatal("invalid label accepted")
	}
	m, e := labelMap([]string{"region=eu", "type=test"})
	if e != nil || m["region"] != "eu" {
		t.Fatal(m, e)
	}
}
