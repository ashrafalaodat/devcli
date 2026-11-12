package integration

import (
	"encoding/json"
	"os"
	"testing"
)

// These credentials belong only to the checked-in, local Keycloak demo realm.
// Tests still authenticate through Authorization Code/PKCE browser forms.
func demoPassword(username string) string {
	if username == "alice" || username == "admin" {
		return username
	}
	return username + "-dev-only"
}

// Keep fresh disposable realms and persistent-demo browser tests in sync.
func TestDemoRealmCredentials(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/keycloak-realm.json")
	if err != nil {
		t.Fatal(err)
	}
	var realm struct {
		Users []struct {
			Username    string `json:"username"`
			Credentials []struct {
				Type      string `json:"type"`
				Value     string `json:"value"`
				Temporary bool   `json:"temporary"`
			} `json:"credentials"`
		} `json:"users"`
	}
	if err = json.Unmarshal(raw, &realm); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, user := range realm.Users {
		found[user.Username] = true
		if len(user.Credentials) != 1 || user.Credentials[0].Type != "password" ||
			user.Credentials[0].Temporary || user.Credentials[0].Value != demoPassword(user.Username) {
			t.Fatalf("demo browser credentials do not match the imported realm for %s", user.Username)
		}
	}
	for _, name := range []string{"alice", "admin", "bob", "outsider"} {
		if !found[name] {
			t.Fatalf("missing development account %s", name)
		}
	}
	if demoPassword("alice") != "alice" || demoPassword("admin") != "admin" {
		t.Fatal("the requested Alice/admin development passwords changed")
	}
}
