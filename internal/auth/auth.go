package auth

import (
	"context"
	"devctl.local/devctl/internal/model"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"strings"
)

type Config struct {
	Issuer         string   `json:"issuer"`
	ClientID       string   `json:"client_id"`
	Audience       string   `json:"audience"`
	Scopes         []string `json:"scopes"`
	Redirect       string   `json:"redirect"`
	GroupsClaim    string   `json:"groups_claim"`
	DeveloperGroup string   `json:"developer_group"`
	AdminGroup     string   `json:"admin_group"`
	AccessClaim    string   `json:"access_claim"`
	AccessValue    string   `json:"access_value"`
}

func DefaultConfig(issuer string) Config {
	return Config{Issuer: issuer, ClientID: "devctl-cli", Audience: "devctl-api", Scopes: []string{"openid", "profile", "email"}, Redirect: "http://127.0.0.1:18000/callback", GroupsClaim: "groups", DeveloperGroup: "/developers", AdminGroup: "/administrators", AccessClaim: "typ", AccessValue: "Bearer"}
}

type Verifier struct {
	Provider *oidc.Provider
	V        *oidc.IDTokenVerifier
	Config   Config
}

func New(ctx context.Context, c Config) (*Verifier, error) {
	if c.Issuer == "" || c.Audience == "" || c.AccessClaim == "" || c.AccessValue == "" || c.DeveloperGroup == "" || c.AdminGroup == "" {
		return nil, errors.New("incomplete OIDC configuration")
	}
	p, e := oidc.NewProvider(ctx, c.Issuer)
	if e != nil {
		return nil, e
	}
	return &Verifier{p, p.Verifier(&oidc.Config{ClientID: c.Audience}), c}, nil
}
func claim(m map[string]any, path string) any {
	var v any = m
	for _, k := range strings.Split(path, ".") {
		a, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = a[k]
	}
	return v
}
func (v *Verifier) Verify(ctx context.Context, raw string) (model.Identity, error) {
	t, e := v.V.Verify(ctx, raw)
	if e != nil {
		return model.Identity{}, errors.New("invalid access token")
	}
	var m map[string]any
	if e = t.Claims(&m); e != nil {
		return model.Identity{}, e
	}
	if claim(m, v.Config.AccessClaim) != v.Config.AccessValue {
		return model.Identity{}, errors.New("API requires an access token, not an ID token")
	}
	if t.Subject == "" {
		return model.Identity{}, errors.New("missing subject")
	}
	groups, _ := claim(m, v.Config.GroupsClaim).([]any)
	dev, admin := false, false
	for _, g := range groups {
		dev = dev || g == v.Config.DeveloperGroup
		admin = admin || g == v.Config.AdminGroup
	}
	if !dev && !admin {
		return model.Identity{}, errors.New("user is not approved for devctl")
	}
	name, _ := m["preferred_username"].(string)
	display, _ := m["name"].(string)
	email, _ := m["email"].(string)
	if display == "" {
		display = name
	}
	return model.Identity{Issuer: t.Issuer, Subject: t.Subject, Name: name, DisplayName: display, Email: email, Admin: admin, TokenExpiresAt: t.Expiry}, nil
}
