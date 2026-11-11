// Package browser provides a browser session in front of the existing REST API.
// OAuth credentials stay encrypted on the backend; the browser receives only an
// opaque Secure/HttpOnly cookie and a separate anti-CSRF token.
package browser

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"devctl.local/devctl/internal/auth"
	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/webui"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const sessionCookie = "__Host-devctl-web"
const loginCookie = "__Host-devctl-login"

type Config struct {
	PublicURL, ClientID, ClientSecret string
	SessionTTL                        time.Duration
}

type Handler struct {
	config        Config
	oauth         oauth2.Config
	idVerifier    *oidc.IDTokenVerifier
	verifier      *auth.Verifier
	store         *store.Store
	vault         *kube.Vault
	next, assets  http.Handler
	revocationURL string
}

type pending struct{ Verifier, Nonce string }
type credentials struct {
	Token *oauth2.Token `json:"token"`
	CSRF  string        `json:"csrf"`
}

func New(c Config, verifier *auth.Verifier, db *store.Store, vault *kube.Vault, next http.Handler) (*Handler, error) {
	origin, err := url.Parse(c.PublicURL)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") || c.ClientID == "" {
		return nil, errors.New("browser access requires a public HTTPS origin and a web OIDC client ID")
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = 8 * time.Hour
	}
	if c.SessionTTL < time.Minute || c.SessionTTL > 7*24*time.Hour {
		return nil, errors.New("browser session duration must be 1m through 168h")
	}
	c.PublicURL = strings.TrimSuffix(c.PublicURL, "/")
	endpoint := verifier.Provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	var discovery struct {
		Revocation string `json:"revocation_endpoint"`
	}
	if err = verifier.Provider.Claims(&discovery); err != nil {
		return nil, err
	}
	return &Handler{config: c, oauth: oauth2.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, Endpoint: endpoint, RedirectURL: c.PublicURL + "/auth/callback", Scopes: verifier.Config.Scopes}, idVerifier: verifier.Provider.Verifier(&oidc.Config{ClientID: c.ClientID}), verifier: verifier, store: db, vault: vault, next: next, assets: webui.Handler(), revocationURL: discovery.Revocation}, nil
}

func random() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func digest(raw string) string { sum := sha256.Sum256([]byte(raw)); return hex.EncodeToString(sum[:]) }
func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func reject(w http.ResponseWriter, status int, message string) {
	jsonReply(w, status, map[string]string{"error": message})
}
func cookie(w http.ResponseWriter, name, value string, until time.Time) {
	age := int(time.Until(until).Seconds())
	if value == "" {
		age = -1
		until = time.Unix(1, 0)
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: until, MaxAge: age})
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
	switch {
	case r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/assets/"):
		h.assets.ServeHTTP(w, r)
	case r.URL.Path == "/auth/login" && r.Method == http.MethodGet:
		h.login(w, r)
	case r.URL.Path == "/auth/callback" && r.Method == http.MethodGet:
		h.callback(w, r)
	case r.URL.Path == "/web/session" && r.Method == http.MethodGet:
		v, u, data, err := h.authenticate(r)
		if err != nil {
			cookie(w, sessionCookie, "", time.Time{})
			reject(w, 401, "sign in through the browser")
			return
		}
		jsonReply(w, 200, map[string]any{"user": u, "owner_id": u.Key(), "csrf_token": data.CSRF, "expires_at": v.ExpiresAt})
	case r.URL.Path == "/auth/logout" && r.Method == http.MethodPost:
		h.logout(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/") && r.Header.Get("Authorization") == "":
		_, _, data, err := h.authenticate(r)
		if err != nil {
			reject(w, 401, "browser login expired; sign in again")
			return
		}
		if !h.csrf(r, data.CSRF) {
			reject(w, 403, "same-origin request and CSRF token required")
			return
		}
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		clone.Header.Set("Authorization", "Bearer "+data.Token.AccessToken)
		clone.Header.Del("Cookie")
		h.next.ServeHTTP(w, clone)
	default:
		h.next.ServeHTTP(w, r)
	}
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	state, err := random()
	if err != nil {
		reject(w, 503, "login unavailable")
		return
	}
	browser, err := random()
	if err != nil {
		reject(w, 503, "login unavailable")
		return
	}
	nonce, err := random()
	if err != nil {
		reject(w, 503, "login unavailable")
		return
	}
	verifier := oauth2.GenerateVerifier()
	raw, _ := json.Marshal(pending{Verifier: verifier, Nonce: nonce})
	id := digest(state)
	encrypted, err := h.vault.Seal("web-login:"+id, raw)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err == nil {
		err = h.store.SaveWebLogin(ctx, id, digest(browser), encrypted)
	}
	if err != nil {
		reject(w, 503, "login state unavailable")
		return
	}
	cookie(w, loginCookie, browser, time.Now().Add(10*time.Minute))
	http.Redirect(w, r, h.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)), http.StatusFound)
}

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	q := r.URL.Query()
	c, err := r.Cookie(loginCookie)
	if err != nil || len(q["state"]) != 1 || len(q["code"]) != 1 || q.Get("state") == "" || q.Get("code") == "" || q.Get("error") != "" {
		reject(w, 400, "invalid authorization response; start login again")
		return
	}
	id := digest(q.Get("state"))
	encrypted, err := h.store.ConsumeWebLogin(ctx, id, digest(c.Value))
	if err != nil {
		reject(w, 400, "invalid, expired, or already used login state")
		return
	}
	cookie(w, loginCookie, "", time.Time{})
	raw, err := h.vault.Open("web-login:"+id, encrypted)
	var attempt pending
	if err != nil || json.Unmarshal(raw, &attempt) != nil {
		reject(w, 400, "invalid login state")
		return
	}
	token, err := h.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(attempt.Verifier))
	if err != nil {
		reject(w, 401, "SSO exchange failed; sign in again")
		return
	}
	rawID, _ := token.Extra("id_token").(string)
	idToken, err := h.idVerifier.Verify(ctx, rawID)
	if err != nil || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(attempt.Nonce)) != 1 {
		reject(w, 401, "SSO identity or nonce validation failed")
		return
	}
	if idToken.AccessTokenHash != "" && idToken.VerifyAccessToken(token.AccessToken) != nil {
		reject(w, 401, "SSO token binding failed")
		return
	}
	u, err := h.verifier.Verify(ctx, token.AccessToken)
	if err != nil || u.Issuer != idToken.Issuer || u.Subject != idToken.Subject || u.TokenExpiresAt.IsZero() || !u.TokenExpiresAt.After(time.Now()) {
		reject(w, 403, "SSO user is not approved for this application")
		return
	}
	if token.Expiry.IsZero() || token.Expiry.After(u.TokenExpiresAt) {
		token.Expiry = u.TokenExpiresAt
	}
	secret, err := random()
	if err != nil {
		reject(w, 503, "session unavailable")
		return
	}
	csrf, err := random()
	if err != nil {
		reject(w, 503, "session unavailable")
		return
	}
	sid := digest(secret)
	raw, _ = json.Marshal(credentials{Token: token, CSRF: csrf})
	encrypted, err = h.vault.Seal("web-session:"+sid, raw)
	expiry := time.Now().UTC().Add(h.config.SessionTTL)
	if err == nil {
		err = h.store.CreateWebSession(ctx, store.WebSession{ID: sid, Owner: u.Key(), Ciphertext: encrypted, ExpiresAt: expiry})
	}
	if err == nil {
		err = h.store.Audit(ctx, u.Key(), "browser_login", sid, "browser SSO code flow completed; credentials encrypted server-side")
	}
	if err != nil {
		_ = h.store.DeleteWebSession(ctx, sid)
		reject(w, 503, "session persistence unavailable")
		return
	}
	cookie(w, sessionCookie, secret, expiry)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) authenticate(r *http.Request) (store.WebSession, model.Identity, credentials, error) {
	var v store.WebSession
	var u model.Identity
	var data credentials
	c, err := r.Cookie(sessionCookie)
	if err != nil || len(c.Value) != 43 {
		return v, u, data, errors.New("missing browser session")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	id := digest(c.Value)
	for {
		v, err = h.store.WebSession(ctx, id)
		if err != nil {
			return v, u, data, err
		}
		raw, err := h.vault.Open("web-session:"+id, v.Ciphertext)
		if err != nil || json.Unmarshal(raw, &data) != nil || data.Token == nil || data.CSRF == "" {
			return v, u, data, errors.New("invalid encrypted session")
		}
		if data.Token.AccessToken != "" && data.Token.Expiry.After(time.Now().Add(30*time.Second)) {
			break
		}
		if data.Token.RefreshToken == "" {
			return v, u, data, errors.New("browser login expired")
		}
		lease, err := random()
		if err != nil {
			return v, u, data, err
		}
		claimed, err := h.store.ClaimWebRefresh(ctx, id, v.Version, lease)
		if err != nil {
			return v, u, data, err
		}
		if !claimed {
			select {
			case <-ctx.Done():
				return v, u, data, ctx.Err()
			case <-time.After(50 * time.Millisecond):
				continue
			}
		}
		old := *data.Token
		old.Expiry = time.Now().Add(-time.Minute)
		fresh, err := h.oauth.TokenSource(ctx, &old).Token()
		if err != nil {
			_ = h.store.DeleteWebSession(ctx, id)
			return v, u, data, errors.New("SSO refresh failed")
		}
		current, err := h.verifier.Verify(ctx, fresh.AccessToken)
		if err != nil || current.Key() != v.Owner || current.TokenExpiresAt.IsZero() || !current.TokenExpiresAt.After(time.Now()) {
			_ = h.store.DeleteWebSession(ctx, id)
			return v, u, data, errors.New("refreshed identity is no longer approved")
		}
		if fresh.Expiry.IsZero() || fresh.Expiry.After(current.TokenExpiresAt) {
			fresh.Expiry = current.TokenExpiresAt
		}
		data.Token = fresh
		raw, _ = json.Marshal(data)
		encrypted, err := h.vault.Seal("web-session:"+id, raw)
		if err != nil {
			return v, u, data, err
		}
		saved, err := h.store.CompleteWebRefresh(ctx, id, lease, encrypted)
		if err != nil || !saved {
			return v, u, data, errors.New("refresh persistence failed")
		}
		break
	}
	u, err = h.verifier.Verify(ctx, data.Token.AccessToken)
	if err != nil || u.Key() != v.Owner {
		return v, u, data, errors.New("invalid browser identity")
	}
	return v, u, data, nil
}

func (h *Handler) csrf(r *http.Request, expected string) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	return r.Header.Get("Origin") == h.config.PublicURL && r.Header.Get("Sec-Fetch-Site") != "cross-site" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(expected)) == 1
}

func (h *Handler) revoke(ctx context.Context, token *oauth2.Token) {
	if h.revocationURL == "" || token == nil || token.RefreshToken == "" {
		return
	}
	values := url.Values{"token": {token.RefreshToken}, "token_type_hint": {"refresh_token"}, "client_id": {h.oauth.ClientID}}
	if h.oauth.ClientSecret != "" {
		values.Set("client_secret", h.oauth.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.revocationURL, strings.NewReader(values.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	v, u, data, err := h.authenticate(r)
	if err != nil {
		cookie(w, sessionCookie, "", time.Time{})
		reject(w, 401, "browser session expired; sign in to manage remaining bookings")
		return
	}
	if !h.csrf(r, data.CSRF) {
		reject(w, 403, "same-origin request and CSRF token required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	releaseErr := h.store.Logout(ctx, u)
	deleteErr := h.store.DeleteWebSession(ctx, v.ID)
	h.revoke(ctx, data.Token)
	cookie(w, sessionCookie, "", time.Time{})
	if releaseErr != nil || deleteErr != nil {
		reject(w, 503, "browser signed out, but booking release or session revocation failed; sign in again to verify")
		return
	}
	jsonReply(w, 200, map[string]string{"status": "signed out; your bookings released and PATs revoked; workloads retained"})
}
