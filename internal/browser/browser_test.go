package browser

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/api"
	"devctl.local/devctl/internal/auth"
	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
	jose "github.com/go-jose/go-jose/v4"
)

// This local issuer signs real JWTs, enforces the PKCE verifier, and consumes
// refresh tokens once. Browser tests still use the production OIDC verifier and
// PostgreSQL persistence, rather than a fake authenticated identity.
type browserIssuer struct {
	server       *httptest.Server
	signer       jose.Signer
	mu           sync.Mutex
	codes        map[string]browserCode
	refresh      map[string]string
	serial       atomic.Int64
	refreshCount atomic.Int64
	revokeCount  atomic.Int64
	unapproved   atomic.Bool
}

type browserCode struct {
	challenge, nonce, subject, idSubject, audience string
}

func newBrowserIssuer(t *testing.T) *browserIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "browser-test"))
	if err != nil {
		t.Fatal(err)
	}
	f := &browserIssuer{signer: signer, codes: map[string]browserCode{}, refresh: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeBrowserJSON(w, map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/keys", "revocation_endpoint": f.server.URL + "/revoke", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		writeBrowserJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "browser-test", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("POST /token", f.exchange)
	mux.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		delete(f.refresh, r.Form.Get("token"))
		f.mu.Unlock()
		f.revokeCount.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func writeBrowserJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *browserIssuer) signed(claims map[string]any) string {
	raw, _ := json.Marshal(claims)
	signed, err := f.signer.Sign(raw)
	if err != nil {
		panic(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return compact
}

func (f *browserIssuer) exchange(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.Form.Get("client_id") != "devctl-web" {
		http.Error(w, "invalid client", http.StatusBadRequest)
		return
	}
	var code browserCode
	f.mu.Lock()
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		var ok bool
		code, ok = f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code"))
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != code.challenge || r.Form.Get("redirect_uri") != "https://gateway.example.test/auth/callback" {
			f.mu.Unlock()
			http.Error(w, "invalid code or PKCE verifier", http.StatusBadRequest)
			return
		}
	case "refresh_token":
		subject, ok := f.refresh[r.Form.Get("refresh_token")]
		delete(f.refresh, r.Form.Get("refresh_token"))
		if !ok {
			f.mu.Unlock()
			http.Error(w, "refresh replay", http.StatusBadRequest)
			return
		}
		code.subject = subject
		f.refreshCount.Add(1)
	default:
		f.mu.Unlock()
		http.Error(w, "unsupported grant", http.StatusBadRequest)
		return
	}
	serial := f.serial.Add(1)
	refresh := fmt.Sprintf("rotating-refresh-%d", serial)
	f.refresh[refresh] = code.subject
	f.mu.Unlock()
	groups := []string{"/developers"}
	if f.unapproved.Load() {
		groups = nil
	}
	access := f.signed(map[string]any{"iss": f.server.URL, "sub": code.subject, "aud": "devctl-api", "exp": time.Now().Add(10 * time.Minute).Unix(), "iat": time.Now().Unix(), "typ": "Bearer", "groups": groups, "preferred_username": code.subject, "name": "Alice Developer", "email": "alice@example.test", "jti": fmt.Sprint(serial)})
	response := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 600, "refresh_token": refresh}
	if code.nonce != "" {
		response["id_token"] = f.signed(map[string]any{"iss": f.server.URL, "sub": code.idSubject, "aud": code.audience, "exp": time.Now().Add(10 * time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": code.nonce})
	}
	writeBrowserJSON(w, response)
}

type browserTest struct {
	t        *testing.T
	issuer   *browserIssuer
	db       *store.Store
	dsn      string
	vault    *kube.Vault
	verifier *auth.Verifier
	h        *Handler
}

func newBrowserTest(t *testing.T) *browserTest {
	t.Helper()
	db, dsn := testutil.Database(t)
	issuer := newBrowserIssuer(t)
	verifier, err := auth.New(t.Context(), auth.DefaultConfig(issuer.server.URL))
	if err != nil {
		t.Fatal(err)
	}
	vault, err := kube.NewVault(bytes.Repeat([]byte{87}, 32))
	if err != nil {
		t.Fatal(err)
	}
	b := &browserTest{t: t, issuer: issuer, db: db, dsn: dsn, vault: vault, verifier: verifier}
	b.h = b.handler(db)
	return b
}

func (b *browserTest) handler(db *store.Store) *Handler {
	b.t.Helper()
	core := (&api.Server{Store: db, Auth: b.verifier, Vault: b.vault, PublicURL: "https://gateway.example.test"}).Handler()
	h, err := New(Config{PublicURL: "https://gateway.example.test", ClientID: "devctl-web"}, b.verifier, db, b.vault, core)
	if err != nil {
		b.t.Fatal(err)
	}
	return h
}

type browserAttempt struct {
	state, code string
	cookie      *http.Cookie
}

func (b *browserTest) attempt(change func(*browserCode)) browserAttempt {
	b.t.Helper()
	r := httptest.NewRequest("GET", "https://gateway.example.test/auth/login", nil)
	w := httptest.NewRecorder()
	b.h.ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		b.t.Fatalf("login initialization returned %d", w.Code)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		b.t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("state") == "" || q.Get("redirect_uri") != "https://gateway.example.test/auth/callback" {
		b.t.Fatal("missing browser PKCE/state/nonce or unapproved callback")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		b.t.Fatal("missing login cookie")
	}
	checkBrowserCookie(b.t, cookies[0], loginCookie)
	code := fmt.Sprintf("authorization-code-%d", b.issuer.serial.Add(1))
	claims := browserCode{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), subject: "alice", idSubject: "alice", audience: "devctl-web"}
	if change != nil {
		change(&claims)
	}
	b.issuer.mu.Lock()
	b.issuer.codes[code] = claims
	b.issuer.mu.Unlock()
	return browserAttempt{state: q.Get("state"), code: code, cookie: cookies[0]}
}

func checkBrowserCookie(t *testing.T, c *http.Cookie, name string) {
	t.Helper()
	if c.Name != name || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" || len(c.Value) != 43 || c.MaxAge <= 0 {
		t.Fatal("browser cookie missing security attributes")
	}
}

func (b *browserTest) callback(a browserAttempt) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "https://gateway.example.test/auth/callback?"+url.Values{"state": {a.state}, "code": {a.code}}.Encode(), nil)
	r.AddCookie(a.cookie)
	w := httptest.NewRecorder()
	b.h.ServeHTTP(w, r)
	return w
}

func (b *browserTest) login() *http.Cookie {
	b.t.Helper()
	w := b.callback(b.attempt(nil))
	if w.Code != http.StatusSeeOther {
		b.t.Fatalf("browser callback returned %d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			checkBrowserCookie(b.t, c, sessionCookie)
			return c
		}
	}
	b.t.Fatal("no browser session cookie")
	return nil
}

func browserCall(h http.Handler, c *http.Cookie, method, path, body, csrf, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://gateway.example.test"+path, strings.NewReader(body))
	if c != nil {
		r.AddCookie(c)
	}
	r.Header.Set("Origin", origin)
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "browser-unit-booking")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestBrowserStatePKCENonceAndCookieBinding(t *testing.T) {
	b := newBrowserTest(t)
	a := b.attempt(nil)
	wrong := a
	wrong.state = "forged"
	if w := b.callback(wrong); w.Code != 400 {
		t.Fatal("forged state accepted")
	}
	wrong = a
	wrong.cookie = &http.Cookie{Name: loginCookie, Value: strings.Repeat("x", 43)}
	if w := b.callback(wrong); w.Code != 400 {
		t.Fatal("other browser's callback accepted")
	}
	if w := b.callback(a); w.Code != 303 {
		t.Fatal("forgery consumed legitimate state", w.Code)
	}
	if w := b.callback(a); w.Code != 400 {
		t.Fatal("replayed authorization response accepted")
	}
	for _, tt := range []struct {
		name   string
		change func(*browserCode)
		status int
	}{
		{"wrong nonce", func(c *browserCode) { c.nonce = "wrong" }, 401},
		{"wrong PKCE", func(c *browserCode) { c.challenge = "wrong" }, 401},
		{"wrong ID audience", func(c *browserCode) { c.audience = "another-client" }, 401},
		{"subject mismatch", func(c *browserCode) { c.idSubject = "bob" }, 403},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if w := b.callback(b.attempt(tt.change)); w.Code != tt.status {
				t.Fatalf("got %d want %d", w.Code, tt.status)
			}
		})
	}
	b.issuer.unapproved.Store(true)
	if w := b.callback(b.attempt(nil)); w.Code != 403 {
		t.Fatal("unapproved browser user accepted", w.Code)
	}
}

func TestBrowserCookieAPIAndLogout(t *testing.T) {
	b := newBrowserTest(t)
	c := b.login()
	w := browserCall(b.h, c, "GET", "/web/session", "", "", "")
	if w.Code != 200 {
		t.Fatal("browser session missing", w.Code)
	}
	var metadata struct {
		User  model.Identity `json:"user"`
		Owner string         `json:"owner_id"`
		CSRF  string         `json:"csrf_token"`
	}
	if json.Unmarshal(w.Body.Bytes(), &metadata) != nil || metadata.User.Name != "alice" || metadata.Owner != metadata.User.Key() || metadata.CSRF == "" {
		t.Fatal("invalid public browser metadata")
	}
	stored, err := b.db.WebSession(t.Context(), digest(c.Value))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.vault.Open("web-session:"+stored.ID, stored.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	var sensitive credentials
	if json.Unmarshal(raw, &sensitive) != nil || sensitive.Token == nil {
		t.Fatal("encrypted session missing OAuth credentials")
	}
	for _, secret := range []string{sensitive.Token.AccessToken, sensitive.Token.RefreshToken, c.Value} {
		if bytes.Contains(stored.Ciphertext, []byte(secret)) || strings.Contains(w.Body.String(), secret) {
			t.Fatal("browser secret exposed in API metadata or plaintext persistence")
		}
	}
	if stored.ID == c.Value || stored.Owner != metadata.Owner {
		t.Fatal("cookie was stored directly or identity mapping lost")
	}
	admin := model.Identity{Issuer: b.issuer.server.URL, Subject: "admin", Admin: true}
	if err = b.db.Register(t.Context(), admin, model.Cluster{ID: "browser-test", Name: "Browser test", MaxParticipants: 2, Labels: map[string]string{}}, []byte("encrypted-placeholder")); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ name, csrf, origin string }{
		{"missing CSRF", "", "https://gateway.example.test"},
		{"wrong CSRF", "forged", "https://gateway.example.test"},
		{"missing Origin", metadata.CSRF, ""},
		{"cross Origin", metadata.CSRF, "https://other.example.test"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if w := browserCall(b.h, c, "POST", "/v1/sessions", `{"cluster":"browser-test"}`, tt.csrf, tt.origin); w.Code != 403 {
				t.Fatal("unsafe cookie mutation accepted", w.Code)
			}
		})
	}
	if w := browserCall(b.h, c, "GET", "/v1/admin/audit", "", "", ""); w.Code != 403 {
		t.Fatal("developer cookie gained administrator access", w.Code)
	}
	w = browserCall(b.h, c, "POST", "/v1/sessions", `{"cluster":"browser-test"}`, metadata.CSRF, "https://gateway.example.test")
	if w.Code != 201 {
		t.Fatal("valid browser booking failed", w.Code)
	}
	var booking model.Session
	if json.Unmarshal(w.Body.Bytes(), &booking) != nil {
		t.Fatal("invalid booking response")
	}
	_, secret, err := b.db.CreatePAT(t.Context(), metadata.User, booking.ID, "browser test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "https://gateway.example.test/v1/admin/audit", nil)
	r.AddCookie(c)
	r.Header.Set("Authorization", "Bearer "+secret)
	w = httptest.NewRecorder()
	b.h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("PAT became an admin/control credential through browser-cookie fallback", w.Code)
	}
	if w := browserCall(b.h, c, "POST", "/auth/logout", "", metadata.CSRF, "https://evil.example.test"); w.Code != 403 {
		t.Fatal("cross-origin logout accepted", w.Code)
	}
	if w := browserCall(b.h, c, "POST", "/auth/logout", "", metadata.CSRF, "https://gateway.example.test"); w.Code != 200 {
		t.Fatal("browser logout failed", w.Code)
	}
	if b.issuer.revokeCount.Load() != 1 {
		t.Fatal("provider refresh-token revocation not attempted")
	}
	if err = b.db.Access(t.Context(), metadata.User, booking.ID); err == nil {
		t.Fatal("logout retained booking access")
	}
	if _, err = b.db.VerifyPAT(t.Context(), secret, booking.ID); err == nil {
		t.Fatal("logout retained PAT access")
	}
	if w := browserCall(b.h, c, "GET", "/web/session", "", "", ""); w.Code != 401 {
		t.Fatal("logged-out cookie still valid")
	}
}

func (b *browserTest) expireAccess(c *http.Cookie) credentials {
	b.t.Helper()
	id := digest(c.Value)
	v, err := b.db.WebSession(b.t.Context(), id)
	if err != nil {
		b.t.Fatal(err)
	}
	raw, err := b.vault.Open("web-session:"+id, v.Ciphertext)
	if err != nil {
		b.t.Fatal(err)
	}
	var data credentials
	if json.Unmarshal(raw, &data) != nil || data.Token == nil {
		b.t.Fatal("invalid persisted credentials")
	}
	old := data
	copy := *data.Token
	data.Token = &copy
	data.Token.Expiry = time.Now().Add(-time.Hour)
	raw, _ = json.Marshal(data)
	encrypted, err := b.vault.Seal("web-session:"+id, raw)
	if err != nil {
		b.t.Fatal(err)
	}
	if _, err = b.db.Pool.Exec(b.t.Context(), "UPDATE web_sessions SET payload_ciphertext=$2 WHERE id_hash=$1", id, encrypted); err != nil {
		b.t.Fatal(err)
	}
	return old
}

func TestBrowserConcurrentRotatingRefreshAndRestart(t *testing.T) {
	b := newBrowserTest(t)
	c := b.login()
	restarted, err := store.Open(t.Context(), b.dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Pool.Close)
	other := b.handler(restarted)
	if w := browserCall(other, c, "GET", "/web/session", "", "", ""); w.Code != 200 {
		t.Fatal("new backend instance lost browser session", w.Code)
	}
	old := b.expireAccess(c)
	var wg sync.WaitGroup
	results := make(chan int, 20)
	for i := range 20 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h := b.h
			if i%2 != 0 {
				h = other
			}
			results <- browserCall(h, c, "GET", "/web/session", "", "", "").Code
		}(i)
	}
	wg.Wait()
	close(results)
	for code := range results {
		if code != 200 {
			t.Fatal("concurrent refresh failed or used a consumed refresh token", code)
		}
	}
	if got := b.issuer.refreshCount.Load(); got != 1 {
		t.Fatalf("rotating refresh grant was used %d times instead of once", got)
	}
	v, err := b.db.WebSession(t.Context(), digest(c.Value))
	if err != nil || v.Version != 2 {
		t.Fatal("fresh credentials not committed exactly once", err)
	}
	raw, err := b.vault.Open("web-session:"+v.ID, v.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	var fresh credentials
	if json.Unmarshal(raw, &fresh) != nil || fresh.Token == nil || fresh.Token.AccessToken == old.Token.AccessToken || fresh.Token.RefreshToken == old.Token.RefreshToken {
		t.Fatal("new access/refresh token pair not persisted")
	}
	_ = b.expireAccess(c)
	if w := browserCall(other, c, "GET", "/web/session", "", "", ""); w.Code != 200 || b.issuer.refreshCount.Load() != 2 {
		t.Fatal("persisted rotated refresh token cannot be reused by another backend", w.Code)
	}
	_ = b.expireAccess(c)
	b.issuer.unapproved.Store(true)
	if w := browserCall(b.h, c, "GET", "/web/session", "", "", ""); w.Code != 401 {
		t.Fatal("removed group survived a fresh access token", w.Code)
	}
	if _, err = b.db.WebSession(context.Background(), digest(c.Value)); err == nil {
		t.Fatal("failed identity refresh retained a usable browser session")
	}
}

func TestBrowserAbsoluteExpiryAndStatePruning(t *testing.T) {
	b := newBrowserTest(t)
	c := b.login()
	_ = b.attempt(nil)
	if _, err := b.db.Pool.Exec(t.Context(), "UPDATE web_sessions SET expires_at=clock_timestamp()-interval '1 second'; UPDATE web_login_attempts SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if w := browserCall(b.h, c, "GET", "/web/session", "", "", ""); w.Code != 401 {
		t.Fatal("absolute browser expiry was not enforced", w.Code)
	}
	if err := b.db.PruneWebSessions(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := b.db.Pool.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM web_sessions)+(SELECT count(*) FROM web_login_attempts)").Scan(&count); err != nil || count != 0 {
		t.Fatal("expired browser state was not pruned", count, err)
	}
}
