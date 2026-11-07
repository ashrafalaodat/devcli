package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"devctl.local/devctl/internal/auth"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofrs/flock"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type loginStore struct {
	Dir, Account string
	Config       auth.Config
	DevFile      bool
}

func newLoginStore(api string, c auth.Config) (*loginStore, error) {
	root := os.Getenv("DEVCTL_CONFIG_DIR")
	if root == "" {
		d, e := os.UserConfigDir()
		if e != nil {
			return nil, e
		}
		root = filepath.Join(d, "devctl")
	}
	root, e := filepath.Abs(root)
	if e != nil {
		return nil, e
	}
	h := sha256.Sum256([]byte(api + "\x00" + c.Issuer + "\x00" + c.ClientID + "\x00" + root))
	account := hex.EncodeToString(h[:16])
	dir := filepath.Join(root, account)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode()&0077 != 0 {
		return nil, errors.New("devctl config directory must be a private directory (0700)")
	}
	if e = scrubLegacySessionConfigs(dir); e != nil {
		return nil, e
	}
	return &loginStore{dir, account, c, os.Getenv("DEVCTL_DEV_TOKEN_FILE") == "1"}, nil
}
func (s *loginStore) lock(ctx context.Context) (func(), error) {
	l := flock.New(filepath.Join(s.Dir, "auth.lock"))
	ok, e := l.TryLockContext(ctx, 50*time.Millisecond)
	if e != nil {
		return nil, e
	}
	if !ok {
		return nil, errors.New("cannot lock login credentials")
	}
	return func() { l.Unlock() }, nil
}
func (s *loginStore) read() (*oauth2.Token, error) {
	raw, e := keyring.Get("devctl", s.Account)
	if e != nil && s.DevFile {
		info, err := os.Lstat(filepath.Join(s.Dir, "tokens.json"))
		if err != nil {
			return nil, errors.New("run devctl login")
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("development token file must be a regular private file (0600)")
		}
		b, err := os.ReadFile(filepath.Join(s.Dir, "tokens.json"))
		if err != nil {
			return nil, err
		}
		raw = string(b)
		e = nil
	}
	if e != nil {
		return nil, errors.New("run devctl login (OS credential store unavailable or no login stored)")
	}
	var t oauth2.Token
	if e = json.Unmarshal([]byte(raw), &t); e != nil {
		return nil, errors.New("stored login invalid; run devctl login")
	}
	return &t, nil
}
func atomicPrivate(path string, raw []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".devctl-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(raw); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(name, path)
}
func (s *loginStore) save(t *oauth2.Token) error {
	raw, e := json.Marshal(t)
	if e != nil {
		return e
	}
	if e = keyring.Set("devctl", s.Account, string(raw)); e == nil {
		os.Remove(filepath.Join(s.Dir, "tokens.json"))
		return nil
	}
	if !s.DevFile {
		return errors.New("OS credential store unavailable; configure one, or explicitly enable DEVCTL_DEV_TOKEN_FILE=1 for development")
	}
	return atomicPrivate(filepath.Join(s.Dir, "tokens.json"), raw)
}
func (s *loginStore) clear() error {
	e := keyring.Delete("devctl", s.Account)
	fileErr := os.Remove(filepath.Join(s.Dir, "tokens.json"))
	if fileErr != nil && !os.IsNotExist(fileErr) {
		return fileErr
	}
	if e != nil && !errors.Is(e, keyring.ErrNotFound) && !s.DevFile {
		return errors.New("could not clear OS credential store")
	}
	return nil
}
func (s *loginStore) provider(ctx context.Context) (*oidc.Provider, *oauth2.Config, error) {
	p, e := oidc.NewProvider(ctx, s.Config.Issuer)
	if e != nil {
		return nil, nil, errors.New("OIDC discovery failed; check issuer and network")
	}
	endpoint := p.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	return p, &oauth2.Config{ClientID: s.Config.ClientID, Endpoint: endpoint, RedirectURL: s.Config.Redirect, Scopes: s.Config.Scopes}, nil
}
func (s *loginStore) token(ctx context.Context) (*oauth2.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	unlock, e := s.lock(ctx)
	if e != nil {
		return nil, e
	}
	defer unlock()
	old, e := s.read()
	if e != nil {
		return nil, e
	}
	if old.AccessToken != "" && !old.Expiry.IsZero() && old.Expiry.After(time.Now().Add(30*time.Second)) {
		return old, nil
	}
	if old.RefreshToken == "" {
		return nil, errors.New("login expired; run devctl login")
	}
	_, cfg, e := s.provider(ctx)
	if e != nil {
		return nil, e
	}
	t, e := cfg.TokenSource(ctx, old).Token()
	if e != nil {
		return nil, errors.New("login refresh failed; run devctl login")
	}
	if t.RefreshToken == "" {
		t.RefreshToken = old.RefreshToken
	}
	if e = s.save(t); e != nil {
		return nil, e
	}
	return t, nil
}
func randomString() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func (s *loginStore) login(ctx context.Context, out io.Writer) error {
	p, cfg, e := s.provider(ctx)
	if e != nil {
		return e
	}
	u, e := url.Parse(cfg.RedirectURL)
	if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != "/callback" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("approved redirect must be http://127.0.0.1:PORT/callback")
	}
	listener, e := net.Listen("tcp4", u.Host)
	if e != nil {
		return errors.New("cannot bind approved loopback callback; close other login attempts or configure approved port")
	}
	defer listener.Close()
	state, nonce, verifier := randomString(), randomString(), oauth2.GenerateVerifier()
	type result struct {
		code string
		err  error
	}
	ch := make(chan result, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain")
		q := r.URL.Query()
		if !equal(q.Get("state"), state) {
			http.Error(w, "invalid state", 400)
			return
		}
		if q.Get("error") != "" {
			select {
			case ch <- result{err: errors.New("identity provider declined login")}:
			default:
			}
			http.Error(w, "login declined", 400)
			return
		}
		if q.Get("code") == "" {
			http.Error(w, "missing authorization code", 400)
			return
		}
		select {
		case ch <- result{code: q.Get("code")}:
		default:
		}
		fmt.Fprintln(w, "Login callback received. Return to devctl to see the result.")
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(listener)
	defer srv.Close()
	authURL := cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("prompt", "login"))
	fmt.Fprintf(out, "Open this URL to log in:\n%s\n", authURL)
	if os.Getenv("DEVCTL_NO_BROWSER") != "1" {
		program, args := "xdg-open", []string{authURL}
		if runtime.GOOS == "darwin" {
			program = "open"
		}
		if runtime.GOOS == "windows" {
			program = "rundll32"
			args = []string{"url.dll,FileProtocolHandler", authURL}
		}
		cmd := exec.Command(program, args...)
		if e := cmd.Start(); e == nil {
			go cmd.Wait()
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return r.err
		}
		t, e := cfg.Exchange(ctx, r.code, oauth2.VerifierOption(verifier))
		if e != nil {
			var re *oauth2.RetrieveError
			if errors.As(e, &re) {
				return fmt.Errorf("authorization code exchange failed (HTTP %d, %s)", re.Response.StatusCode, re.ErrorCode)
			}
			return errors.New("authorization code exchange failed: token endpoint unavailable")
		}
		rawID, ok := t.Extra("id_token").(string)
		if !ok {
			return errors.New("provider did not return ID token")
		}
		id, e := p.Verifier(&oidc.Config{ClientID: s.Config.ClientID}).Verify(ctx, rawID)
		if e != nil || !equal(id.Nonce, nonce) {
			return errors.New("ID token validation or nonce failed")
		}
		if t.AccessToken == "" || t.Expiry.IsZero() {
			return errors.New("provider did not return an expiring API access token")
		}
		unlock, e := s.lock(ctx)
		if e != nil {
			return e
		}
		defer unlock()
		return s.save(t)
	}
}
func (s *loginStore) revoke(ctx context.Context, t *oauth2.Token) error {
	if t.RefreshToken == "" {
		return nil
	}
	p, _, e := s.provider(ctx)
	if e != nil {
		return e
	}
	var discovery struct {
		Revocation string `json:"revocation_endpoint"`
	}
	if e = p.Claims(&discovery); e != nil {
		return e
	}
	if discovery.Revocation == "" {
		return errors.New("provider does not advertise refresh-token revocation")
	}
	form := url.Values{"token": {t.RefreshToken}, "token_type_hint": {"refresh_token"}, "client_id": {s.Config.ClientID}}
	req, e := http.NewRequestWithContext(ctx, "POST", discovery.Revocation, strings.NewReader(form.Encode()))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		return errors.New("provider revocation unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return errors.New("provider rejected refresh-token revocation")
	}
	return nil
}
