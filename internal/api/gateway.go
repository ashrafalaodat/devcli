package api

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Connection contains public gateway metadata only. Upstream endpoints, user
// credentials and private keys are intentionally not represented in this type.
type Connection struct {
	Server                   string `json:"server"`
	CertificateAuthorityData string `json:"certificate_authority_data,omitempty"`
}

func ValidatePublicURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return errors.New("invalid DEVCTL_PUBLIC_URL")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("DEVCTL_PUBLIC_URL must be an origin without a path")
	}
	if u.Scheme == "https" {
		return nil
	}
	return errors.New("DEVCTL_PUBLIC_URL requires HTTPS; kubectl exec authentication is not enabled for HTTP servers")
}
func (s *Server) connection(w http.ResponseWriter, r *http.Request) {
	if e := s.Store.Access(r.Context(), user(r), r.PathValue("id")); e != nil {
		gatewayFailure(w, e)
		return
	}
	if ValidatePublicURL(s.PublicURL) != nil {
		fail(w, 503, "gateway public URL is not configured")
		return
	}
	if e := s.Store.Audit(r.Context(), user(r).Key(), "connection", r.PathValue("id"), "gateway metadata only; upstream credentials remain on server"); e != nil {
		fail(w, 503, "audit unavailable")
		return
	}
	write(w, 200, Connection{Server: strings.TrimSuffix(s.PublicURL, "/") + "/k8s/sessions/" + url.PathEscape(r.PathValue("id")), CertificateAuthorityData: base64.StdEncoding.EncodeToString(s.GatewayCAData)})
}
func gatewayFailure(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, store.ErrNotFound):
		fail(w, 404, "session not found")
	case errors.Is(e, store.ErrForbidden):
		fail(w, 403, "session belongs to another developer")
	case errors.Is(e, store.ErrConflict):
		fail(w, 409, "session is not active or its lease expired")
	default:
		fail(w, 503, "reservation state unavailable")
	}
}

var gatewaySessionID = regexp.MustCompile(`^s-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var gatewayAutomaticID = regexp.MustCompile(`^a-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func gatewayPath(u *url.URL) (string, string, error) {
	return parseGatewayPath(u, "/k8s/sessions/", gatewaySessionID)
}

func parseGatewayPath(u *url.URL, prefix string, validID *regexp.Regexp) (string, string, error) {
	escaped := u.EscapedPath()
	if !strings.HasPrefix(escaped, prefix) {
		return "", "", errors.New("invalid gateway path")
	}
	id, suffix, ok := strings.Cut(strings.TrimPrefix(escaped, prefix), "/")
	if !ok || !validID.MatchString(id) {
		return "", "", errors.New("invalid gateway session path")
	}
	suffix = "/" + suffix
	decoded, e := url.PathUnescape(suffix)
	if e != nil {
		return "", "", errors.New("invalid URL escape")
	}
	// Preserve ordinary encoded resource paths, while rejecting traversal into an
	// upstream kubeconfig's URL prefix (e.g. a pre-existing cluster gateway).
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return "", "", errors.New("path traversal is not allowed")
		}
	}
	lower := strings.ToLower(decoded)
	if strings.Contains(decoded, "\\") || strings.ContainsAny(decoded, "\x00\r\n") || strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return "", "", errors.New("ambiguous encoded path")
	}
	return id, suffix, nil
}
func (s *Server) gateway(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	id, suffix, e := gatewayPath(r.URL)
	binding := ""
	if strings.HasPrefix(r.URL.Path, "/k8s/auto/") {
		binding, suffix, e = parseGatewayPath(r.URL, "/k8s/auto/", gatewayAutomaticID)
	}
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
	default:
		fail(w, 405, "unsupported Kubernetes request method")
		return
	}
	rawToken, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || rawToken == "" {
		fail(w, 401, "devctl access token required")
		return
	}
	setup, cancelSetup := context.WithTimeout(r.Context(), 20*time.Second)
	var u model.Identity
	personal := strings.HasPrefix(rawToken, "dcpat_")
	if personal {
		// PATs authenticate only their exact session route. They cannot allocate
		// a booking, authenticate a control API or use an automatic binding.
		if binding != "" {
			cancelSetup()
			fail(w, http.StatusUnauthorized, "personal credentials require their recorded session gateway")
			return
		}
		u, e = s.Store.VerifyPAT(setup, rawToken, id)
	} else {
		u, e = s.Auth.Verify(setup, rawToken)
	}
	if e != nil {
		cancelSetup()
		fail(w, 401, "invalid devctl access token or user not approved")
		return
	}
	if binding != "" {
		if u.TokenExpiresAt.IsZero() || !u.TokenExpiresAt.After(time.Now()) {
			cancelSetup()
			fail(w, http.StatusUnauthorized, "automatic gateway requires an unexpired access token")
			return
		}
		id, e = s.Store.AutomaticSession(setup, u, binding)
		if e != nil {
			cancelSetup()
			gatewayFailure(w, e)
			return
		}
	}
	cluster, ciphertext, e := s.Store.Config(setup, u, id)
	if e != nil {
		cancelSetup()
		gatewayFailure(w, e)
		return
	}
	if e = s.Store.TouchActivity(setup, u, id); e != nil {
		cancelSetup()
		fail(w, http.StatusServiceUnavailable, "activity state unavailable")
		return
	}
	raw, e := s.Vault.Open(cluster, ciphertext)
	if e != nil {
		cancelSetup()
		fail(w, 503, "upstream credentials unavailable")
		return
	}
	if e = kube.Validate(raw); e != nil {
		cancelSetup()
		fail(w, 503, "stored cluster configuration is unsupported")
		return
	}
	cfg, e := clientcmd.RESTConfigFromKubeConfig(raw)
	if e != nil {
		cancelSetup()
		fail(w, 503, "upstream configuration unavailable")
		return
	}
	// TransportFor uses the original server-held token or client certificate, with
	// normal CA verification. Proxying never runs an uploaded executable plugin.
	// HTTP/1.1 is required by Kubernetes WebSocket and SPDY upgrade transports.
	cfg.NextProtos = []string{"http/1.1"}
	transport, e := rest.TransportFor(cfg)
	if e != nil {
		cancelSetup()
		fail(w, 503, "upstream TLS configuration unavailable")
		return
	}
	target, e := url.Parse(cfg.Host)
	if e != nil || target.Scheme != "https" {
		cancelSetup()
		fail(w, 503, "invalid upstream endpoint")
		return
	}
	cancelSetup()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if personal {
		go s.monitorPAT(ctx, cancel, u, rawToken, id)
	} else if binding == "" {
		go s.monitor(ctx, cancel, u, rawToken, id)
	} else {
		go s.monitorAutomatic(ctx, cancel, u, binding, id)
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			decoded, _ := url.PathUnescape(suffix)
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path = strings.TrimSuffix(target.Path, "/") + decoded
			pr.Out.URL.RawPath = strings.TrimSuffix(target.EscapedPath(), "/") + suffix
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			pr.Out.Host = target.Host
			stripGatewayHeaders(pr.Out.Header)
		},
		Transport:     transport,
		FlushInterval: -1,
		ErrorLog:      log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
			if r.Context().Err() == nil {
				fail(w, 502, "Kubernetes upstream unavailable")
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Header.Get("Location") != "" {
				return errors.New("upstream redirects are not forwarded")
			}
			resp.Header.Set("Cache-Control", "no-store")
			resp.Header.Del("Set-Cookie")
			resp.Header.Del("Authorization")
			resp.Header.Del("Proxy-Authenticate")
			return nil
		},
	}
	proxy.ServeHTTP(w, r.WithContext(ctx))
}
func stripGatewayHeaders(h http.Header) {
	for k := range h {
		lower := strings.ToLower(k)
		if lower == "authorization" || lower == "proxy-authorization" || lower == "cookie" || lower == "forwarded" || lower == "x-real-ip" || strings.HasPrefix(lower, "impersonate-") || strings.HasPrefix(lower, "x-remote-") || strings.HasPrefix(lower, "x-forwarded-") {
			h.Del(k)
		}
	}
	// Kubernetes also recognizes bearer credentials encoded in a WebSocket
	// subprotocol. Strip those, preserving channel/SPDY negotiation headers.
	protocols := []string{}
	for _, line := range h.Values("Sec-Websocket-Protocol") {
		for _, protocol := range strings.Split(line, ",") {
			protocol = strings.TrimSpace(protocol)
			if !strings.HasPrefix(strings.ToLower(protocol), "base64url.bearer.authorization.k8s.io.") {
				protocols = append(protocols, protocol)
			}
		}
	}
	if len(protocols) > 0 {
		h.Set("Sec-Websocket-Protocol", strings.Join(protocols, ", "))
	} else {
		h.Del("Sec-Websocket-Protocol")
	}
}

// Each stream periodically rechecks both access-token validity and the committed
// booking. Failure, expiry, release, logout or a DB outage closes both directions.
func (s *Server) monitor(ctx context.Context, cancel context.CancelFunc, u model.Identity, token, id string) {
	interval := s.GatewayRecheckInterval
	if interval <= 0 {
		interval = time.Second
	}
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			check, done := context.WithTimeout(ctx, 5*time.Second)
			current, e := s.Auth.Verify(check, token)
			if e == nil && current.Key() != u.Key() {
				e = errors.New("identity changed")
			}
			if e == nil {
				e = s.Store.Access(check, u, id)
			}
			if e == nil {
				e = s.Store.TouchActivity(check, u, id)
			}
			done()
			if e != nil {
				cancel()
				return
			}
		}
	}
}

// Automatic streams use a server-side authorization lease. A separate request
// with a fresh, fully validated JWT may renew that exact binding while active;
// an expired bearer on a new request is still always rejected above.
func (s *Server) monitorAutomatic(ctx context.Context, cancel context.CancelFunc, u model.Identity, binding, id string) {
	interval := s.GatewayRecheckInterval
	if interval <= 0 {
		interval = time.Second
	}
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			check, done := context.WithTimeout(ctx, 5*time.Second)
			err := s.Store.CheckAutomaticAccess(check, u, binding, id)
			if err == nil {
				err = s.Store.TouchActivity(check, u, id)
			}
			done()
			if err != nil {
				cancel()
				return
			}
		}
	}
}

// Personal credentials are rechecked against durable revocation and session
// state throughout ordinary streams and duplex exec/port-forward connections.
func (s *Server) monitorPAT(ctx context.Context, cancel context.CancelFunc, u model.Identity, token, id string) {
	interval := s.GatewayRecheckInterval
	if interval <= 0 {
		interval = time.Second
	}
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			check, done := context.WithTimeout(ctx, 5*time.Second)
			current, err := s.Store.VerifyPAT(check, token, id)
			if err == nil && current.Key() != u.Key() {
				err = errors.New("identity changed")
			}
			if err == nil {
				err = s.Store.TouchActivity(check, u, id)
			}
			done()
			if err != nil {
				cancel()
				return
			}
		}
	}
}
