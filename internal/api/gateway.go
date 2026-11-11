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
	"strings"
	"time"

	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

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
	if u.Scheme != "https" {
		return errors.New("DEVCTL_PUBLIC_URL requires HTTPS")
	}
	return nil
}
func (s *Server) connection(w http.ResponseWriter, r *http.Request) {
	if ValidatePublicURL(s.PublicURL) != nil {
		fail(w, 503, "gateway public URL is not configured")
		return
	}
	if e := s.Store.Audit(r.Context(), user(r).Key(), "connection", user(r).Key(), "stable developer gateway metadata; no reservation created"); e != nil {
		fail(w, 503, "audit unavailable")
		return
	}
	write(w, 200, Connection{Server: strings.TrimSuffix(s.PublicURL, "/") + "/k8s", CertificateAuthorityData: base64.StdEncoding.EncodeToString(s.GatewayCAData)})
}
func gatewayStatus(w http.ResponseWriter, code int, reason, message string) {
	write(w, code, map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Failure", "reason": reason, "message": message, "code": code})
}
func gatewayFailure(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, store.ErrNoPrimary):
		// kubectl discovery and --raw use client-go.DoRaw, which discards a
		// JSON Status body on errors. Forbidden text preserves the actionable
		// reservation error in both raw and typed Kubernetes clients.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "no cluster is booked; book a cluster in the web UI or with devctl start\n")
	case errors.Is(e, store.ErrNotFound):
		gatewayStatus(w, 404, "NotFound", "primary booking was not found")
	case errors.Is(e, store.ErrForbidden):
		gatewayStatus(w, 403, "Forbidden", "access is not permitted for this developer")
	case errors.Is(e, store.ErrConflict):
		gatewayStatus(w, 409, "Conflict", "primary selection changed or booking ended; retry the command")
	default:
		gatewayStatus(w, 503, "ServiceUnavailable", "reservation state unavailable")
	}
}

// The single public gateway never includes a booking/user identifier. Routing
// comes exclusively from authenticated identity and committed primary state.
func gatewayPath(u *url.URL) (string, error) {
	escaped := u.EscapedPath()
	suffix := "/"
	if escaped != "/k8s" {
		if !strings.HasPrefix(escaped, "/k8s/") {
			return "", errors.New("invalid gateway path")
		}
		suffix = strings.TrimPrefix(escaped, "/k8s")
	}
	decoded, e := url.PathUnescape(suffix)
	if e != nil {
		return "", errors.New("invalid URL escape")
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return "", errors.New("path traversal is not allowed")
		}
	}
	lower := strings.ToLower(decoded)
	if strings.Contains(decoded, "\\") || strings.ContainsAny(decoded, "\x00\r\n") || strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return "", errors.New("ambiguous encoded path")
	}
	return suffix, nil
}
func (s *Server) gateway(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	suffix, e := gatewayPath(r.URL)
	if e != nil {
		gatewayStatus(w, 400, "BadRequest", e.Error())
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
	default:
		gatewayStatus(w, 405, "MethodNotAllowed", "unsupported Kubernetes request method")
		return
	}
	rawToken, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || rawToken == "" {
		gatewayStatus(w, 401, "Unauthorized", "devctl access token or PAT required")
		return
	}
	setup, cancelSetup := context.WithTimeout(r.Context(), 20*time.Second)
	var u model.Identity
	personal := strings.HasPrefix(rawToken, "dcpat_")
	if personal {
		u, e = s.Store.VerifyPAT(setup, rawToken)
	} else {
		u, e = s.Auth.Verify(setup, rawToken)
	}
	if e != nil || !personal && (u.TokenExpiresAt.IsZero() || !u.TokenExpiresAt.After(time.Now())) {
		cancelSetup()
		gatewayStatus(w, 401, "Unauthorized", "invalid or expired credential; sign in or replace the PAT")
		return
	}
	session, version, cluster, ciphertext, e := s.Store.PrimaryConfig(setup, u)
	if e != nil {
		cancelSetup()
		gatewayFailure(w, e)
		return
	}
	if !personal {
		authorized, err := s.Store.AuthorizePrimary(setup, u)
		if err != nil || authorized.Session.ID != session.ID || authorized.SelectionVersion != version {
			cancelSetup()
			if err == nil {
				err = store.ErrConflict
			}
			gatewayFailure(w, err)
			return
		}
	}
	id := session.ID
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
	go s.monitorPrimary(ctx, cancel, u, rawToken, id, version, personal)
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

// Each connection stays on the primary it started with. Switching, including an
// away-and-back switch, changes the version and terminates existing streams.
func (s *Server) monitorPrimary(ctx context.Context, cancel context.CancelFunc, u model.Identity, token, id string, version int64, personal bool) {
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
			var e error
			if personal {
				var current model.Identity
				current, e = s.Store.VerifyPAT(check, token)
				if e == nil && current.Key() != u.Key() {
					e = errors.New("identity changed")
				}
				if e == nil {
					e = s.Store.CheckPrimaryAccess(check, u, id, version)
				}
			} else {
				if time.Now().Before(u.TokenExpiresAt) {
					var current model.Identity
					current, e = s.Auth.Verify(check, token)
					if e == nil && current.Key() != u.Key() {
						e = errors.New("identity changed")
					}
				}
				if e == nil {
					e = s.Store.CheckGatewayAuthorization(check, u, id, version)
				}
			}
			if e == nil {
				_, e = s.Store.RecordPrimaryActivity(check, u, id, version)
			}
			done()
			if e != nil {
				cancel()
				return
			}
		}
	}
}
