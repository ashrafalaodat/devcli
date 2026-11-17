package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/scheduler"
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

// Discovery uses client-go's DoRaw, which does not decode JSON Status errors.
// Plain text preserves a safe diagnosis in native kubectl's error message.
func gatewayTextFailure(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, message+"\n")
}

var errGatewayRedirect = errors.New("upstream redirects are not forwarded")

type gatewayCancellation struct {
	status   int
	category string
	message  string
}

func (e *gatewayCancellation) Error() string { return e.category }

// Never expose or log raw transport errors: they can contain upstream URLs,
// query parameters, certificate identities or proxy credentials.
func gatewayTransportFailure(err error) (string, string) {
	var verification *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalidCertificate x509.CertificateInvalidError
	var dns *net.DNSError
	var network net.Error
	var operation *net.OpError
	switch {
	case errors.Is(err, errGatewayRedirect):
		return "upstream_redirect", "Kubernetes upstream returned a redirect; ask an administrator to check the registered endpoint"
	case errors.As(err, &verification), errors.As(err, &authority), errors.As(err, &hostname), errors.As(err, &invalidCertificate):
		return "tls_verification_failed", "Kubernetes upstream TLS verification failed; ask an administrator to check the registered cluster certificates"
	case errors.As(err, &dns):
		return "dns_failed", "Kubernetes upstream name resolution failed; ask an administrator to check backend DNS and cluster connectivity"
	case errors.As(err, &network) && network.Timeout():
		return "network_timeout", "Kubernetes upstream connection timed out; ask an administrator to check connectivity from the backend to the selected cluster (including VPN and firewall)"
	case errors.As(err, &operation) && operation.Op == "dial":
		return "connection_failed", "Kubernetes upstream connection failed; ask an administrator to check backend connectivity and the registered cluster endpoint"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "upstream_closed", "Kubernetes upstream closed the connection before responding; retry and ask an administrator to check the selected cluster if this continues"
	default:
		return "transport_failed", "Kubernetes upstream request failed; ask an administrator to check backend connectivity and the selected cluster"
	}
}

func logGatewayFailure(cluster, session, category string) {
	slog.Warn("Kubernetes gateway request failed", "cluster_id", cluster, "session_id", session, "category", category)
}

func gatewayFailure(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, scheduler.ErrUnavailable), errors.Is(e, store.ErrBookingLimit):
		// Preserve an actionable allocation error in native kubectl's DoRaw.
		message := e.Error()
		if errors.Is(e, scheduler.ErrUnavailable) {
			message = "no matching available cluster for automatic booking; an unused cluster must match the saved PAT labels and pass enforced health checks; check cluster health, wait for capacity or edit the preferences"
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, message+"\n")
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
	var session model.Session
	var version int64
	var cluster string
	var ciphertext []byte
	if personal {
		session, version, cluster, ciphertext, e = s.Store.PrimaryPATConfig(setup, rawToken)
	} else {
		session, version, cluster, ciphertext, e = s.Store.PrimaryConfig(setup, u)
	}
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
	setupFailure := func(category, message string) {
		cancelSetup()
		logGatewayFailure(cluster, id, category)
		gatewayTextFailure(w, http.StatusBadGateway, message)
	}
	raw, e := s.Vault.Open(cluster, ciphertext)
	if e != nil {
		setupFailure("credentials_unavailable", "Kubernetes upstream credentials are unavailable; ask an administrator to check the registered cluster configuration")
		return
	}
	if e = kube.Validate(raw); e != nil {
		setupFailure("configuration_unsupported", "Kubernetes upstream configuration is unsupported; ask an administrator to update the registered cluster configuration")
		return
	}
	cfg, e := clientcmd.RESTConfigFromKubeConfig(raw)
	if e != nil {
		setupFailure("configuration_unavailable", "Kubernetes upstream configuration is unavailable; ask an administrator to check the registered cluster configuration")
		return
	}
	// TransportFor uses the original server-held token or client certificate, with
	// normal CA verification. Proxying never runs an uploaded executable plugin.
	// HTTP/1.1 is required by Kubernetes WebSocket and SPDY upgrade transports.
	cfg.NextProtos = []string{"http/1.1"}
	transport, e := rest.TransportFor(cfg)
	if e != nil {
		setupFailure("tls_configuration_unavailable", "Kubernetes upstream TLS configuration is unavailable; ask an administrator to check the registered cluster certificates")
		return
	}
	target, e := url.Parse(cfg.Host)
	if e != nil || target.Scheme != "https" {
		setupFailure("endpoint_invalid", "Kubernetes upstream endpoint is invalid; ask an administrator to check the registered cluster endpoint")
		return
	}
	cancelSetup()
	clientContext := r.Context()
	ctx, cancel := context.WithCancelCause(clientContext)
	defer cancel(nil)
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
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, e error) {
			if clientContext.Err() != nil {
				return // The caller disconnected; there is no response to deliver.
			}
			var ended *gatewayCancellation
			if errors.As(context.Cause(ctx), &ended) {
				logGatewayFailure(cluster, id, ended.category)
				gatewayTextFailure(w, ended.status, ended.message)
				return
			}
			category, message := gatewayTransportFailure(e)
			logGatewayFailure(cluster, id, category)
			gatewayTextFailure(w, http.StatusBadGateway, message)
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Header.Get("Location") != "" {
				return errGatewayRedirect
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
func (s *Server) monitorPrimary(ctx context.Context, cancel context.CancelCauseFunc, u model.Identity, token, id string, version int64, personal bool) {
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
				failure := &gatewayCancellation{
					status: http.StatusServiceUnavailable, category: "authorization_recheck_failed",
					message: "Gateway authorization could not be confirmed; retry and check the backend if this continues",
				}
				if errors.Is(e, store.ErrConflict) || errors.Is(e, store.ErrForbidden) || errors.Is(e, store.ErrNoPrimary) || errors.Is(e, store.ErrNotFound) {
					failure = &gatewayCancellation{
						status: http.StatusForbidden, category: "access_ended",
						message: "Gateway access ended because the booking, primary cluster, or credentials changed; check your booking and sign in again if needed",
					}
				}
				cancel(failure)
				return
			}
		}
	}
}
