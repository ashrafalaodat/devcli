package webui

import (
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// IsLoopbackHost deliberately accepts no arbitrary DNS names. Development
// source serving must never become a proxy to another network destination.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func developmentOrigin(raw string) (*url.URL, error) {
	target, err := url.Parse(raw)
	if err != nil || target.Host == "" || target.User != nil || target.Opaque != "" || target.RawPath != "" || target.RawQuery != "" || target.Fragment != "" || (target.Path != "" && target.Path != "/") || (target.Scheme != "http" && target.Scheme != "https") || !IsLoopbackHost(target.Hostname()) {
		return nil, errors.New("DEVCTL_FRONTEND_DEV_URL must be a loopback HTTP or HTTPS origin without credentials, a path, query or fragment")
	}
	return target, nil
}

// IsAssetPath lists only the paths Vite needs for the frontend entry point,
// source modules, dependency cache and hot-module-reload connection. Control,
// identity and Kubernetes gateway routes never belong to this handler.
func IsAssetPath(path string, development bool) bool {
	if !safeAssetPath(path) {
		return false
	}
	if path == "/" || strings.HasPrefix(path, "/assets/") {
		return true
	}
	return development && (strings.HasPrefix(path, "/src/") ||
		strings.HasPrefix(path, "/@vite/") || path == "/@react-refresh" ||
		strings.HasPrefix(path, "/node_modules/.vite/") ||
		path == "/node_modules/vite/dist/client/env.mjs" || path == "/__vite_hmr")
}

func safeAssetPath(path string) bool {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\%\x00\r\n") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if privateAssetSegment(strings.ToLower(segment)) {
			return false
		}
	}
	return true
}

func privateAssetSegment(part string) bool {
	switch part {
	case ".", "..", ".git", ".ssh", ".npmrc", ".netrc", ".env", "kubeconfig":
		return true
	}
	if strings.HasPrefix(part, ".env.") {
		return true
	}
	for _, suffix := range []string{".env", ".key", ".pem", ".crt", ".kubeconfig", "-kubeconfig"} {
		if strings.HasSuffix(part, suffix) {
			return true
		}
	}
	for _, extension := range []string{".yaml", ".yml", ".json"} {
		base := strings.TrimSuffix(part, extension)
		if base != part && (base == "kubeconfig" || strings.HasSuffix(base, ".kubeconfig") || strings.HasSuffix(base, "-kubeconfig")) {
			return true
		}
	}
	return false
}

func assetHeaders(h http.Header, development bool) {
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if development {
		// Vite injects the React refresh preamble and CSS updates. This relaxed
		// policy applies only to the explicitly enabled loopback development UI.
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		return
	}
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
}

func stripDevelopmentHeaders(h http.Header) {
	for key := range h {
		name := strings.ToLower(key)
		if name == "authorization" || name == "proxy-authorization" || name == "cookie" || name == "x-csrf-token" || name == "forwarded" || name == "x-real-ip" || strings.HasPrefix(name, "x-forwarded-") || strings.HasPrefix(name, "x-remote-") || strings.HasPrefix(name, "impersonate-") {
			h.Del(key)
		}
	}
	protocols := []string{}
	for _, line := range h.Values("Sec-WebSocket-Protocol") {
		for _, protocol := range strings.Split(line, ",") {
			protocol = strings.TrimSpace(protocol)
			if protocol != "" && !strings.HasPrefix(strings.ToLower(protocol), "base64url.bearer.authorization.k8s.io.") {
				protocols = append(protocols, protocol)
			}
		}
	}
	if len(protocols) == 0 {
		h.Del("Sec-WebSocket-Protocol")
	} else {
		h.Set("Sec-WebSocket-Protocol", strings.Join(protocols, ", "))
	}
}

func developmentHandler(raw string) (http.Handler, error) {
	target, err := developmentOrigin(raw)
	if err != nil {
		return nil, err
	}
	proxy := &httputil.ReverseProxy{
		Transport: &http.Transport{
			// The validated target is local: do not send frontend sources through
			// an inherited outbound proxy. HTTPS keeps normal CA verification.
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		},
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			stripDevelopmentHeaders(pr.Out.Header)
		},
		ModifyResponse: func(response *http.Response) error {
			response.Header.Del("Set-Cookie")
			response.Header.Del("Authorization")
			response.Header.Del("Proxy-Authenticate")
			response.Header.Del("WWW-Authenticate")
			assetHeaders(response.Header, true)
			return nil
		},
		ErrorLog: log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			assetHeaders(w.Header(), true)
			http.Error(w, "frontend development server unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assetHeaders(w.Header(), true)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !IsAssetPath(r.URL.Path, true) {
			http.NotFound(w, r)
			return
		}
		if upgrade := r.Header.Get("Upgrade"); upgrade != "" && (r.URL.Path != "/__vite_hmr" || !strings.EqualFold(upgrade, "websocket")) {
			http.Error(w, "unsupported frontend upgrade", http.StatusBadRequest)
			return
		}
		proxy.ServeHTTP(w, r)
	}), nil
}
