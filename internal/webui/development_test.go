package webui

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDevelopmentOriginMustBeExplicitLoopback(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1:5173", "http://localhost:5173/", "https://LOCALHOST:5173", "https://[::1]:5173"} {
		if _, err := NewHandler(target); err != nil {
			t.Errorf("valid development origin %s: %v", target, err)
		}
	}
	for _, target := range []string{
		"https://frontend.example.test", "http://10.0.0.1:5173", "http://0.0.0.0:5173", "http://[::]:5173",
		"http://localhost.example.test:5173", "file:///etc/passwd", "//127.0.0.1:5173", "ws://127.0.0.1:5173",
		"http://user:secret@127.0.0.1:5173", "http://127.0.0.1:5173/src", "http://127.0.0.1:5173/?token=secret",
		"http://127.0.0.1:5173/#fragment", "http://127.0.0.1:5173/%2f", "http://127.0.0.1:bad",
	} {
		if _, err := NewHandler(target); err == nil {
			t.Errorf("unsafe development origin accepted: %s", target)
		} else if strings.Contains(err.Error(), "secret") {
			t.Error("invalid origin error exposed credential text")
		}
	}
}

func TestDevelopmentAssetPathsNeverIncludePrivateOrControlRoutes(t *testing.T) {
	for _, path := range []string{"/", "/assets/app.js", "/assets/app.css"} {
		if !IsAssetPath(path, false) || !IsAssetPath(path, true) {
			t.Errorf("public asset path rejected: %s", path)
		}
	}
	for _, path := range []string{"/src/main.tsx", "/src/pages/Admin.tsx", "/src/lib/kubeconfig.ts", "/@vite/client", "/@react-refresh", "/node_modules/.vite/deps/react.js", "/node_modules/vite/dist/client/env.mjs", "/__vite_hmr"} {
		if IsAssetPath(path, false) || !IsAssetPath(path, true) {
			t.Errorf("development-only asset route is incorrect: %s", path)
		}
	}
	for _, path := range []string{
		"/v1/pats", "/auth/login", "/auth/callback", "/web/session", "/healthz", "/readyz", "/k8s/version",
		"/src/../.env", "/src/%2e%2e/.env", "/src/\\private", "/src/.env", "/src/.env.local", "/src/.git/config",
		"/assets/key.pem", "/src/server.key", "/src/server.crt", "/src/personal.kubeconfig", "/src/local-kubeconfig", "/src/kubeconfig.yaml", "/src/local-kubeconfig.yml", "/src/production.env",
		"/node_modules/.vite/.npmrc", "/node_modules/vite/package.json", "/node_modules/vite/dist/client/private.mjs", "/src/.ssh/id_rsa", "/@fs/etc/passwd", "//src/main.tsx", "/src/a\x00b.tsx",
	} {
		if IsAssetPath(path, false) || IsAssetPath(path, true) {
			t.Errorf("private/control path classified as an asset: %s", path)
		}
	}
}

func TestDevelopmentProxyPreservesModulesButStripsCredentials(t *testing.T) {
	requests := make(chan *http.Request, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		w.Header().Set("Content-Type", "text/javascript")
		w.Header().Set("Authorization", "upstream-secret")
		w.Header().Set("WWW-Authenticate", "upstream-auth")
		w.Header().Set("Proxy-Authenticate", "upstream-proxy")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Content-Security-Policy", "default-src *")
		http.SetCookie(w, &http.Cookie{Name: "unexpected", Value: "secret"})
		fmt.Fprint(w, "export const moduleLoaded = true;")
	}))
	defer upstream.Close()
	handler, err := NewHandler(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	frontend := httptest.NewServer(handler)
	defer frontend.Close()
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		request, err := http.NewRequest(method, frontend.URL+"/src/main.tsx?import&v=fixture", nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-CSRF-Token", "Forwarded", "X-Real-IP", "X-Forwarded-For", "X-Remote-User", "Impersonate-User"} {
			request.Header.Set(name, "browser-secret")
		}
		request.Header.Set("Origin", "https://127.0.0.1:9090")
		request.Header.Set("Sec-WebSocket-Protocol", "vite-hmr, base64url.bearer.authorization.k8s.io.browser-secret")
		response, err := frontend.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || response.Header.Get("Content-Type") != "text/javascript" {
			t.Fatal("development module was not forwarded", response.StatusCode, err)
		}
		if method == http.MethodHead && len(body) != 0 {
			t.Fatal("HEAD returned a body")
		}
		if method == http.MethodGet && !strings.Contains(string(body), "moduleLoaded") {
			t.Fatal("development module changed")
		}
		for _, name := range []string{"Authorization", "Set-Cookie", "WWW-Authenticate", "Proxy-Authenticate"} {
			if response.Header.Get(name) != "" {
				t.Fatal("upstream credential header leaked", name)
			}
		}
		if response.Header.Get("Cache-Control") != "no-store" || !strings.Contains(response.Header.Get("Content-Security-Policy"), "unsafe-inline") || !strings.Contains(response.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatal("development response security headers were lost")
		}
		observed := <-requests
		if observed.Method != method || observed.URL.Path != "/src/main.tsx" || observed.URL.RawQuery != "import&v=fixture" || observed.Header.Get("Origin") != "https://127.0.0.1:9090" {
			t.Fatal("proxy changed module path, query, method or browser origin")
		}
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-CSRF-Token", "Forwarded", "X-Real-IP", "X-Forwarded-For", "X-Remote-User", "Impersonate-User"} {
			if observed.Header.Get(name) != "" {
				t.Fatal("browser identity was forwarded to the asset server", name)
			}
		}
		if observed.Header.Get("Sec-WebSocket-Protocol") != "vite-hmr" {
			t.Fatal("credential-bearing websocket subprotocol was forwarded")
		}
	}
}

func TestDevelopmentProxyRefusesPrivatePathsMethodsAndInvalidUpgrades(t *testing.T) {
	var requests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer upstream.Close()
	handler, err := NewHandler(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/pats", "/auth/login", "/src/.env", "/src/../secret.pem", "/assets/private.key", "/@fs/etc/passwd", "/node_modules/.vite/.git/config"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("%s returned %d", path, response.Code)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodConnect} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(method, "/src/main.tsx", nil))
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("mutation was not rejected: %s returned %d", method, response.Code)
		}
	}
	for _, fixture := range []struct{ path, upgrade string }{{"/src/main.tsx", "websocket"}, {"/__vite_hmr", "SPDY/3.1"}} {
		request := httptest.NewRequest(http.MethodGet, fixture.path, nil)
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", fixture.upgrade)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatal("unsupported frontend upgrade was accepted", response.Code)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("rejected requests reached the frontend development server")
	}
}

func TestDevelopmentHTTPSVerificationFailsClosed(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "unsafe") }))
	upstream.Config.ErrorLog = log.New(io.Discard, "", 0)
	upstream.StartTLS()
	defer upstream.Close()
	handler, err := NewHandler(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/src/main.tsx", nil))
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "unsafe") || strings.Contains(response.Body.String(), upstream.URL) {
		t.Fatal("untrusted frontend TLS did not fail safely")
	}
}

func TestDevelopmentHMRUpgradeForwardsBidirectionalTraffic(t *testing.T) {
	seen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		connection, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprint(buffer, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		if buffer.Flush() != nil {
			return
		}
		payload := make([]byte, 5)
		if _, err = io.ReadFull(buffer, payload); err == nil {
			_, _ = connection.Write(payload)
		}
	}))
	defer upstream.Close()
	handler, err := NewHandler(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	frontend := httptest.NewServer(handler)
	defer frontend.Close()
	connection, err := net.DialTimeout("tcp", strings.TrimPrefix(frontend.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(connection, "GET /__vite_hmr?token=development-fixture HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Protocol: vite-hmr\r\nAuthorization: Bearer browser-secret\r\nCookie: browser-secret\r\n\r\n", strings.TrimPrefix(frontend.URL, "http://"))
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatal("frontend HMR upgrade failed", err)
	}
	if _, err = io.WriteString(connection, "hello"); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 5)
	if _, err = io.ReadFull(reader, payload); err != nil || string(payload) != "hello" {
		t.Fatal("HMR upgrade did not preserve duplex traffic", err)
	}
	headers := <-seen
	if headers.Get("Authorization") != "" || headers.Get("Cookie") != "" || headers.Get("Sec-WebSocket-Protocol") != "vite-hmr" {
		t.Fatal("HMR forwarding leaked identity or lost protocol negotiation")
	}
}
