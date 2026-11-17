package api_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/api"
	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"devctl.local/devctl/internal/testutil"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
)

type gatewayAuth struct{ invalid atomic.Bool }

func (a *gatewayAuth) Verify(ctx context.Context, token string) (model.Identity, error) {
	if a.invalid.Load() || token != "alice" && token != "bob" && token != "admin" {
		return model.Identity{}, errors.New("invalid token")
	}
	return model.Identity{Issuer: "https://issuer.test", Subject: token, Name: token, Admin: token == "admin", TokenExpiresAt: time.Now().Add(time.Hour)}, nil
}

type gatewayTest struct {
	db                 *store.Store
	app                *api.Server
	auth               *gatewayAuth
	frontend, upstream *httptest.Server
	session            model.Session
	alice              model.Identity
}

func newGateway(t *testing.T, handler http.Handler, clientCertificate bool) *gatewayTest {
	t.Helper()
	db, _ := testutil.Database(t)
	up := httptest.NewUnstartedServer(handler)
	up.EnableHTTP2 = true
	var cert, key []byte
	if clientCertificate {
		pool, clientCert, clientKey := clientIdentity(t)
		cert, key = clientCert, clientKey
		up.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	}
	up.StartTLS()
	t.Cleanup(up.Close)
	cfg := clientapi.NewConfig()
	cfg.CurrentContext = "registered"
	cfg.Clusters["upstream"] = &clientapi.Cluster{Server: up.URL, CertificateAuthorityData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.Certificate().Raw})}
	cfg.Contexts["registered"] = &clientapi.Context{Cluster: "upstream", AuthInfo: "original"}
	if clientCertificate {
		cfg.AuthInfos["original"] = &clientapi.AuthInfo{ClientCertificateData: cert, ClientKeyData: key}
	} else {
		cfg.AuthInfos["original"] = &clientapi.AuthInfo{Token: "upstream-secret-only"}
	}
	raw, e := clientcmd.Write(*cfg)
	if e != nil {
		t.Fatal(e)
	}
	vault, e := kube.NewVault(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	encrypted, e := vault.Seal("cluster", raw)
	if e != nil {
		t.Fatal(e)
	}
	admin := model.Identity{Issuer: "https://issuer.test", Subject: "admin", Admin: true}
	alice := model.Identity{Issuer: "https://issuer.test", Subject: "alice", Name: "alice"}
	if e = db.Register(context.Background(), admin, model.Cluster{ID: "cluster", Name: "Cluster", MaxParticipants: 2}, encrypted); e != nil {
		t.Fatal(e)
	}
	testutil.MarkHealthy(t, db, "cluster")
	session, _, e := db.Book(context.Background(), alice, model.Booking{}, "one")
	if e != nil {
		t.Fatal(e)
	}
	auth := &gatewayAuth{}
	app := &api.Server{Store: db, Auth: auth, Vault: vault, GatewayRecheckInterval: 20 * time.Millisecond}
	front := httptest.NewServer(app.Handler())
	app.PublicURL = "https://gateway.example.test"
	t.Cleanup(front.Close)
	return &gatewayTest{db: db, app: app, auth: auth, frontend: front, upstream: up, session: session, alice: alice}
}
func (g *gatewayTest) url(path string) string {
	return g.frontend.URL + "/k8s" + path
}
func request(t *testing.T, method, address, token, body string) *http.Response {
	t.Helper()
	req, e := http.NewRequest(method, address, strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func readResponse(t *testing.T, r *http.Response) string {
	t.Helper()
	defer r.Body.Close()
	raw, e := io.ReadAll(r.Body)
	if e != nil {
		t.Fatal(e)
	}
	return string(raw)
}
func TestGatewayForwardsAndKeepsSecretsOnServer(t *testing.T) {
	seen := make(chan *http.Request, 1)
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		seen <- r.Clone(context.Background())
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"kind":"ConfigMap","metadata":{"name":"test"}}`)
	}), false)
	req, e := http.NewRequest("PATCH", g.url("/api/v1/namespaces/default/configmaps/test?fieldManager=kubectl&force=true"), strings.NewReader("manifest-data"))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Authorization", "Bearer alice")
	req.Header.Set("Content-Type", "application/apply-patch+yaml")
	req.Header.Set("Impersonate-User", "admin")
	req.Header.Set("Impersonate-Extra-Role", "admin")
	req.Header.Set("X-Remote-User", "admin")
	req.Header.Set("X-Forwarded-User", "admin")
	req.Header.Set("Cookie", "upstream-token=do-not-forward")
	req.Header.Set("Sec-WebSocket-Protocol", "v5.channel.k8s.io, base64url.bearer.authorization.k8s.io.SENSITIVE")
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	body := readResponse(t, resp)
	if resp.StatusCode != 200 || strings.Contains(body, "upstream-secret") {
		t.Fatal(resp.StatusCode, body)
	}
	received := <-seen
	if received.Method != "PATCH" || received.URL.Path != "/api/v1/namespaces/default/configmaps/test" || received.URL.RawQuery != "fieldManager=kubectl&force=true" || received.Header.Get("Content-Type") != "application/apply-patch+yaml" {
		t.Fatal("request not preserved", received.Method, received.URL, received.Header)
	}
	if received.Header.Get("Authorization") != "Bearer upstream-secret-only" {
		t.Fatal("upstream authentication missing or client token forwarded")
	}
	for _, h := range []string{"Impersonate-User", "Impersonate-Extra-Role", "X-Remote-User", "X-Forwarded-User", "Cookie"} {
		if received.Header.Get(h) != "" {
			t.Fatal("untrusted header forwarded", h)
		}
	}
	if received.Header.Get("Sec-WebSocket-Protocol") != "v5.channel.k8s.io" {
		t.Fatal("websocket bearer protocol not stripped")
	}
	resp = request(t, "GET", g.frontend.URL+"/v1/connection", "alice", "")
	body = readResponse(t, resp)
	var metadata api.Connection
	if e = json.Unmarshal([]byte(body), &metadata); e != nil {
		t.Fatal(e)
	}
	if resp.StatusCode != 200 || metadata.Server != g.app.PublicURL+"/k8s" {
		t.Fatal(resp.StatusCode, body)
	}
	if strings.Contains(body, "upstream-secret") || strings.Contains(body, g.upstream.URL) || strings.Contains(body, "PRIVATE KEY") {
		t.Fatal("metadata leaked original credentials or endpoint")
	}
	resp = request(t, "GET", g.frontend.URL+"/v1/sessions/"+g.session.ID+"/kubeconfig", "alice", "")
	if resp.StatusCode != 410 {
		t.Fatal("raw config delivery is still available", resp.StatusCode)
	}
	readResponse(t, resp)
}
func TestGatewayAuthorizationAndLease(t *testing.T) {
	var hits atomic.Int32
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "ok") }), false)
	for _, tt := range []struct {
		token string
		code  int
	}{{"", 401}, {"invalid", 401}, {"bob", 403}, {"alice", 200}} {
		resp := request(t, "GET", g.url("/version"), tt.token, "")
		if resp.StatusCode != tt.code {
			t.Fatal(tt.token, resp.StatusCode)
		}
		readResponse(t, resp)
	}
	if hits.Load() != 1 {
		t.Fatal("unauthorized requests reached upstream")
	}
	if e := g.db.Stop(context.Background(), g.alice, g.session.ID, "test stop", false); e != nil {
		t.Fatal(e)
	}
	resp := request(t, "GET", g.url("/version"), "alice", "")
	if resp.StatusCode != 403 {
		t.Fatal("old access token bypassed stopped reservation")
	}
	readResponse(t, resp)
	if hits.Load() != 1 {
		t.Fatal("stopped request reached upstream")
	}
}
func TestGatewayClientCertificateAndTLSVerification(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "no client identity", 401)
			return
		}
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "devctl bearer leaked", 400)
			return
		}
		fmt.Fprint(w, "certificate-authenticated")
	}), true)
	resp := request(t, "GET", g.url("/version"), "alice", "")
	if body := readResponse(t, resp); resp.StatusCode != 200 || body != "certificate-authenticated" {
		t.Fatal(resp.StatusCode, body)
	}
	// Replace the encrypted fixture with one lacking the trusted private CA. Normal
	// TLS validation must fail rather than falling back to insecure verification.
	config := clientapi.NewConfig()
	config.CurrentContext = "ctx"
	config.Clusters["cluster"] = &clientapi.Cluster{Server: g.upstream.URL}
	config.AuthInfos["user"] = &clientapi.AuthInfo{Token: "upstream-secret-only"}
	config.Contexts["ctx"] = &clientapi.Context{Cluster: "cluster", AuthInfo: "user"}
	raw, _ := clientcmd.Write(*config)
	ciphertext, _ := g.app.Vault.Seal("cluster", raw)
	if _, e := g.db.Pool.Exec(context.Background(), "UPDATE clusters SET kubeconfig_ciphertext=$1 WHERE id='cluster'", ciphertext); e != nil {
		t.Fatal(e)
	}
	resp = request(t, "GET", g.url("/version"), "alice", "")
	body := readResponse(t, resp)
	if resp.StatusCode != 502 || !strings.Contains(body, "TLS verification failed") || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") || strings.Contains(body, "upstream-secret") || strings.Contains(body, g.upstream.URL) {
		t.Fatal("unverified TLS accepted or error leaked credentials", resp.StatusCode, body)
	}
}

func TestGatewayDiscoveryTransportFailureIsActionableAndRedacted(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"versions":["v1"]}`)
	}), false)
	g.upstream.Close()

	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	client, err := rest.UnversionedRESTClientFor(&rest.Config{
		Host: g.frontend.URL + "/k8s", BearerToken: "alice", Timeout: 5 * time.Second,
		ContentConfig: rest.ContentConfig{NegotiatedSerializer: serializer.NewCodecFactory(runtime.NewScheme())},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Discovery uses DoRaw internally. JSON application errors previously became
	// the opaque InternalError("unknown") reported by ordinary kubectl.
	_, err = client.Get().AbsPath("/api").DoRaw(t.Context())
	if err == nil || !strings.Contains(err.Error(), "Kubernetes upstream connection failed") || strings.Contains(err.Error(), `"unknown"`) {
		t.Fatal("native discovery did not retain the actionable connection error", err)
	}
	var event map[string]any
	if err = json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &event); err != nil || event["cluster_id"] != "cluster" || event["session_id"] != g.session.ID || event["category"] != "connection_failed" {
		t.Fatal("safe structured gateway diagnosis missing", logs.String(), err)
	}
	for _, secret := range []string{"upstream-secret-only", g.upstream.URL, "Bearer alice", "PRIVATE KEY"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("gateway logs exposed credentials or upstream details")
		}
	}
}

func TestGatewayDiscoveryConfigurationFailureIsActionable(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("invalid server-held credentials reached upstream")
	}), false)
	if _, err := g.db.Pool.Exec(t.Context(), "UPDATE clusters SET kubeconfig_ciphertext=$1 WHERE id='cluster'", []byte("invalid encrypted credential material")); err != nil {
		t.Fatal(err)
	}
	client, err := rest.UnversionedRESTClientFor(&rest.Config{
		Host: g.frontend.URL + "/k8s", BearerToken: "alice", Timeout: 5 * time.Second,
		ContentConfig: rest.ContentConfig{NegotiatedSerializer: serializer.NewCodecFactory(runtime.NewScheme())},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Get().AbsPath("/api").DoRaw(t.Context())
	if err == nil || !strings.Contains(err.Error(), "Kubernetes upstream credentials are unavailable") || strings.Contains(err.Error(), `"unknown"`) || strings.Contains(err.Error(), "invalid encrypted credential material") {
		t.Fatal("native discovery lost the safe configuration diagnosis", err)
	}
}

func TestGatewayCancellationBeforeResponseDoesNotReturnEmptySuccess(t *testing.T) {
	for _, end := range []string{"logout", "stop", "db-unavailable"} {
		t.Run(end, func(t *testing.T) {
			started := make(chan struct{}, 1)
			g := newGateway(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				select {
				case started <- struct{}{}:
				default:
				}
				<-r.Context().Done() // No upstream headers or JSON have been sent.
			}), false)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.url("/api"), nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer alice")
			type result struct {
				response *http.Response
				err      error
			}
			done := make(chan result, 1)
			go func() {
				response, err := http.DefaultClient.Do(req)
				done <- result{response, err}
			}()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("upstream request did not start")
			}
			status := http.StatusForbidden
			switch end {
			case "logout":
				err = g.db.Logout(t.Context(), g.alice)
			case "stop":
				err = g.db.Stop(t.Context(), g.alice, g.session.ID, "test release during discovery", false)
			case "db-unavailable":
				g.db.Pool.Close()
				status = http.StatusServiceUnavailable
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-done:
				if got.err != nil {
					t.Fatal("gateway silently closed discovery instead of returning a failure", got.err)
				}
				body := readResponse(t, got.response)
				if got.response.StatusCode != status || !strings.HasPrefix(got.response.Header.Get("Content-Type"), "text/plain") || strings.TrimSpace(body) == "" {
					t.Fatal("authorization cancellation returned an empty or successful response", got.response.StatusCode, body)
				}
				if status == http.StatusForbidden && !strings.Contains(body, "Gateway access ended") {
					t.Fatal("released booking diagnosis missing", body)
				}
			case <-ctx.Done():
				t.Fatal("gateway did not cancel outstanding discovery")
			}
		})
	}
}

func TestGatewayClientDisconnectCancelsPendingUpstream(t *testing.T) {
	started, closed := make(chan struct{}), make(chan struct{})
	g := newGateway(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(closed)
	}), false)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.url("/api"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer alice")
	done := make(chan error, 1)
	go func() {
		response, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if response != nil {
			response.Body.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("pending upstream request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("client disconnect returned an unrelated error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client request did not cancel")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("client disconnect retained the upstream request")
	}
}

func TestGatewayRejectsTraversalAndRedirects(t *testing.T) {
	g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://outside.example.test/credential", 302)
	}), false)
	for _, path := range []string{"/../version", "/%2e%2e/version", "/%252e%252e/version", "/%5cversion"} {
		r := request(t, "GET", g.url(path), "alice", "")
		if r.StatusCode != 400 {
			t.Fatal("traversal not rejected", path, r.StatusCode)
		}
		readResponse(t, r)
	}
	r := request(t, "GET", g.url("/version"), "alice", "")
	if r.StatusCode != 502 || r.Header.Get("Location") != "" {
		t.Fatal("upstream redirect exposed", r.StatusCode)
	}
	readResponse(t, r)
}
func TestGatewayWatchCancelledOnLeaseOrTokenEnd(t *testing.T) {
	for _, end := range []string{"stop", "expiry", "token", "db-unavailable"} {
		t.Run(end, func(t *testing.T) {
			g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintln(w, `{"type":"ADDED"}`)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}), false)
			req, _ := http.NewRequest("GET", g.url("/api/v1/pods?watch=true"), nil)
			req.Header.Set("Authorization", "Bearer alice")
			client := &http.Client{Timeout: 5 * time.Second}
			resp, e := client.Do(req)
			if e != nil {
				t.Fatal(e)
			}
			reader := bufio.NewReader(resp.Body)
			if _, e = reader.ReadString('\n'); e != nil {
				t.Fatal(e)
			}
			switch end {
			case "stop":
				e = g.db.Stop(context.Background(), g.alice, g.session.ID, "test", false)
			case "expiry":
				_, e = g.db.Pool.Exec(context.Background(), "UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", g.session.ID)
			case "token":
				g.auth.invalid.Store(true)
			case "db-unavailable":
				g.db.Pool.Close()
			}
			if e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { _, e := reader.ReadByte(); done <- e }()
			select {
			case e = <-done:
				if e == nil {
					t.Fatal("stream still available")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("stream was not terminated")
			}
			resp.Body.Close()
		})
	}
}
func TestGatewayDuplexUpgradesCancelled(t *testing.T) {
	for _, protocol := range []string{"websocket", "SPDY/3.1"} {
		t.Run(protocol, func(t *testing.T) {
			upDone := make(chan struct{})
			g := newGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer upstream-secret-only" {
					http.Error(w, "bad upstream auth", 401)
					return
				}
				conn, rw, e := w.(http.Hijacker).Hijack()
				if e != nil {
					return
				}
				defer conn.Close()
				defer close(upDone)
				fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", protocol)
				rw.Flush()
				io.Copy(conn, rw)
			}), false)
			u := strings.TrimPrefix(g.frontend.URL, "http://")
			conn, e := net.DialTimeout("tcp", u, time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(4 * time.Second))
			req, _ := http.NewRequest("POST", g.url("/api/v1/namespaces/default/pods/p/exec"), nil)
			req.Header.Set("Authorization", "Bearer alice")
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", protocol)
			if e = req.Write(conn); e != nil {
				t.Fatal(e)
			}
			reader := bufio.NewReader(conn)
			resp, e := http.ReadResponse(reader, req)
			if e != nil {
				t.Fatal(e)
			}
			if resp.StatusCode != 101 {
				t.Fatal("upgrade failed", resp.StatusCode, readResponse(t, resp))
			}
			if _, e = conn.Write([]byte("ping")); e != nil {
				t.Fatal(e)
			}
			buffer := make([]byte, 4)
			if _, e = io.ReadFull(reader, buffer); e != nil || string(buffer) != "ping" {
				t.Fatal("bidirectional stream failed", e)
			}
			if e = g.db.Stop(context.Background(), g.alice, g.session.ID, "test stream stop", false); e != nil {
				t.Fatal(e)
			}
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, e = reader.ReadByte(); e == nil {
				t.Fatal("upgraded connection survived termination")
			}
			select {
			case <-upDone:
			case <-time.After(time.Second):
				t.Fatal("upstream upgraded connection not closed")
			}
		})
	}
}
func clientIdentity(t *testing.T) (*x509.CertPool, []byte, []byte) {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-client-CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	clientKey, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "original-cluster-identity"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	clientDER, e := x509.CreateCertificate(rand.Reader, cert, ca, &clientKey.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	caParsed, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	pool.AddCert(caParsed)
	return pool, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})
}
