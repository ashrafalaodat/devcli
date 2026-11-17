package health

import (
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/model"
	clientcmd "k8s.io/client-go/tools/clientcmd"
	clientapi "k8s.io/client-go/tools/clientcmd/api"
)

const testCredential = "server-held-test-secret-never-return"

func healthyBody(path string, aggregated bool) (string, string) {
	switch path {
	case "/version":
		return "application/json", `{"major":"1","minor":"35","gitVersion":"v1.35.1"}`
	case "/readyz":
		return "text/plain", "ok"
	case "/api":
		if aggregated {
			return "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList", `{"apiVersion":"apidiscovery.k8s.io/v2","kind":"APIGroupDiscoveryList","items":[{"metadata":{"name":""},"versions":[{"version":"v1","freshness":"Current","resources":[{"resource":"pods"}]}]}]}`
		}
		return "application/json", `{"kind":"APIVersions","apiVersion":"v1","versions":["v1"]}`
	case "/apis":
		if aggregated {
			return "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList", `{"apiVersion":"apidiscovery.k8s.io/v2","kind":"APIGroupDiscoveryList","items":[{"metadata":{"name":"apps"},"versions":[{"version":"v1","freshness":"Current","resources":[{"resource":"deployments"}]}]},{"metadata":{"name":"batch"},"versions":[{"version":"v1","freshness":"Current","resources":[{"resource":"jobs"}]}]}]}`
		}
		return "application/json", `{"kind":"APIGroupList","apiVersion":"v1","groups":[{"name":"apps","versions":[{"groupVersion":"apps/v1","version":"v1"}]},{"name":"batch","versions":[{"groupVersion":"batch/v1","version":"v1"}]}]}`
	case "/api/v1":
		return "application/json", `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[{"name":"pods","kind":"Pod"}]}`
	case "/apis/apps/v1":
		return "application/json", `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"apps/v1","resources":[{"name":"deployments","kind":"Deployment"}]}`
	case "/apis/batch/v1":
		return "application/json", `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"batch/v1","resources":[{"name":"jobs","kind":"Job"}]}`
	default:
		return "application/json", `{"kind":"Status","status":"Failure"}`
	}
}

func portableConfig(t *testing.T, server *httptest.Server, prefix string, auth *clientapi.AuthInfo) []byte {
	t.Helper()
	cfg := clientapi.NewConfig()
	cfg.CurrentContext = "fixture"
	cfg.Clusters["fixture"] = &clientapi.Cluster{Server: server.URL + prefix, CertificateAuthorityData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}
	cfg.Contexts["fixture"] = &clientapi.Context{Cluster: "fixture", AuthInfo: "fixture"}
	if auth == nil {
		auth = &clientapi.AuthInfo{Token: testCredential}
	}
	cfg.AuthInfos["fixture"] = auth
	raw, err := clientcmd.Write(*cfg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func probeFixture(t *testing.T, aggregated bool, override func(http.ResponseWriter, *http.Request) bool) (*httptest.Server, []byte, *[]string, *sync.Mutex) {
	t.Helper()
	paths := []string{}
	var mu sync.Mutex
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+testCredential {
			t.Errorf("probe changed method or registered identity: %s", r.Method)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if override != nil && override(w, r) {
			return
		}
		content, body := healthyBody(r.URL.Path, aggregated)
		w.Header().Set("Content-Type", content)
		fmt.Fprint(w, body)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, portableConfig(t, server, "", nil), &paths, &mu
}

func TestProbeChecksProfilesAndDiscovery(t *testing.T) {
	for _, tc := range []struct {
		name       string
		aggregated bool
		profile    model.HealthProfile
		coverage   string
		requests   int
		ready      bool
	}{
		{"aggregated", true, model.HealthProfileAPIReady, "aggregated", 4, true},
		{"legacy", false, model.HealthProfileAPIReady, "baseline", 7, true},
		{"explicit-discovery-only", true, model.HealthProfileDiscoveryOnly, "aggregated", 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, raw, paths, mu := probeFixture(t, tc.aggregated, nil)
			result := Probe(t.Context(), raw, tc.profile)
			if !result.Passed || result.ReasonCode != "checks_passed" || result.DiscoveryCoverage != tc.coverage || result.ReadinessConfirmed != tc.ready {
				t.Fatalf("unexpected result: %+v", result)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(*paths) != tc.requests || len(result.Components) != tc.requests {
				t.Fatal("unbounded or incomplete cycle", *paths, result.Components)
			}
			serialized, _ := json.Marshal(result)
			if strings.Contains(string(serialized), testCredential) || strings.Contains(string(serialized), server.URL) {
				t.Fatal("result leaked identity or endpoint")
			}
		})
	}
}

func TestProbeRejectsInvalidOrUnreadyResponses(t *testing.T) {
	for _, tc := range []struct {
		name, path            string
		status                int
		content, body, reason string
	}{
		{"html-login", "/version", 200, "text/html", "<html>sign in</html>", "response_invalid"},
		{"html-json", "/version", 200, "application/json", "<html>sign in</html>", "response_invalid"},
		{"missing-version", "/version", 200, "application/json", `{}`, "response_invalid"},
		{"invalid-json", "/apis", 200, "application/json", `{"kind":`, "discovery_invalid"},
		{"wrong-discovery-type", "/apis", 200, "application/json", `{"kind":"PodList","items":[]}`, "discovery_invalid"},
		{"wrong-negotiated-discovery", "/apis", 200, "application/json;g=apidiscovery.k8s.io;v=v1;as=APIGroupDiscoveryList", `{"apiVersion":"apidiscovery.k8s.io/v2","kind":"APIGroupDiscoveryList","items":[]}`, "discovery_invalid"},
		{"missing-aggregated-core", "/api", 200, "application/json", `{"apiVersion":"apidiscovery.k8s.io/v2","kind":"APIGroupDiscoveryList","items":[]}`, "discovery_invalid"},
		{"stale-discovery", "/apis", 200, "application/json", `{"apiVersion":"apidiscovery.k8s.io/v2","kind":"APIGroupDiscoveryList","items":[{"metadata":{"name":"apps"},"versions":[{"version":"v1","freshness":"Stale"}]}]}`, "discovery_stale"},
		{"unknown-freshness", "/apis", 200, "application/json", `{"apiVersion":"apidiscovery.k8s.io/v2","kind":"APIGroupDiscoveryList","items":[{"metadata":{"name":"apps"},"versions":[{"version":"v1","freshness":"Unknown"}]}]}`, "discovery_invalid"},
		{"readiness-failed", "/readyz", 503, "text/plain", "etcd failed", "api_not_ready"},
		{"readiness-forbidden", "/readyz", 403, "text/plain", "forbidden", "permission_blocked"},
		{"unauthorized", "/version", 401, "text/plain", "invalid token", "unauthorized"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, raw, _, _ := probeFixture(t, true, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != tc.path {
					return false
				}
				w.Header().Set("Content-Type", tc.content)
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
				return true
			})
			got := Probe(t.Context(), raw, model.HealthProfileAPIReady)
			if got.Passed || got.ReasonCode != tc.reason {
				t.Fatal("false passing response", got)
			}
		})
	}
	_, raw, _, _ := probeFixture(t, true, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/readyz" {
			t.Error("explicit discovery-only profile still requested readiness")
			w.WriteHeader(403)
			return true
		}
		return false
	})
	if got := Probe(t.Context(), raw, model.HealthProfileDiscoveryOnly); !got.Passed || got.ReadinessConfirmed {
		t.Fatal(got)
	}
}

func TestProbeKeepsEscapedEndpointPrefix(t *testing.T) {
	const escapedPrefix = "/clusters/lab%2Fa"
	var count atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.EscapedPath(), escapedPrefix+"/") || r.Header.Get("Authorization") != "Bearer "+testCredential {
			t.Error("endpoint prefix or identity lost")
			w.WriteHeader(404)
			return
		}
		count.Add(1)
		path := strings.TrimPrefix(r.URL.Path, "/clusters/lab/a")
		content, body := healthyBody(path, true)
		w.Header().Set("Content-Type", content)
		fmt.Fprint(w, body)
	}))
	defer server.Close()
	if got := Probe(t.Context(), portableConfig(t, server, escapedPrefix, nil), model.HealthProfileAPIReady); !got.Passed || count.Load() != 4 {
		t.Fatal(got, count.Load())
	}
}

func TestProbeBoundsDecodedBodiesAndDoesNotFollowRedirect(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		limit      int
		gzip       bool
	}{
		{"version", "/version", versionLimit, false},
		{"compressed-version", "/version", versionLimit, true},
		{"readiness", "/readyz", readinessLimit, false},
		{"discovery", "/api", discoveryLimit, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, raw, _, _ := probeFixture(t, true, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != tc.path {
					return false
				}
				w.Header().Set("Content-Type", "application/json")
				if tc.gzip {
					w.Header().Set("Content-Encoding", "gzip")
					zw := gzip.NewWriter(w)
					fmt.Fprint(zw, strings.Repeat(" ", tc.limit+1))
					zw.Close()
				} else {
					fmt.Fprint(w, strings.Repeat(" ", tc.limit+1))
				}
				return true
			})
			if got := Probe(t.Context(), raw, model.HealthProfileAPIReady); got.Passed || got.ReasonCode != "response_too_large" {
				t.Fatal(got)
			}
		})
	}
	var callbacks atomic.Int32
	_, raw, _, _ := probeFixture(t, true, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/version" {
			w.Header().Set("Location", "/callback")
			w.WriteHeader(http.StatusFound)
			return true
		}
		if r.URL.Path == "/callback" {
			callbacks.Add(1)
		}
		return false
	})
	if got := Probe(t.Context(), raw, model.HealthProfileAPIReady); got.Passed || got.ReasonCode != "redirect_blocked" || callbacks.Load() != 0 {
		t.Fatal(got, callbacks.Load())
	}
}

func TestProbeDeadlinesCancellationAndRateLimits(t *testing.T) {
	_, raw, _, _ := probeFixture(t, true, func(_ http.ResponseWriter, r *http.Request) bool { <-r.Context().Done(); return true })
	start := time.Now()
	result := (Prober{RequestTimeout: 40 * time.Millisecond}).Probe(t.Context(), raw, model.HealthProfileAPIReady)
	if result.Passed || result.ReasonCode != "request_timeout" || time.Since(start) > time.Second {
		t.Fatal("request deadline not applied", result)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := Probe(ctx, raw, model.HealthProfileAPIReady); got.Passed || got.ReasonCode != "cancelled" {
		t.Fatal(got)
	}
	_, raw, _, _ = probeFixture(t, true, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/version" {
			w.Header().Set("Retry-After", "600")
			w.WriteHeader(429)
			return true
		}
		return false
	})
	if got := Probe(t.Context(), raw, model.HealthProfileAPIReady); got.Passed || got.ReasonCode != "rate_limited" || got.RetryAfterSeconds != 300 {
		t.Fatal(got)
	}
	_, raw, _, _ = probeFixture(t, true, func(w http.ResponseWriter, r *http.Request) bool {
		select {
		case <-r.Context().Done():
			return true
		case <-time.After(25 * time.Millisecond):
			return false
		}
	})
	start = time.Now()
	result = (Prober{RequestTimeout: time.Second, CycleTimeout: 60 * time.Millisecond}).Probe(t.Context(), raw, model.HealthProfileAPIReady)
	if result.Passed || result.ReasonCode != "request_timeout" || len(result.Components) == 0 || len(result.Components) >= 4 || time.Since(start) > time.Second {
		t.Fatal("cycle deadline not applied", result)
	}
}

func TestProbeTLSIdentityAndConfiguration(t *testing.T) {
	server, raw, _, _ := probeFixture(t, true, nil)
	cfg, err := clientcmd.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Clusters["fixture"].CertificateAuthorityData = nil
	untrusted, _ := clientcmd.Write(*cfg)
	if got := Probe(t.Context(), untrusted, model.HealthProfileAPIReady); got.Passed || got.ReasonCode != "tls_untrusted" {
		t.Fatal(got)
	}
	cfg.Clusters["fixture"].CertificateAuthorityData = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	cfg.Clusters["fixture"].TLSServerName = "wrong-name.example.test"
	mismatch, _ := clientcmd.Write(*cfg)
	if got := Probe(t.Context(), mismatch, model.HealthProfileAPIReady); got.Passed || got.ReasonCode != "tls_hostname_mismatch" {
		t.Fatal(got)
	}
	for _, bad := range [][]byte{nil, []byte("not: valid: yaml"), []byte(strings.Replace(string(raw), "token: "+testCredential, "exec:\n      command: forbidden-program\n      apiVersion: client.authentication.k8s.io/v1", 1))} {
		if got := Probe(t.Context(), bad, model.HealthProfileAPIReady); got.Passed || got.ReasonCode != "configuration_invalid" || len(got.Components) != 0 {
			t.Fatal(got)
		}
	}
}

func TestProbeUsesRegisteredClientCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "health-fixture-client"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	var count atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 1 || r.TLS.PeerCertificates[0].Subject.CommonName != "health-fixture-client" || r.Header.Get("Authorization") != "" {
			t.Error("registered client certificate lost or replaced")
			w.WriteHeader(401)
			return
		}
		count.Add(1)
		content, body := healthyBody(r.URL.Path, true)
		w.Header().Set("Content-Type", content)
		fmt.Fprint(w, body)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	encodedKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	auth := &clientapi.AuthInfo{ClientCertificateData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ClientKeyData: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encodedKey})}
	if got := Probe(t.Context(), portableConfig(t, server, "", auth), model.HealthProfileAPIReady); !got.Passed || count.Load() != 4 {
		t.Fatal(got, count.Load())
	}
}

func TestProbeRejectsExpiredServerCertificateAndRefusedConnection(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "expired-owned-fixture"},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("expired TLS certificate was accepted")
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	raw := portableConfig(t, server, "", nil)
	if got := Probe(t.Context(), raw, model.HealthProfileAPIReady); got.Passed || got.ReasonCode != "tls_expired" {
		t.Fatal(got)
	}
	server.Close()
	if got := Probe(t.Context(), raw, model.HealthProfileAPIReady); got.Passed || got.ReasonCode != "connection_refused" {
		t.Fatal(got)
	}
}
