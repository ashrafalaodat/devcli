package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"golang.org/x/net/websocket"
	"io"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/util/httpstream/spdy"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const upstreamToken = "inert-demo-token-only-the-gateway-may-use"

type apiRequest struct {
	Method, Path, ContentType string
	Watch                     bool
}
type kubernetesFixture struct {
	Server   *httptest.Server
	mu       sync.Mutex
	Requests []apiRequest
}

// This deliberately tiny Kubernetes API fixture validates real kubectl HTTP
// traffic without creating or accessing a real cluster. Kubernetes admission,
// scheduling, Pod execution and cluster authorization are outside its scope.
func newKubernetesFixture(t *testing.T) *kubernetesFixture {
	return newKubernetesFixtureVersion(t, "v1.35.1-fixture")
}
func newKubernetesFixtureVersion(t *testing.T, version string) *kubernetesFixture {
	t.Helper()
	f := &kubernetesFixture{}
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+upstreamToken {
			http.Error(w, "unexpected upstream identity", http.StatusUnauthorized)
			return
		}
		for k := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "impersonate-") {
				http.Error(w, "impersonation header reached upstream", http.StatusForbidden)
				return
			}
		}
		f.mu.Lock()
		f.Requests = append(f.Requests, apiRequest{r.Method, r.URL.Path, r.Header.Get("Content-Type"), r.URL.Query().Get("watch") == "true"})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			json.NewEncoder(w).Encode(map[string]any{"major": "1", "minor": "35", "gitVersion": version, "gitCommit": "fixture", "gitTreeState": "clean", "buildDate": "2026-01-01T00:00:00Z", "goVersion": "go1.26.0", "compiler": "gc", "platform": "linux/amd64"})
		case "/api":
			json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "APIVersions", "versions": []string{"v1"}, "serverAddressByClientCIDRs": []any{}})
		case "/apis":
			json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "APIGroupList", "groups": []any{}})
		case "/api/v1":
			json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "APIResourceList", "groupVersion": "v1", "resources": []any{
				map[string]any{"name": "configmaps", "singularName": "configmap", "namespaced": true, "kind": "ConfigMap", "verbs": []string{"create", "get", "list", "patch", "update", "watch"}},
				map[string]any{"name": "pods", "singularName": "pod", "namespaced": true, "kind": "Pod", "verbs": []string{"get", "list", "watch"}},
			}})
		case "/api/v1/namespaces/default/configmaps/gateway-test":
			if r.Method != "PATCH" {
				http.Error(w, "expected server-side apply patch", 405)
				return
			}
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/apply-patch+") {
				http.Error(w, "expected apply content type", 400)
				return
			}
			raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil || !strings.Contains(string(raw), "gateway-test") {
				http.Error(w, "manifest not forwarded", 400)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "gateway-test", "namespace": "default", "resourceVersion": "1", "uid": "fixture-configmap"}, "data": map[string]string{"message": "gateway apply works"}})
		case "/api/v1/namespaces/default/pods/example":
			json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "example", "namespace": "default", "uid": "fixture-pod"}, "spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "fixture"}}}, "status": map[string]any{"phase": "Running"}})

		case "/api/v1/namespaces/default/pods/example/exec":
			// Exercise kubectl's real multiplexed WebSocket exec transport. No process
			// runs in this fixture; stdout and a successful status are protocol frames.
			server := websocket.Server{Handshake: func(cfg *websocket.Config, req *http.Request) error {
				for _, protocol := range cfg.Protocol {
					if protocol == "v5.channel.k8s.io" {
						cfg.Protocol = []string{protocol}
						return nil
					}
				}
				return fmt.Errorf("expected Kubernetes exec WebSocket protocol")
			}, Handler: func(conn *websocket.Conn) {
				defer conn.Close()
				websocket.Message.Send(conn, append([]byte{1}, []byte("gateway fixture exec output\n")...))
				websocket.Message.Send(conn, append([]byte{3}, []byte(`{"status":"Success"}`)...))
			}}
			server.ServeHTTP(w, r)

		case "/api/v1/namespaces/default/pods/example/portforward":
			servePortForwardFixture(w, r)
		case "/api/v1/namespaces/default/pods/example/log":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintln(w, "gateway fixture log line")
		case "/api/v1/namespaces/default/pods":
			if r.URL.Query().Get("watch") == "true" {
				json.NewEncoder(w).Encode(map[string]any{"type": "ADDED", "object": map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "example", "namespace": "default", "resourceVersion": "1"}, "spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "fixture"}}}, "status": map[string]any{"phase": "Running"}}})
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "PodList", "metadata": map[string]any{"resourceVersion": "1"}, "items": []any{}})
		default:
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Failure", "message": "fixture does not implement this endpoint", "reason": "NotFound", "code": 404})
		}
	}))
	f.Server.EnableHTTP2 = true
	f.Server.StartTLS()
	t.Cleanup(f.Server.Close)
	return f
}
func (f *kubernetesFixture) kubeconfig() string {
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Server.Certificate().Raw})
	return fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: demo
clusters:
- name: demo
  cluster:
    server: %s
    certificate-authority-data: %s
contexts:
- name: demo
  context:
    cluster: demo
    user: demo
users:
- name: demo
  user:
    token: %s
`, f.Server.URL, base64.StdEncoding.EncodeToString(ca), upstreamToken)
}
func (f *kubernetesFixture) saw(method, path string, watch bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.Requests {
		if r.Method == method && r.Path == path && r.Watch == watch {
			return true
		}
	}
	return false
}
func runKubectl(t *testing.T, path string, args ...string) []byte {
	t.Helper()
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Fatal("kubectl is required for the gateway end-to-end suite")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	options := []string{"--kubeconfig", path, "--cache-dir", filepath.Join(t.TempDir(), "cache"), "--request-timeout=10s"}
	options = append(options, args...)
	cmd := exec.CommandContext(ctx, "kubectl", options...)
	cmd.Env = os.Environ()
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl %v failed: %v %s", args, err, raw)
	}
	return raw
}
func assertGatewayDenied(t *testing.T, client *http.Client, address, token string) {
	t.Helper()
	req, err := http.NewRequest("GET", address, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Fatalf("gateway should reject this identity/session, status %d", resp.StatusCode)
	}
}
func credentialToken(t *testing.T, raw []byte) string {
	t.Helper()
	var c struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     struct {
			Token               string    `json:"token"`
			ExpirationTimestamp time.Time `json:"expirationTimestamp"`
			ClientKeyData       string    `json:"clientKeyData"`
		} `json:"status"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal("credential output is not JSON")
	}
	if c.APIVersion != "client.authentication.k8s.io/v1" || c.Kind != "ExecCredential" || c.Status.Token == "" || !c.Status.ExpirationTimestamp.After(time.Now()) || c.Status.ClientKeyData != "" || strings.Contains(c.Status.Token, upstreamToken) {
		t.Fatal("invalid gateway ExecCredential")
	}
	return c.Status.Token
}

func configureGatewayTLS(t *testing.T, e *environment) {
	t.Helper()
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	cert := fixture.TLS.Certificates[0]
	fixture.Close()
	dir := t.TempDir()
	e.certFile = filepath.Join(dir, "gateway.crt")
	e.caFile = e.certFile
	e.keyFile = filepath.Join(dir, "gateway.key")
	raw := []byte{}
	for _, der := range cert.Certificate {
		raw = append(raw, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := os.WriteFile(e.certFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(e.keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
}
func (e *environment) gatewayClient() *http.Client {
	roots := x509.NewCertPool()
	ca, err := os.ReadFile(e.caFile)
	if err != nil {
		e.t.Fatal(err)
	}
	if !roots.AppendCertsFromPEM(ca) {
		e.t.Fatal("invalid test gateway CA")
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
}

func servePortForwardFixture(w http.ResponseWriter, r *http.Request) {
	server := websocket.Server{Handshake: func(cfg *websocket.Config, req *http.Request) error {
		for _, protocol := range cfg.Protocol {
			if protocol == "SPDY/3.1+portforward.k8s.io" {
				cfg.Protocol = []string{protocol}
				return nil
			}
		}
		return fmt.Errorf("expected Kubernetes port-forward WebSocket protocol")
	}, Handler: func(socket *websocket.Conn) {
		defer socket.Close()
		socket.PayloadType = websocket.BinaryFrame
		var mu sync.Mutex
		errors := map[string]httpstream.Stream{}
		conn, err := spdy.NewServerConnection(socket, func(stream httpstream.Stream, replySent <-chan struct{}) error {
			id := stream.Headers().Get("requestID")
			switch stream.Headers().Get("streamType") {
			case "error":
				mu.Lock()
				errors[id] = stream
				mu.Unlock()
			case "data":
				go func() {
					<-replySent
					defer stream.Close()
					request, err := http.ReadRequest(bufio.NewReader(stream))
					if err != nil {
						return
					}
					request.Body.Close()
					body := "gateway fixture port-forward output\n"
					fmt.Fprintf(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
					mu.Lock()
					errorStream := errors[id]
					delete(errors, id)
					mu.Unlock()
					if errorStream != nil {
						errorStream.Close()
					}
				}()
			default:
				return fmt.Errorf("unexpected port-forward stream")
			}
			return nil
		})
		if err != nil {
			return
		}
		defer conn.Close()
		<-conn.CloseChan()
	}}
	server.ServeHTTP(w, r)
}
func runKubectlPortForward(t *testing.T, path string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", path, "--request-timeout=10s", "port-forward", "--address=127.0.0.1", "pod/example", ":8080")
	cmd.Env = os.Environ()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	exited := false
	defer func() {
		if !exited {
			cmd.Process.Signal(os.Interrupt)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				cmd.Process.Kill()
				<-done
			}
		}
	}()
	address := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		pattern := regexp.MustCompile(`Forwarding from (127\.0\.0\.1:[0-9]+)`)
		for scanner.Scan() {
			if match := pattern.FindStringSubmatch(scanner.Text()); len(match) > 1 {
				select {
				case address <- match[1]:
				default:
				}
			}
		}
	}()
	var local string
	select {
	case local = <-address:
	case err = <-done:
		exited = true
		t.Fatalf("kubectl port-forward exited before readiness: %v %s", err, diagnostics.String())
	case <-ctx.Done():
		t.Fatal("kubectl port-forward readiness timed out")
	}
	response, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + local + "/")
	if err != nil {
		t.Fatal("forwarded request failed", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil || !bytes.Contains(raw, []byte("gateway fixture port-forward output")) {
		t.Fatal("port-forward response not tunneled", err)
	}
}
