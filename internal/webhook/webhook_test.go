package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"devctl.local/devctl/internal/store"
)

func fixturePolicy(server *httptest.Server) Policy {
	return Policy{AllowedOrigins: []string{server.URL}, AllowLoopback: true, CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}
}

func TestSignedDeliveryAndScopedCallbackRemainStableOnRetry(t *testing.T) {
	secret := []byte(strings.Repeat("secret", 8))
	delivery := store.WebhookDelivery{ID: "delivery-fixture", WebhookID: "hook-fixture", Blocking: true, Body: []byte(`{"id":"audit-123","type":"cluster_idle"}`), Deadline: time.Now().UTC().Add(time.Hour)}
	var attempts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || !bytes.Equal(body, delivery.Body) || r.Header.Get("Idempotency-Key") != delivery.ID || r.Header.Get("X-Devctl-Delivery-ID") != delivery.ID {
			t.Error("fixed delivery contract was changed")
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(delivery.ID + "\n" + r.Header.Get("X-Devctl-Timestamp") + "\n"))
		mac.Write(body)
		if r.Header.Get("X-Devctl-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
			t.Error("signature does not authenticate delivery identity, time and exact bytes")
		}
		if r.Header.Get("Authorization") != "" || strings.Contains(r.URL.String(), "secret") {
			t.Error("unexpected credential channel")
		}
		if r.Header.Get("X-Devctl-Callback-URL") != "https://gateway.example.test/v1/webhooks/deliveries/delivery-fixture/complete" || r.Header.Get("X-Devctl-Callback-Token") != CallbackToken(secret, delivery.ID, delivery.Deadline) {
			t.Error("callback scope or endpoint changed")
		}
		attempts.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	delivery.URL = server.URL + "/pipeline"
	sender := Sender{Policy: fixturePolicy(server), PublicURL: "https://gateway.example.test"}
	for range 2 {
		result := sender.Send(t.Context(), delivery, secret)
		if result.StatusCode != 202 || result.Retryable || result.ReasonCode != "accepted" {
			t.Fatal("signed local delivery failed", result)
		}
	}
	if attempts.Load() != 2 {
		t.Fatal("retry did not use same receiver")
	}
	token := CallbackToken(secret, delivery.ID, delivery.Deadline)
	if token == CallbackToken(secret, "another-job", delivery.Deadline) || token == CallbackToken(secret, delivery.ID, delivery.Deadline.Add(time.Second)) || token == CallbackToken([]byte("other-secret"), delivery.ID, delivery.Deadline) {
		t.Fatal("callback capability is not scoped to its integration, job and deadline")
	}
}

func TestPolicyRejectsUnapprovedAndProtectedDestinations(t *testing.T) {
	policy := Policy{AllowedOrigins: []string{"https://ci.example.test", "https://127.0.0.1:9443", "https://169.254.169.254", "https://100.100.100.200", "https://168.63.129.16", "https://0.1.2.3", "https://[fd00:ec2::254]", "https://[fd20:ce::254]", "https://[fd00:1234::1]"}}
	for _, raw := range []string{
		"http://ci.example.test/path", "https://unapproved.example.test/path", "https://ci.example.test:8443/path",
		"https://user:secret@ci.example.test/path", "https://ci.example.test/path?token=secret", "https://ci.example.test/path#fragment",
		"https://ci.example.test/a/../b", "https://ci.example.test/a/%2e%2e/b", "https://ci.example.test/a%5cb",
		"https://127.0.0.1:9443/", "https://169.254.169.254/", "https://100.100.100.200/", "https://168.63.129.16/", "https://0.1.2.3/",
		"https://[fd00:ec2::254]/", "https://[fd20:ce::254]/",
	} {
		if policy.Validate(raw) == nil {
			t.Fatalf("unsafe endpoint accepted: %s", raw)
		}
	}
	if (Policy{}).Validate("https://ci.example.test/path") == nil || policy.Validate("https://ci.example.test/path") != nil || policy.Validate("https://CI.EXAMPLE.TEST:443/path") != nil || policy.Validate("https://[fd00:1234::1]/pipeline") != nil {
		t.Fatal("operator allowlist or canonical HTTPS origin matching failed")
	}
	if (Policy{AllowedOrigins: []string{"https://ci.example.test/path"}}).Validate("https://ci.example.test/other") == nil {
		t.Fatal("path-bearing allowlist entry accepted")
	}
}

func TestDNSResolutionIsCheckedAndBoundToDial(t *testing.T) {
	policy := Policy{AllowedOrigins: []string{"https://ci.example.test"}, resolve: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.20.30.40")}, {IP: net.ParseIP("169.254.169.254")}}, nil
	}}
	transport, err := policy.transport()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.DialContext(t.Context(), "tcp", "ci.example.test:443"); err == nil {
		t.Fatal("mixed public/private DNS answer bypassed protected address check")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	policy.AllowLoopback = true
	var resolves atomic.Int32
	policy.resolve = func(context.Context, string) ([]net.IPAddr, error) {
		resolves.Add(1)
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	transport, err = policy.transport()
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	conn, err := transport.DialContext(t.Context(), "tcp", "does-not-exist.invalid:"+port)
	if err != nil {
		t.Fatal("validated address was not used for dialing")
	}
	conn.Close()
	if resolves.Load() != 1 {
		t.Fatal("destination was resolved again after validation")
	}
}

func TestReceiverFailuresAreBoundedAndClassified(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		delay  time.Duration
		want   string
		retry  bool
	}{
		{"retry", 503, "private-receiver-error", 0, "receiver_rejected", true},
		{"rate-limit", 429, "", 0, "receiver_rejected", true},
		{"auth", 401, "sensitive-credential-hint", 0, "receiver_rejected", false},
		{"large", 200, strings.Repeat("x", (64<<10)+1), 0, "accepted", false},
		{"slow", 200, "", 500 * time.Millisecond, "request_timeout", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if test.delay > 0 {
					select {
					case <-r.Context().Done():
						return
					case <-time.After(test.delay):
					}
				}
				w.WriteHeader(test.status)
				io.WriteString(w, test.body)
			}))
			defer server.Close()
			sender := Sender{Policy: fixturePolicy(server)}
			if test.delay > 0 {
				sender.timeout = 200 * time.Millisecond
			}
			result := sender.Send(t.Context(), store.WebhookDelivery{ID: "job", URL: server.URL, Body: []byte(`{}`)}, []byte("inert-secret"))
			if result.ReasonCode != test.want || result.Retryable != test.retry {
				t.Fatal("wrong safe receiver classification", result)
			}
		})
	}
	var targetCalls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer redirect.Close()
	result := (Sender{Policy: fixturePolicy(redirect)}).Send(t.Context(), store.WebhookDelivery{ID: "job", URL: redirect.URL, Body: []byte(`{}`)}, []byte("inert-secret"))
	if result.Retryable || result.StatusCode != 302 || targetCalls.Load() != 0 {
		t.Fatal("redirect followed or retried", result)
	}
	policy := fixturePolicy(target)
	policy.CAPEM = nil
	result = (Sender{Policy: policy}).Send(t.Context(), store.WebhookDelivery{ID: "job", URL: target.URL, Body: []byte(`{}`)}, []byte("inert-secret"))
	if result.StatusCode != 0 || targetCalls.Load() != 0 || result.ReasonCode != "tls_failed" || result.Retryable {
		t.Fatal("untrusted TLS was accepted")
	}
}

func TestAppliedProxyIsRejectedWithoutSending(t *testing.T) {
	if os.Getenv("DEVCTL_WEBHOOK_PROXY_CHILD") == "1" {
		result := (Sender{Policy: Policy{AllowedOrigins: []string{"https://ci.example.test"}}}).Send(t.Context(), store.WebhookDelivery{ID: "job", URL: "https://ci.example.test/trigger", Body: []byte(`{}`)}, []byte("inert-secret"))
		if result.ReasonCode != "proxy_unsupported" || result.Retryable {
			t.Fatal("proxy route was silently bypassed", result)
		}
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestAppliedProxyIsRejectedWithoutSending$")
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		if strings.Contains(strings.ToUpper(name), "PROXY") {
			continue
		}
		command.Env = append(command.Env, value)
	}
	command.Env = append(command.Env, "DEVCTL_WEBHOOK_PROXY_CHILD=1", "HTTPS_PROXY=http://127.0.0.1:9", "NO_PROXY=")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated proxy check failed: %s", output)
	}
}
