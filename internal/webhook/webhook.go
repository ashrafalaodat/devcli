// Package webhook delivers fixed, signed lifecycle notifications. It never runs
// commands or follows receiver-provided URLs.
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/store"
)

type Policy struct {
	AllowedOrigins []string
	AllowLoopback  bool
	CAPEM          []byte
	resolve        func(context.Context, string) ([]net.IPAddr, error)
}

var errDestinationBlocked = errors.New("webhook destination address is protected")
var errDNSUnavailable = errors.New("webhook DNS unavailable")

func endpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(u.Path, "\\\x00\r\n") {
		return nil, errors.New("webhook endpoint must be HTTPS without URL credentials, query or fragment")
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return nil, errors.New("webhook endpoint path must not contain traversal segments")
		}
	}
	return u, nil
}

func origin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// Validate performs configuration checks without contacting the receiver.
// DNS and destination-address checks are repeated when the request is dialed.
func (p Policy) Validate(raw string) error {
	u, err := endpoint(raw)
	if err != nil {
		return err
	}
	allowed := false
	for _, rawOrigin := range p.AllowedOrigins {
		entry, err := endpoint(strings.TrimSpace(rawOrigin))
		if err != nil || entry.Path != "" && entry.Path != "/" {
			return errors.New("webhook allowed origins must contain HTTPS origins only")
		}
		allowed = allowed || origin(entry) == origin(u)
	}
	if !allowed {
		return errors.New("webhook destination is not in the operator's allowed origins")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !p.safeIP(ip) {
		return errors.New("webhook destination address is protected")
	}
	return nil
}

func (p Policy) safeIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return p.AllowLoopback
	}
	if !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	switch ip.String() {
	case "100.100.100.200", "168.63.129.16", "fd00:ec2::254", "fd20:ce::254":
		return false // Provider metadata/control endpoints, including IPv6 ULA.
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 0 {
		return false
	}
	return true // Private CI addresses still require the exact operator allowlist.
}

func (p Policy) transport() (*http.Transport, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if len(p.CAPEM) > 0 {
		public, err := kube.PublicCertificates(p.CAPEM)
		if err != nil || !pool.AppendCertsFromPEM(public) {
			return nil, errors.New("invalid webhook CA configuration")
		}
	}
	resolve := p.resolve
	if resolve == nil {
		resolve = net.DefaultResolver.LookupIPAddr
	}
	return &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			addresses, err := resolve(ctx, host)
			if err != nil || len(addresses) == 0 {
				return nil, errDNSUnavailable
			}
			for _, address := range addresses {
				if !p.safeIP(address.IP) {
					return nil, errDestinationBlocked
				}
			}
			// Dial the validated literal address, avoiding a second DNS lookup.
			var last error
			for _, address := range addresses {
				connection, err := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
				if err == nil {
					return connection, nil
				}
				last = err
			}
			return nil, last
		},
	}, nil
}

func Signature(secret []byte, id, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = io.WriteString(mac, id+"\n"+timestamp+"\n")
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func CallbackToken(secret []byte, id string, deadline time.Time) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = io.WriteString(mac, "devctl callback\n"+id+"\n"+deadline.UTC().Format(time.RFC3339Nano))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

type Result struct {
	StatusCode int
	Retryable  bool
	ReasonCode string
}

type Sender struct {
	Policy    Policy
	PublicURL string
	timeout   time.Duration
}

func (s Sender) Send(ctx context.Context, delivery store.WebhookDelivery, secret []byte) Result {
	if s.Policy.Validate(delivery.URL) != nil {
		return Result{ReasonCode: "destination_blocked"}
	}
	timeout := s.timeout
	if timeout <= 0 || timeout > 5*time.Second {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, delivery.URL, strings.NewReader(string(delivery.Body)))
	if err != nil {
		return Result{ReasonCode: "configuration_invalid"}
	}
	proxy, err := http.ProxyFromEnvironment(req)
	if err != nil || proxy != nil {
		return Result{ReasonCode: "proxy_unsupported"}
	}
	transport, err := s.Policy.transport()
	if err != nil {
		return Result{ReasonCode: "configuration_invalid"}
	}
	defer transport.CloseIdleConnections()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", delivery.ID)
	req.Header.Set("X-Devctl-Delivery-ID", delivery.ID)
	req.Header.Set("X-Devctl-Timestamp", timestamp)
	req.Header.Set("X-Devctl-Signature", Signature(secret, delivery.ID, timestamp, delivery.Body))
	if delivery.Blocking {
		callback, err := endpoint(s.PublicURL)
		if err != nil || callback.Path != "" && callback.Path != "/" {
			return Result{ReasonCode: "configuration_invalid"}
		}
		req.Header.Set("X-Devctl-Callback-URL", strings.TrimSuffix(s.PublicURL, "/")+"/v1/webhooks/deliveries/"+url.PathEscape(delivery.ID)+"/complete")
		req.Header.Set("X-Devctl-Callback-Token", CallbackToken(secret, delivery.ID, delivery.Deadline))
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		var certificate *tls.CertificateVerificationError
		var network net.Error
		switch {
		case errors.Is(err, errDestinationBlocked):
			return Result{ReasonCode: "destination_blocked"}
		case errors.As(err, &certificate):
			return Result{ReasonCode: "tls_failed"}
		case errors.Is(err, errDNSUnavailable):
			return Result{Retryable: true, ReasonCode: "dns_failed"}
		case errors.As(err, &network) && network.Timeout():
			return Result{Retryable: true, ReasonCode: "request_timeout"}
		}
		return Result{Retryable: true, ReasonCode: "connection_failed"}
	}
	defer response.Body.Close()
	// Acceptance is the HTTP status, not an untrusted response body. Discard a
	// bounded amount without converting an acknowledged request into a retry.
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return Result{StatusCode: response.StatusCode, ReasonCode: "accepted"}
	}
	return Result{StatusCode: response.StatusCode, Retryable: response.StatusCode == 408 || response.StatusCode == 429 || response.StatusCode >= 500, ReasonCode: "receiver_rejected"}
}
