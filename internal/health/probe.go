// Package health observes registered Kubernetes APIs without reservation or
// developer-activity side effects. It never creates Kubernetes resources.
package health

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
	apidiscovery "k8s.io/api/apidiscovery/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	semanticversion "k8s.io/apimachinery/pkg/util/version"
	kubeversion "k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	requestTimeout  = 3 * time.Second
	cycleTimeout    = 10 * time.Second
	versionLimit    = 64 << 10
	readinessLimit  = 4 << 10
	discoveryLimit  = 4 << 20
	discoveryAccept = "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList,application/json"
)

// Prober permits shorter deadlines for deterministic fixtures. Zero values use
// production defaults; callers cannot extend production time budgets.
type Prober struct {
	RequestTimeout time.Duration
	CycleTimeout   time.Duration
}

// Probe performs a bounded cycle with default deadlines. Returned diagnostics
// contain fixed codes, never credential material or endpoint URLs.
func Probe(ctx context.Context, raw []byte, profile model.HealthProfile) model.HealthResult {
	return (Prober{}).Probe(ctx, raw, profile)
}

func boundedDuration(value, maximum time.Duration) time.Duration {
	if value <= 0 || value > maximum {
		return maximum
	}
	return value
}

type cycle struct {
	ctx            context.Context
	client         *http.Client
	target         *url.URL
	requestTimeout time.Duration
	result         model.HealthResult
}

// Probe performs one cycle with this prober's bounded deadlines.
func (p Prober) Probe(parent context.Context, raw []byte, profile model.HealthProfile) (result model.HealthResult) {
	started := time.Now()
	defer func() { result.DurationMS = time.Since(started).Milliseconds() }()
	ctx, cancel := context.WithTimeout(parent, boundedDuration(p.CycleTimeout, cycleTimeout))
	defer cancel()
	result = model.HealthResult{DiscoveryCoverage: "not_completed"}
	if !model.ValidHealthProfile(profile) || kube.Validate(raw) != nil {
		result.ReasonCode = "configuration_invalid"
		return
	}
	cfg, err := clientcmd.RESTConfigFromKubeConfig(raw)
	if err != nil {
		result.ReasonCode = "configuration_invalid"
		return
	}
	cfg.NextProtos = []string{"http/1.1"}
	transport, err := rest.TransportFor(cfg)
	if err != nil {
		result.ReasonCode = "configuration_invalid"
		return
	}
	target, err := url.Parse(cfg.Host)
	if err != nil || target.Scheme != "https" || target.Host == "" {
		result.ReasonCode = "configuration_invalid"
		return
	}
	c := cycle{
		ctx: ctx, target: target, requestTimeout: boundedDuration(p.RequestTimeout, requestTimeout), result: result,
		client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	if !c.check("version", "/version", versionLimit, "application/json", validateVersion) {
		return c.result
	}
	if profile == model.HealthProfileAPIReady {
		if !c.check("readiness", "/readyz", readinessLimit, "text/plain", nil) {
			return c.result
		}
		c.result.ReadinessConfirmed = true
	}
	coreAggregated, groupsAggregated := false, false
	coreVersions, groupVersions := map[string]bool{}, map[string]bool{}
	if !c.check("core_discovery", "/api", discoveryLimit, discoveryAccept, func(body []byte) string {
		var reason string
		coreAggregated, coreVersions, reason = validateDiscovery(body, true)
		return reason
	}) {
		return c.result
	}
	if !c.check("group_discovery", "/apis", discoveryLimit, discoveryAccept, func(body []byte) string {
		var reason string
		groupsAggregated, groupVersions, reason = validateDiscovery(body, false)
		return reason
	}) {
		return c.result
	}
	if coreAggregated && groupsAggregated {
		if !coreVersions["v1"] || !groupVersions["apps/v1"] || !groupVersions["batch/v1"] {
			c.result.ReasonCode = "discovery_invalid"
			return c.result
		}
		c.result.DiscoveryCoverage = "aggregated"
	} else {
		for _, endpoint := range []struct{ name, path, version string }{
			{"core_resources", "/api/v1", "v1"},
			{"application_resources", "/apis/apps/v1", "apps/v1"},
			{"job_resources", "/apis/batch/v1", "batch/v1"},
		} {
			if !c.check(endpoint.name, endpoint.path, discoveryLimit, "application/json", func(body []byte) string { return validateResources(body, endpoint.version) }) {
				return c.result
			}
		}
		c.result.DiscoveryCoverage = "baseline"
	}
	c.result.Passed = true
	c.result.ReasonCode = "checks_passed"
	return c.result
}

func (c *cycle) check(name, path string, limit int64, accept string, validate func([]byte) string) bool {
	started := time.Now()
	component := model.HealthComponent{Name: name, State: "FAILING"}
	finish := func(reason string) bool {
		component.DurationMS = time.Since(started).Milliseconds()
		component.ReasonCode = reason
		if reason == "" {
			component.State = "PASSING"
		} else {
			c.result.ReasonCode = reason
		}
		c.result.Components = append(c.result.Components, component)
		return reason == ""
	}
	u := *c.target
	u.Path = strings.TrimSuffix(c.target.Path, "/") + path
	u.RawPath = strings.TrimSuffix(c.target.EscapedPath(), "/") + path
	u.RawQuery = ""
	u.Fragment = ""
	ctx, cancel := context.WithTimeout(c.ctx, c.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return finish("configuration_invalid")
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "devctl-health/1")
	resp, err := c.client.Do(req)
	if err != nil {
		return finish(transportReason(err))
	}
	defer resp.Body.Close()
	component.HTTPStatus = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			return finish("redirect_blocked")
		case resp.StatusCode == http.StatusUnauthorized:
			return finish("unauthorized")
		case resp.StatusCode == http.StatusForbidden:
			return finish("permission_blocked")
		case resp.StatusCode == http.StatusTooManyRequests:
			c.result.RetryAfterSeconds = int((parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()) + time.Second - 1) / time.Second)
			return finish("rate_limited")
		case name == "readiness":
			return finish("api_not_ready")
		default:
			return finish("upstream_failed")
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return finish(transportReason(err))
	}
	if int64(len(body)) > limit {
		return finish("response_too_large")
	}
	if validate != nil {
		mediaType, parameters, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return finish("response_invalid")
		}
		if name == "core_discovery" || name == "group_discovery" {
			if parameters["g"] != "" || parameters["v"] != "" || parameters["as"] != "" {
				var meta metav1.TypeMeta
				if parameters["g"] != "apidiscovery.k8s.io" || parameters["v"] != "v2" || parameters["as"] != "APIGroupDiscoveryList" || json.Unmarshal(body, &meta) != nil || meta.Kind != "APIGroupDiscoveryList" || meta.APIVersion != "apidiscovery.k8s.io/v2" {
					return finish("discovery_invalid")
				}
			}
		}
		if reason := validate(body); reason != "" {
			return finish(reason)
		}
	}
	return finish("")
}

func validateVersion(body []byte) string {
	var v kubeversion.Info
	if json.Unmarshal(body, &v) != nil {
		return "response_invalid"
	}
	if _, err := semanticversion.ParseSemantic(v.GitVersion); err != nil {
		return "response_invalid"
	}
	return ""
}

func validateDiscovery(body []byte, core bool) (bool, map[string]bool, string) {
	versions := map[string]bool{}
	var meta metav1.TypeMeta
	if json.Unmarshal(body, &meta) != nil {
		return false, versions, "discovery_invalid"
	}
	if meta.Kind == "APIGroupDiscoveryList" {
		var list apidiscovery.APIGroupDiscoveryList
		if meta.APIVersion != "apidiscovery.k8s.io/v2" || json.Unmarshal(body, &list) != nil || list.Items == nil {
			return false, versions, "discovery_invalid"
		}
		for _, group := range list.Items {
			if len(group.Versions) == 0 {
				return true, versions, "discovery_invalid"
			}
			for _, version := range group.Versions {
				if version.Freshness == apidiscovery.DiscoveryFreshnessStale {
					return true, versions, "discovery_stale"
				}
				if version.Freshness != apidiscovery.DiscoveryFreshnessCurrent || version.Version == "" {
					return true, versions, "discovery_invalid"
				}
				name := version.Version
				if group.Name != "" {
					name = group.Name + "/" + name
				}
				if (name == "v1" || name == "apps/v1" || name == "batch/v1") && len(version.Resources) == 0 {
					return true, versions, "discovery_invalid"
				}
				versions[name] = true
			}
		}
		if core && !versions["v1"] || !core && (!versions["apps/v1"] || !versions["batch/v1"]) {
			return true, versions, "discovery_invalid"
		}
		return true, versions, ""
	}
	if core {
		var list metav1.APIVersions
		if meta.Kind != "APIVersions" || json.Unmarshal(body, &list) != nil || len(list.Versions) == 0 {
			return false, versions, "discovery_invalid"
		}
		for _, version := range list.Versions {
			versions[version] = true
		}
		if !versions["v1"] {
			return false, versions, "discovery_invalid"
		}
	} else {
		var list metav1.APIGroupList
		if meta.Kind != "APIGroupList" || json.Unmarshal(body, &list) != nil || list.Groups == nil {
			return false, versions, "discovery_invalid"
		}
		for _, group := range list.Groups {
			for _, version := range group.Versions {
				versions[version.GroupVersion] = true
			}
		}
		if !versions["apps/v1"] || !versions["batch/v1"] {
			return false, versions, "discovery_invalid"
		}
	}
	return false, versions, ""
}

func validateResources(body []byte, groupVersion string) string {
	var list metav1.APIResourceList
	if json.Unmarshal(body, &list) != nil || list.Kind != "APIResourceList" || list.GroupVersion != groupVersion || len(list.APIResources) == 0 {
		return "discovery_invalid"
	}
	return ""
}

func transportReason(err error) string {
	var certificate *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var dns *net.DNSError
	var network net.Error
	var operation *net.OpError
	switch {
	case errors.As(err, &authority):
		return "tls_untrusted"
	case errors.As(err, &hostname):
		return "tls_hostname_mismatch"
	case errors.As(err, &invalid):
		if invalid.Reason == x509.Expired {
			return "tls_expired"
		}
		return "tls_failed"
	case errors.As(err, &certificate):
		return "tls_failed"
	case errors.As(err, &dns):
		return "dns_failed"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.As(err, &operation) && operation.Op == "dial" && operation.Timeout():
		return "connect_timeout"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &network) && network.Timeout():
		return "request_timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused"
	case errors.As(err, &operation) && operation.Op == "dial":
		return "connection_failed"
	default:
		return "upstream_failed"
	}
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	var delay time.Duration
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
		if seconds > 300 {
			return 5 * time.Minute
		}
		delay = time.Duration(seconds) * time.Second
	} else if when, err := http.ParseTime(value); err == nil {
		delay = when.Sub(now)
	}
	if delay < 0 {
		return 0
	}
	if delay > 5*time.Minute {
		return 5 * time.Minute
	}
	return delay
}
