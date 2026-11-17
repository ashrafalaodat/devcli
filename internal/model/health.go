package model

import "time"

type HealthProfile string

const (
	HealthProfileAPIReady      HealthProfile = "api-ready.v1"
	HealthProfileDiscoveryOnly HealthProfile = "discovery-only.v1"
	HealthMaxAge                             = 90 * time.Second
	HealthLeaseDuration                      = 20 * time.Second
)

func ValidHealthProfile(v HealthProfile) bool {
	return v == HealthProfileAPIReady || v == HealthProfileDiscoveryOnly
}

type HealthComponent struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	ReasonCode string `json:"reason_code,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// HealthResult contains bounded, classified observations, never upstream bodies,
// URLs, headers or credentials. It is produced by the fixed probe implementation.
type HealthResult struct {
	Passed             bool              `json:"passed"`
	ReasonCode         string            `json:"reason_code"`
	DurationMS         int64             `json:"duration_ms"`
	ReadinessConfirmed bool              `json:"readiness_confirmed"`
	DiscoveryCoverage  string            `json:"discovery_coverage"`
	Components         []HealthComponent `json:"components"`
	RetryAfterSeconds  int               `json:"retry_after_seconds,omitempty"`
}

type ClusterHealth struct {
	State                           string            `json:"state"`
	Profile                         HealthProfile     `json:"profile"`
	ReasonCode                      string            `json:"reason_code"`
	CheckedAt                       *time.Time        `json:"checked_at,omitempty"`
	LastSuccessAt                   *time.Time        `json:"last_success_at,omitempty"`
	DurationMS                      int64             `json:"duration_ms"`
	MaxAgeSeconds                   int               `json:"max_age_seconds"`
	ConsecutiveSuccesses            int               `json:"consecutive_successes"`
	ReadinessConfirmed              bool              `json:"readiness_confirmed"`
	DiscoveryCoverage               string            `json:"discovery_coverage"`
	IdentityVerification            string            `json:"identity_verification"`
	Components                      []HealthComponent `json:"components"`
	CheckPending                    bool              `json:"check_pending"`
	NextCheckAt                     *time.Time        `json:"next_check_at,omitempty"`
	ConfigurationGeneration         int64             `json:"configuration_generation"`
	PolicyRevision                  int64             `json:"policy_revision"`
	ObservedConfigurationGeneration int64             `json:"-"`
	ObservedPolicyRevision          int64             `json:"-"`
	EvaluatedAt                     time.Time         `json:"-"`
}

// Effective derives freshness at decision time, even if every worker has died.
func (h ClusterHealth) Effective(now time.Time) ClusterHealth {
	if h.CheckedAt == nil {
		h.State = "UNKNOWN"
		if h.ReasonCode == "" {
			h.ReasonCode = "not_checked"
		}
		return h
	}
	if h.ConfigurationGeneration != h.ObservedConfigurationGeneration || h.PolicyRevision != h.ObservedPolicyRevision {
		h.State, h.ReasonCode = "UNKNOWN", "configuration_changed"
		return h
	}
	if h.CheckedAt.After(now) || now.Sub(*h.CheckedAt) >= HealthMaxAge {
		h.State = "STALE"
	}
	return h
}

func (h ClusterHealth) Eligible(now time.Time) bool {
	return h.Effective(now).State == "PASSING"
}

func (c Cluster) HealthEligible(now time.Time) bool { return c.Health != nil && c.Health.Eligible(now) }
