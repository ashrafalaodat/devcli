package model

import (
	"testing"
	"time"
)

func TestHealthEligibilityUsesFreshCurrentObservation(t *testing.T) {
	now := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	if (Cluster{}).HealthEligible(now) {
		t.Fatal("missing health bypassed placement gate")
	}
	checked := now.Add(-30 * time.Second)
	h := ClusterHealth{State: "PASSING", CheckedAt: &checked, ConfigurationGeneration: 2, ObservedConfigurationGeneration: 2, PolicyRevision: 3, ObservedPolicyRevision: 3}
	if !h.Eligible(now) {
		t.Fatal("fresh matching observation blocked")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ClusterHealth)
	}{
		{"exact boundary", func(h *ClusterHealth) { v := now.Add(-HealthMaxAge); h.CheckedAt = &v }},
		{"future timestamp", func(h *ClusterHealth) { v := now.Add(time.Second); h.CheckedAt = &v }},
		{"changed configuration", func(h *ClusterHealth) { h.ConfigurationGeneration++ }},
		{"changed profile", func(h *ClusterHealth) { h.PolicyRevision++ }},
		{"no observation", func(h *ClusterHealth) { h.CheckedAt = nil }},
		{"one recovery pass", func(h *ClusterHealth) { h.State = "RECOVERING" }},
		{"failed check", func(h *ClusterHealth) { h.State = "FAILING" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := h
			tc.mutate(&v)
			if v.Eligible(now) {
				t.Fatal("unsafe health admitted")
			}
		})
	}
}
