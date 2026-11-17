package main

import "testing"

func TestWebhookPolicyDefaultsToNoDestinations(t *testing.T) {
	t.Setenv("DEVCTL_WEBHOOK_ALLOWED_ORIGINS", "")
	t.Setenv("DEVCTL_DEV_WEBHOOK_LOOPBACK", "")
	t.Setenv("DEVCTL_WEBHOOK_CA_FILE", "")
	policy, err := configuredWebhookPolicy("127.0.0.1:9090")
	if err != nil || len(policy.AllowedOrigins) != 0 || policy.AllowLoopback || policy.Validate("https://ci.example.test/run") == nil {
		t.Fatal("default webhook policy authorized a destination", err)
	}
}

func TestDevelopmentWebhookLoopbackRequiresExplicitLocalMode(t *testing.T) {
	t.Setenv("DEVCTL_WEBHOOK_ALLOWED_ORIGINS", "https://127.0.0.1:19443")
	t.Setenv("DEVCTL_WEBHOOK_CA_FILE", "")
	t.Setenv("DEVCTL_DEV_WEBHOOK_LOOPBACK", "1")
	t.Setenv("DEVCTL_DEV_HTTP", "1")
	for _, address := range []string{"0.0.0.0:9090", ":9090", "10.1.2.3:9090", "invalid"} {
		if _, err := configuredWebhookPolicy(address); err == nil {
			t.Fatal("development loopback allowed for non-local backend", address)
		}
	}
	if _, err := configuredWebhookPolicy("127.0.0.1:9090"); err != nil {
		t.Fatal("explicit local fixture receiver was rejected", err)
	}
	t.Setenv("DEVCTL_DEV_HTTP", "")
	if _, err := configuredWebhookPolicy("127.0.0.1:9090"); err == nil {
		t.Fatal("development receiver allowed without explicit development mode")
	}
}
