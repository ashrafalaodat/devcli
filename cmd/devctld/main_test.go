package main

import "testing"

func TestDevelopmentFrontendRequiresLoopbackListenerAndTarget(t *testing.T) {
	for _, address := range []string{"127.0.0.1:9090", "localhost:9090", "[::1]:9090"} {
		if err := validateFrontendDevelopmentListener(address, "http://127.0.0.1:5173"); err != nil {
			t.Errorf("valid development listener %s: %v", address, err)
		}
	}
	for _, address := range []string{":9090", "0.0.0.0:9090", "[::]:9090", "10.0.0.1:9090", "gateway.example.test:9090", "invalid"} {
		if err := validateFrontendDevelopmentListener(address, "http://127.0.0.1:5173"); err == nil {
			t.Errorf("development assets enabled on nonloopback listener %s", address)
		}
	}
	if err := validateFrontendDevelopmentListener("127.0.0.1:9090", "https://frontend.example.test"); err == nil {
		t.Error("remote development target was accepted")
	}
	if err := validateFrontendDevelopmentListener("0.0.0.0:9090", ""); err != nil {
		t.Error("production listener was restricted by disabled development mode", err)
	}
}
