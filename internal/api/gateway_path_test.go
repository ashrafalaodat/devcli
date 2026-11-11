package api

import (
	"net/url"
	"testing"
)

func TestGatewayRoutingAndPublicURL(t *testing.T) {
	for _, raw := range []string{"https://gateway.example.test", "https://127.0.0.1:8080"} {
		if e := ValidatePublicURL(raw); e != nil {
			t.Fatal(raw, e)
		}
	}
	for _, raw := range []string{"http://127.0.0.1:8080", "http://gateway.example.test", "https://user:password@gateway.example.test", "https://gateway.example.test/prefix", "https://gateway.example.test?secret=token", ""} {
		if e := ValidatePublicURL(raw); e == nil {
			t.Fatal("unsafe publicURL accepted", raw)
		}
	}
	for _, raw := range []string{"/k8s" + "/version", "/k8s" + "/api/v1/namespaces/default/pods/p/log?follow=true", "/k8s" + "/api/v1/services/http:service:80/proxy/hello%20world"} {
		u, e := url.Parse(raw)
		if e != nil {
			t.Fatal(e)
		}
		path, e := gatewayPath(u)
		if e != nil || path == "" {
			t.Fatal("valid path rejected", raw, e)
		}
	}
	for _, raw := range []string{"/k8s" + "/../other", "/k8s" + "/%2e%2e/other", "/k8s" + "/%252e%252e/other", "/other/version", "/k8s%2fapi/version", "/k8s%2fapi/version"} {
		u, e := url.Parse(raw)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = gatewayPath(u); e == nil {
			t.Fatal("ambiguous route accepted", raw)
		}
	}
}
