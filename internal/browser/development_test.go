package browser

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"devctl.local/devctl/internal/webui"
)

func TestDevelopmentFrontendRequiresLoopbackPublicOrigin(t *testing.T) {
	for _, fixture := range []Config{
		{PublicURL: "https://gateway.example.test", ClientID: "devctl-web", FrontendDevURL: "http://127.0.0.1:5173"},
		{PublicURL: "http://127.0.0.1:9090", ClientID: "devctl-web", FrontendDevURL: "http://127.0.0.1:5173"},
		{PublicURL: "https://127.0.0.1:9090", ClientID: "devctl-web", FrontendDevURL: "https://frontend.example.test"},
	} {
		// Invalid development settings fail before accessing OIDC or persistence.
		if _, err := New(fixture, nil, nil, nil, nil); err == nil {
			t.Error("unsafe development configuration accepted")
		}
	}
}

func TestDevelopmentAssetRoutingDoesNotCaptureControlEndpoints(t *testing.T) {
	assetCalls, coreCalls := 0, 0
	for _, development := range []bool{false, true} {
		handler := &Handler{next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			coreCalls++
			fmt.Fprint(w, "control")
		}), assets: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assetCalls++
			fmt.Fprint(w, "asset")
		})}
		if development {
			handler.config.FrontendDevURL = "http://127.0.0.1:5173"
		}
		for _, path := range []string{"/", "/assets/app.js", "/src/main.tsx", "/@vite/client", "/node_modules/vite/dist/client/env.mjs", "/__vite_hmr", "/k8s/version", "/readyz", "/src/.env"} {
			beforeAsset, beforeCore := assetCalls, coreCalls
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if webui.IsAssetPath(path, development) {
				if assetCalls != beforeAsset+1 || coreCalls != beforeCore {
					t.Errorf("frontend asset routing failed for %s", path)
				}
			} else if coreCalls != beforeCore+1 || assetCalls != beforeAsset {
				t.Errorf("non-asset path was captured: %s", path)
			}
		}
	}
}
