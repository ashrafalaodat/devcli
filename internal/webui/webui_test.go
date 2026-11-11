package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBrowserAssetsDoNotExposeOtherFiles(t *testing.T) {
	handler := Handler()
	for _, path := range []string{"/assets/", "/assets/index.html", "/assets/../index.html", "/assets/../../go.mod", "/assets/nonexistent.js"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s returned %d; only named public assets may be served", path, w.Code)
		}
	}
	for _, path := range []string{"/", "/assets/app.js", "/assets/app.css"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != 200 || w.Body.Len() == 0 {
			t.Errorf("public asset %s unavailable", path)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("asset %s lacks browser security headers", path)
		}
		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("asset %s has unsafe execution/framing policy", path)
		}
		head := httptest.NewRecorder()
		handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, path, nil))
		if head.Code != 200 || head.Body.Len() != 0 {
			t.Errorf("HEAD %s did not preserve bodyless response", path)
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/assets/app.js", nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatal("static handler accepted a mutation")
	}
}
