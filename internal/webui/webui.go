// Package webui serves the browser client. Identity and refresh tokens stay
// in the backend; this client receives only CSRF and explicitly requested
// one-time gateway kubeconfig downloads.
package webui

import (
	"embed"
	"net/http"
)

//go:embed assets/index.html assets/app.css assets/app.js
var assets embed.FS

// Handler serves named application assets without directory listings.
func Handler() http.Handler {
	files := map[string]struct{ path, contentType string }{
		"/":               {"assets/index.html", "text/html; charset=utf-8"},
		"/assets/app.css": {"assets/app.css", "text/css; charset=utf-8"},
		"/assets/app.js":  {"assets/app.js", "text/javascript; charset=utf-8"},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		file, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		body, err := assets.ReadFile(file.path)
		if err != nil {
			http.Error(w, "browser client unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", file.contentType)
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	})
}
