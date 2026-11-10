package api

import (
	"context"
	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/scheduler"
	"devctl.local/devctl/internal/store"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Authenticator interface {
	Verify(context.Context, string) (model.Identity, error)
}
type Server struct {
	Store                  *store.Store
	Auth                   Authenticator
	Vault                  *kube.Vault
	PublicURL              string
	GatewayCAData          []byte
	GatewayRecheckInterval time.Duration
}
type identityKey struct{}

func user(r *http.Request) model.Identity { return r.Context().Value(identityKey{}).(model.Identity) }
func write(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, code int, msg string) {
	write(w, code, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("one JSON document required")
	}
	return nil
}
func respond(w http.ResponseWriter, e error, v any) {
	if e != nil {
		switch {
		case errors.Is(e, store.ErrNotFound):
			fail(w, 404, "not found")
		case errors.Is(e, store.ErrForbidden):
			fail(w, 403, "not permitted for this identity")
		case errors.Is(e, scheduler.ErrUnavailable), errors.Is(e, store.ErrKey), errors.Is(e, store.ErrConflict):
			fail(w, 409, e.Error())
		default:
			fail(w, 409, e.Error())
		}
		return
	}
	write(w, 200, v)
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { write(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if e := s.Store.Pool.Ping(r.Context()); e != nil {
			fail(w, 503, "database unavailable")
			return
		}
		write(w, 200, map[string]string{"status": "ready"})
	})
	m.HandleFunc("GET /v1/whoami", func(w http.ResponseWriter, r *http.Request) {
		u := user(r)
		if e := s.Store.Audit(r.Context(), u.Key(), "identity", u.Key(), "authenticated application identity"); e != nil {
			fail(w, 503, "audit unavailable")
			return
		}
		write(w, 200, u)
	})
	m.HandleFunc("GET /v1/clusters", func(w http.ResponseWriter, r *http.Request) {
		cs, _, e := s.Store.Snapshot(r.Context())
		respond(w, e, cs)
	})
	m.HandleFunc("GET /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		_, ss, e := s.Store.Snapshot(r.Context())
		respond(w, e, ss)
	})
	m.HandleFunc("GET /v1/sessions/{id}", s.get)
	m.HandleFunc("POST /v1/sessions", s.book)
	m.HandleFunc("POST /v1/auto/{binding}/ensure", s.ensureAutomatic)
	m.HandleFunc("GET /v1/auto/{binding}", s.automatic)
	m.HandleFunc("POST /v1/auto/{binding}/heartbeat", s.heartbeatAutomatic)
	m.HandleFunc("POST /v1/sessions/{id}/stop", func(w http.ResponseWriter, r *http.Request) {
		e := s.Store.Stop(r.Context(), user(r), r.PathValue("id"), "holder ended booking; gateway requests denied; workloads retained", false)
		if errors.Is(e, store.ErrForbidden) {
			fail(w, http.StatusForbidden, "only the original session owner can stop this booking; check devctl whoami and your profile, or ask an administrator to release it")
			return
		}
		respond(w, e, map[string]string{"status": "released"})
	})
	m.HandleFunc("POST /v1/sessions/{id}/share", s.share)
	m.HandleFunc("POST /v1/sessions/{id}/renew", s.renew)
	m.HandleFunc("GET /v1/sessions/{id}/connection", s.connection)
	m.HandleFunc("GET /v1/sessions/{id}/kubeconfig", func(w http.ResponseWriter, r *http.Request) {
		fail(w, http.StatusGone, "raw kubeconfig delivery removed; use devctl kubeconfig for gateway configuration")
	})
	m.HandleFunc("POST /v1/logout", func(w http.ResponseWriter, r *http.Request) {
		e := s.Store.Logout(r.Context(), user(r))
		respond(w, e, map[string]string{"status": "all your bookings released"})
	})
	m.HandleFunc("POST /v1/admin/clusters", s.register)
	m.HandleFunc("PATCH /v1/admin/clusters/{id}", s.maintain)
	m.HandleFunc("POST /v1/admin/sessions/{id}/release", s.force)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/k8s/sessions/") || strings.HasPrefix(r.URL.Path, "/k8s/auto/") {
			s.gateway(w, r)
			return
		}
		// Bound control-plane body reads/writes; gateway streams bypass these deadlines.
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(time.Now().Add(20 * time.Second))
		_ = controller.SetWriteDeadline(time.Now().Add(20 * time.Second))
		defer func() { _ = controller.SetReadDeadline(time.Time{}); _ = controller.SetWriteDeadline(time.Time{}) }()
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			m.ServeHTTP(w, r)
			return
		}
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			fail(w, 401, "Bearer access token required")
			return
		}
		u, e := s.Auth.Verify(r.Context(), strings.TrimPrefix(header, "Bearer "))
		if e != nil {
			slog.Warn("authentication rejected", "reason", e.Error())
			fail(w, 401, "invalid token or user not approved")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/admin/") && !u.Admin {
			fail(w, 403, "administrator required")
			return
		}
		m.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, u)))
	})
}
func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	cs, ss, e := s.Store.Snapshot(r.Context())
	if e != nil {
		respond(w, e, nil)
		return
	}
	for _, v := range ss {
		if v.ID == r.PathValue("id") {
			for _, c := range cs {
				if c.ID == v.Cluster {
					write(w, 200, map[string]any{"session": v, "cluster": c})
					return
				}
			}
		}
	}
	fail(w, 404, "session not found")
}
func (s *Server) book(w http.ResponseWriter, r *http.Request) {
	var b model.Booking
	if e := decode(w, r, &b); e != nil {
		fail(w, 400, "invalid booking JSON")
		return
	}
	if b.TTL != "" {
		d, e := time.ParseDuration(b.TTL)
		if e != nil || d < time.Minute || d > 168*time.Hour {
			fail(w, 400, "TTL must be 1m through 168h, or omitted for no expiry")
			return
		}
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" || len(key) > 128 {
		fail(w, 400, "Idempotency-Key required (max 128 bytes)")
		return
	}
	v, created, e := s.Store.Book(r.Context(), user(r), b, key)
	if e != nil {
		respond(w, e, nil)
		return
	}
	code := 200
	if created {
		code = 201
	}
	write(w, code, v)
}
func (s *Server) share(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Shareable *bool `json:"shareable"`
	}
	if e := decode(w, r, &b); e != nil || b.Shareable == nil {
		fail(w, 400, "shareable boolean required")
		return
	}
	e := s.Store.Share(r.Context(), user(r), r.PathValue("id"), *b.Shareable)
	respond(w, e, map[string]any{"shareable": *b.Shareable})
}
func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	var b struct {
		TTL string `json:"ttl"`
	}
	if e := decode(w, r, &b); e != nil {
		fail(w, 400, "TTL required")
		return
	}
	ttl, e := time.ParseDuration(b.TTL)
	if e != nil || ttl < time.Minute || ttl > 168*time.Hour {
		fail(w, 400, "TTL must be 1m through 168h")
		return
	}
	e = s.Store.Renew(r.Context(), user(r), r.PathValue("id"), ttl)
	respond(w, e, map[string]string{"status": "renewed"})
}

var safeID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID              string            `json:"id"`
		Name            string            `json:"name"`
		Labels          map[string]string `json:"labels"`
		Kubeconfig      string            `json:"kubeconfig"`
		MaxParticipants int               `json:"max_participants"`
	}
	if e := decode(w, r, &b); e != nil {
		fail(w, 400, "invalid registration JSON")
		return
	}
	if !safeID.MatchString(b.ID) || b.Name == "" || len(b.Name) > 128 {
		fail(w, 400, "safe cluster ID and display name required")
		return
	}
	if b.MaxParticipants == 0 {
		b.MaxParticipants = 2
	}
	if b.MaxParticipants < 2 || b.MaxParticipants > 10 {
		fail(w, 400, "max_participants must be 2 through 10")
		return
	}
	if e := kube.Validate([]byte(b.Kubeconfig)); e != nil {
		fail(w, 400, e.Error())
		return
	}
	ciphertext, e := s.Vault.Seal(b.ID, []byte(b.Kubeconfig))
	if e != nil {
		fail(w, 503, "encryption unavailable")
		return
	}
	c := model.Cluster{ID: b.ID, Name: b.Name, Labels: b.Labels, MaxParticipants: b.MaxParticipants}
	e = s.Store.Register(r.Context(), user(r), c, ciphertext)
	respond(w, e, map[string]string{"id": c.ID, "status": "registered"})
}
func (s *Server) maintain(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Maintenance *bool  `json:"maintenance"`
		Reason      string `json:"reason"`
	}
	if e := decode(w, r, &b); e != nil || b.Maintenance == nil || b.Reason == "" {
		fail(w, 400, "maintenance boolean and audit reason required")
		return
	}
	e := s.Store.Maintain(r.Context(), user(r), r.PathValue("id"), *b.Maintenance, b.Reason)
	respond(w, e, map[string]string{"status": "updated"})
}
func (s *Server) force(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Reason string `json:"reason"`
	}
	if e := decode(w, r, &b); e != nil || b.Reason == "" {
		fail(w, 400, "audit reason required")
		return
	}
	e := s.Store.Stop(r.Context(), user(r), r.PathValue("id"), b.Reason, true)
	respond(w, e, map[string]string{"status": "released"})
}
