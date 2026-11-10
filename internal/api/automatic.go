package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/scheduler"
	"devctl.local/devctl/internal/store"
)

func automaticRequest(w http.ResponseWriter, r *http.Request) bool {
	if !store.ValidAutomaticBinding(r.PathValue("binding")) {
		fail(w, http.StatusBadRequest, "invalid automatic binding ID")
		return false
	}
	// TokenExpiresAt is a server-only field populated by the trusted verifier.
	// No submitted JSON or unverified JWT payload can choose an expiry.
	if expiry := user(r).TokenExpiresAt; expiry.IsZero() || !expiry.After(time.Now()) {
		fail(w, http.StatusUnauthorized, "automatic access requires a valid access token with an expiry")
		return false
	}
	return true
}

func automaticFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "automatic binding not found for this identity")
	case errors.Is(err, store.ErrForbidden):
		fail(w, http.StatusForbidden, "automatic binding is not permitted for this identity")
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrKey), errors.Is(err, scheduler.ErrUnavailable):
		fail(w, http.StatusConflict, err.Error())
	default:
		fail(w, http.StatusServiceUnavailable, "automatic reservation state unavailable")
	}
}

func (s *Server) ensureAutomatic(w http.ResponseWriter, r *http.Request) {
	if !automaticRequest(w, r) {
		return
	}
	if ValidatePublicURL(s.PublicURL) != nil {
		fail(w, http.StatusServiceUnavailable, "gateway public URL is not configured")
		return
	}
	var booking model.Booking
	if err := decode(w, r, &booking); err != nil {
		fail(w, http.StatusBadRequest, "invalid automatic booking request")
		return
	}
	if booking.TTL != "" {
		ttl, err := time.ParseDuration(booking.TTL)
		if err != nil || ttl < time.Minute || ttl > 7*24*time.Hour {
			fail(w, http.StatusBadRequest, "TTL must be 1m through 168h, or omitted for no expiry")
			return
		}
	}
	binding := r.PathValue("binding")
	access, err := s.Store.EnsureAutomatic(r.Context(), user(r), binding, booking)
	if err != nil {
		automaticFailure(w, err)
		return
	}
	write(w, http.StatusOK, struct {
		store.AutomaticAccess
		Connection
	}{access, Connection{
		Server:                   strings.TrimSuffix(s.PublicURL, "/") + "/k8s/auto/" + url.PathEscape(binding),
		CertificateAuthorityData: base64.StdEncoding.EncodeToString(s.GatewayCAData),
	}})
}

func (s *Server) automatic(w http.ResponseWriter, r *http.Request) {
	if !automaticRequest(w, r) {
		return
	}
	access, err := s.Store.Automatic(r.Context(), user(r), r.PathValue("binding"))
	if err != nil {
		automaticFailure(w, err)
		return
	}
	write(w, http.StatusOK, access)
}

func (s *Server) heartbeatAutomatic(w http.ResponseWriter, r *http.Request) {
	if !automaticRequest(w, r) {
		return
	}
	// An empty request is sufficient. {} is accepted for standard JSON clients;
	// all fields (especially purported token expiries) are rejected.
	if r.ContentLength != 0 {
		var empty struct{}
		if err := decode(w, r, &empty); err != nil {
			fail(w, http.StatusBadRequest, "heartbeat accepts no request fields")
			return
		}
	}
	access, err := s.Store.HeartbeatAutomatic(r.Context(), user(r), r.PathValue("binding"))
	if err != nil {
		automaticFailure(w, err)
		return
	}
	write(w, http.StatusOK, access)
}
