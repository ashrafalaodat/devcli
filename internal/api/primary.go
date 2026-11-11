package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

func (s *Server) profile(w http.ResponseWriter, r *http.Request) {
	v, e := s.Store.Profile(r.Context(), user(r))
	respond(w, e, v)
}
func (s *Server) selectPrimary(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Cluster string `json:"cluster"`
	}
	if e := decode(w, r, &b); e != nil || strings.TrimSpace(b.Cluster) == "" || len(b.Cluster) > 128 {
		fail(w, 400, "an owned active cluster ID/name or booking ID is required")
		return
	}
	v, e := s.Store.SelectPrimary(r.Context(), user(r), b.Cluster)
	respond(w, e, v)
}
func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	v, e := s.Store.Settings(r.Context(), user(r))
	respond(w, e, v)
}
func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Max    int    `json:"default_max_bookings"`
		Reason string `json:"reason"`
	}
	if e := decode(w, r, &b); e != nil || b.Max < 1 || b.Max > 100 || strings.TrimSpace(b.Reason) == "" || len(b.Reason) > 1000 {
		fail(w, 400, "default_max_bookings must be 1 through 100 and an audit reason is required")
		return
	}
	e := s.Store.UpdateSettings(r.Context(), user(r), b.Max, b.Reason)
	respond(w, e, map[string]string{"status": "booking default updated; existing bookings retained"})
}
func (s *Server) developers(w http.ResponseWriter, r *http.Request) {
	v, e := s.Store.Developers(r.Context(), user(r))
	respond(w, e, v)
}
func (s *Server) updateDeveloper(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Max    json.RawMessage `json:"max_bookings"`
		Reason string          `json:"reason"`
	}
	if e := decode(w, r, &b); e != nil || len(b.Max) == 0 || strings.TrimSpace(b.Reason) == "" || len(b.Reason) > 1000 {
		fail(w, 400, "max_bookings (integer or null to inherit) and an audit reason are required")
		return
	}
	var limit *int
	if !bytes.Equal(bytes.TrimSpace(b.Max), []byte("null")) {
		var n int
		if json.Unmarshal(b.Max, &n) != nil || n < 1 || n > 100 {
			fail(w, 400, "max_bookings must be 1 through 100, or null to inherit")
			return
		}
		limit = &n
	}
	e := s.Store.UpdateDeveloperLimit(r.Context(), user(r), r.PathValue("owner"), limit, b.Reason)
	respond(w, e, map[string]string{"status": "developer limit updated; existing bookings retained"})
}

func accessTokenCurrent(w http.ResponseWriter, r *http.Request) bool {
	if expiry := user(r).TokenExpiresAt; expiry.IsZero() || !expiry.After(time.Now()) {
		fail(w, 401, "an unexpired API access token is required")
		return false
	}
	return true
}
func (s *Server) access(w http.ResponseWriter, r *http.Request) {
	if !accessTokenCurrent(w, r) {
		return
	}
	v, e := s.Store.PrimaryAccess(r.Context(), user(r))
	respond(w, e, v)
}
func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	if !accessTokenCurrent(w, r) {
		return
	}
	if r.ContentLength != 0 {
		var b struct{}
		if e := decode(w, r, &b); e != nil {
			fail(w, 400, "heartbeat accepts no request fields")
			return
		}
	}
	v, e := s.Store.HeartbeatPrimary(r.Context(), user(r))
	respond(w, e, v)
}
