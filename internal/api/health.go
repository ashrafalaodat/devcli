package api

import (
	"errors"
	"net/http"
	"strings"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
)

func healthReason(reason string) (string, bool) {
	reason = strings.TrimSpace(reason)
	return reason, len(reason) > 0 && len(reason) <= 1000
}

func healthResponse(w http.ResponseWriter, err error, status int, value any) {
	switch {
	case err == nil:
		write(w, status, value)
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "registered cluster was not found")
	case errors.Is(err, store.ErrForbidden):
		fail(w, http.StatusForbidden, "administrator required")
	case errors.Is(err, store.ErrConflict):
		fail(w, http.StatusConflict, err.Error())
	default:
		fail(w, http.StatusServiceUnavailable, "cluster health service unavailable; try again")
	}
}

func (s *Server) clusterHealth(w http.ResponseWriter, r *http.Request) {
	if !safeID.MatchString(r.PathValue("id")) {
		fail(w, http.StatusBadRequest, "valid cluster ID required")
		return
	}
	value, err := s.Store.GetHealth(r.Context(), r.PathValue("id"))
	healthResponse(w, err, http.StatusOK, value)
}

func (s *Server) requestHealthCheck(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decode(w, r, &body); err != nil || !safeID.MatchString(r.PathValue("id")) {
		fail(w, http.StatusBadRequest, "valid cluster ID and health-check JSON required")
		return
	}
	reason, valid := healthReason(body.Reason)
	if !valid {
		fail(w, http.StatusBadRequest, "an audit reason of 1 through 1000 bytes is required")
		return
	}
	value, err := s.Store.RequestHealthCheck(r.Context(), user(r), r.PathValue("id"), reason)
	healthResponse(w, err, http.StatusAccepted, value)
}

func (s *Server) healthProfile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Profile          model.HealthProfile `json:"profile"`
		ExpectedRevision *int64              `json:"expected_revision"`
		Reason           string              `json:"reason"`
	}
	if err := decode(w, r, &body); err != nil || !safeID.MatchString(r.PathValue("id")) || body.ExpectedRevision == nil || *body.ExpectedRevision < 1 || (body.Profile != "api-ready.v1" && body.Profile != "discovery-only.v1") {
		fail(w, http.StatusBadRequest, "valid cluster ID, profile and expected_revision are required")
		return
	}
	reason, valid := healthReason(body.Reason)
	if !valid {
		fail(w, http.StatusBadRequest, "an audit reason of 1 through 1000 bytes is required")
		return
	}
	err := s.Store.SetHealthProfile(r.Context(), user(r), r.PathValue("id"), body.Profile, *body.ExpectedRevision, reason)
	if err != nil {
		healthResponse(w, err, 0, nil)
		return
	}
	value, err := s.Store.GetHealth(r.Context(), r.PathValue("id"))
	healthResponse(w, err, http.StatusOK, value)
}
