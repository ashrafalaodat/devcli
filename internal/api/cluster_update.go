package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"devctl.local/devctl/internal/kube"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
)

// decodeClusterLabels refuses null and duplicate keys instead of allowing
// encoding/json's string-map null coercion or silent last-key overwrite.
func decodeClusterLabels(raw json.RawMessage) (map[string]string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("labels and expected_labels must be JSON objects with string values")
	}
	labels := map[string]string{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, fmt.Errorf("invalid label object")
		}
		if _, duplicate := labels[key]; duplicate {
			return nil, fmt.Errorf("duplicate label key %q", key)
		}
		var value any
		if err = decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("invalid label value")
		}
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("label values must be strings, including an empty string where intended")
		}
		labels[key] = text
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return nil, fmt.Errorf("invalid label object")
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("one label object required")
	}
	return labels, nil
}

func (s *Server) maintain(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name            json.RawMessage `json:"name"`
		Maintenance     json.RawMessage `json:"maintenance"`
		MaxParticipants json.RawMessage `json:"max_participants"`
		HealthProfile   json.RawMessage `json:"health_profile"`
		ExpectedVersion json.RawMessage `json:"expected_version"`
		Kubeconfig      json.RawMessage `json:"kubeconfig"`
		Labels          json.RawMessage `json:"labels"`
		ExpectedLabels  json.RawMessage `json:"expected_labels"`
		Reason          string          `json:"reason"`
	}
	if err := decode(w, r, &request); err != nil || !safeID.MatchString(r.PathValue("id")) {
		fail(w, http.StatusBadRequest, "valid cluster ID and cluster update JSON required")
		return
	}
	reason, valid := healthReason(request.Reason)
	if !valid {
		fail(w, http.StatusBadRequest, "an audit reason of 1 through 1000 bytes is required")
		return
	}
	update := store.ClusterUpdate{}
	// Optional values must have their declared types. Explicit null is never an
	// instruction to clear a field or silently omit a credential replacement.
	var name, config string
	var maximum int
	var profile model.HealthProfile
	var version int64
	for _, field := range []struct {
		raw   json.RawMessage
		value any
		name  string
	}{{request.Name, &name, "name"}, {request.MaxParticipants, &maximum, "max_participants"}, {request.HealthProfile, &profile, "health_profile"}, {request.ExpectedVersion, &version, "expected_version"}, {request.Kubeconfig, &config, "kubeconfig"}} {
		if field.raw != nil && (bytes.Equal(bytes.TrimSpace(field.raw), []byte("null")) || json.Unmarshal(field.raw, field.value) != nil) {
			fail(w, http.StatusBadRequest, "invalid "+field.name)
			return
		}
	}
	if request.Name != nil {
		update.Name = &name
	}
	if request.MaxParticipants != nil {
		update.MaxParticipants = &maximum
	}
	if request.HealthProfile != nil {
		update.HealthProfile = &profile
	}
	if request.ExpectedVersion != nil {
		update.ExpectedVersion = &version
	}
	if request.Kubeconfig != nil {
		// Validate the version and reason before parsing any powerful credentials.
		if version < 1 || len(config) == 0 || len(config) > 1_500_000 {
			fail(w, http.StatusBadRequest, "kubeconfig replacement requires expected_version and 1 through 1500000 bytes of YAML")
			return
		}
		if err := kube.Validate([]byte(config)); err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		var err error
		update.Ciphertext, err = s.Vault.Seal(r.PathValue("id"), []byte(config))
		config = ""
		if err != nil {
			fail(w, http.StatusServiceUnavailable, "encryption unavailable")
			return
		}
	}
	if request.Maintenance != nil {
		var maintenance bool
		if bytes.Equal(bytes.TrimSpace(request.Maintenance), []byte("null")) || json.Unmarshal(request.Maintenance, &maintenance) != nil {
			fail(w, http.StatusBadRequest, "maintenance must be a boolean when provided")
			return
		}
		update.Maintenance = &maintenance
	}
	for _, field := range []struct {
		raw    json.RawMessage
		target **map[string]string
	}{{request.Labels, &update.Labels}, {request.ExpectedLabels, &update.ExpectedLabels}} {
		if field.raw == nil {
			continue
		}
		labels, err := decodeClusterLabels(field.raw)
		if err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		*field.target = &labels
	}
	if err := store.ValidateClusterUpdate(update, reason); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	err := s.Store.UpdateCluster(r.Context(), user(r), r.PathValue("id"), update, reason)
	if err != nil && !errors.Is(err, store.ErrForbidden) && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
		fail(w, http.StatusServiceUnavailable, "cluster metadata update unavailable; try again")
		return
	}
	if err != nil {
		respond(w, err, nil)
		return
	}
	s.adminCluster(w, r)
}

func (s *Server) adminCluster(w http.ResponseWriter, r *http.Request) {
	if !safeID.MatchString(r.PathValue("id")) {
		fail(w, http.StatusBadRequest, "valid cluster ID required")
		return
	}
	value, err := s.Store.AdminCluster(r.Context(), user(r), r.PathValue("id"))
	clusterAdminResponse(w, err, value)
}

// The only original-credential disclosure endpoint is an explicit, audited
// administrator operation. POST also subjects browser reads to Origin/CSRF
// validation; it never creates a download or adds credentials to team metadata.
func (s *Server) adminKubeconfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decode(w, r, &body); err != nil || !safeID.MatchString(r.PathValue("id")) {
		fail(w, http.StatusBadRequest, "valid cluster ID and audit reason JSON required")
		return
	}
	reason, valid := healthReason(body.Reason)
	if !valid {
		fail(w, http.StatusBadRequest, "an audit reason of 1 through 1000 bytes is required")
		return
	}
	value, err := s.Store.AdminKubeconfig(r.Context(), user(r), r.PathValue("id"), reason)
	if err != nil {
		clusterAdminResponse(w, err, nil)
		return
	}
	raw, err := s.Vault.Open(r.PathValue("id"), value.Ciphertext)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "stored cluster credentials unavailable")
		return
	}
	defer clear(raw)
	write(w, http.StatusOK, struct {
		Kubeconfig      string `json:"kubeconfig"`
		RegistryVersion int64  `json:"registry_version"`
	}{string(raw), value.RegistryVersion})
}

func clusterAdminResponse(w http.ResponseWriter, err error, value any) {
	if err != nil && !errors.Is(err, store.ErrForbidden) && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
		fail(w, http.StatusServiceUnavailable, "cluster registration service unavailable; try again")
		return
	}
	respond(w, err, value)
}
