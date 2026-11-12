package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

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
		Maintenance    json.RawMessage `json:"maintenance"`
		Labels         json.RawMessage `json:"labels"`
		ExpectedLabels json.RawMessage `json:"expected_labels"`
		Reason         string          `json:"reason"`
	}
	if err := decode(w, r, &request); err != nil || !safeID.MatchString(r.PathValue("id")) {
		fail(w, http.StatusBadRequest, "valid cluster ID and cluster update JSON required")
		return
	}
	update := store.ClusterUpdate{}
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
	reason := strings.TrimSpace(request.Reason)
	if err := store.ValidateClusterUpdate(update, reason); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	err := s.Store.UpdateCluster(r.Context(), user(r), r.PathValue("id"), update, reason)
	if err != nil && !errors.Is(err, store.ErrForbidden) && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
		fail(w, http.StatusServiceUnavailable, "cluster metadata update unavailable; try again")
		return
	}
	respond(w, err, map[string]string{"status": "updated"})
}
