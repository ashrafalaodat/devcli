package store

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	"devctl.local/devctl/internal/model"
)

// ClusterUpdate changes reservation-registry metadata, never Kubernetes labels.
// ExpectedLabels is a compare-and-swap snapshot whenever Labels is specified.
// A nil pointer omits a field; an empty map deliberately clears every label.
type ClusterUpdate struct {
	Maintenance    *bool
	Labels         *map[string]string
	ExpectedLabels *map[string]string
}

func ValidateClusterUpdate(update ClusterUpdate, reason string) error {
	if update.Maintenance == nil && update.Labels == nil {
		return fmt.Errorf("provide maintenance or labels to update")
	}
	if update.Labels == nil && update.ExpectedLabels != nil {
		return fmt.Errorf("expected_labels is valid only with labels")
	}
	if update.Labels != nil && update.ExpectedLabels == nil {
		return fmt.Errorf("expected_labels must contain the labels originally loaded before editing")
	}
	if reason = strings.TrimSpace(reason); reason == "" || len(reason) > 1000 {
		return fmt.Errorf("an audit reason of 1 through 1000 bytes is required")
	}
	if update.Labels != nil {
		// Keep registry placement labels consistent with the PAT selectors that
		// consume them, including valid empty values and Kubernetes key syntax.
		if err := model.ValidateLabels(*update.Labels); err != nil {
			return err
		}
	}
	return nil
}

func cloneClusterLabels(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels))
	maps.Copy(out, labels)
	return out
}

// UpdateCluster serializes edits with booking, PAT fallback and deregistration.
// Active reservations, identity-wide primary, PAT preferences and encrypted
// credentials are untouched. Labels affect only subsequent placement decisions.
func (s *Store) UpdateCluster(ctx context.Context, u model.Identity, id string, update ClusterUpdate, reason string) error {
	if !u.Admin {
		return ErrForbidden
	}
	if err := ValidateClusterUpdate(update, reason); err != nil {
		return fmt.Errorf("%w: %s", ErrConflict, err)
	}
	reason = strings.TrimSpace(reason)
	var desired, expected map[string]string
	if update.Labels != nil {
		desired = cloneClusterLabels(*update.Labels)
		expected = cloneClusterLabels(*update.ExpectedLabels)
	}
	return s.update(ctx, func(t *Tx) error {
		var raw []byte
		var maintenance bool
		if err := t.QueryRow(ctx, `SELECT labels,maintenance FROM clusters
 WHERE id=$1 AND deregistered_at IS NULL FOR UPDATE`, id).Scan(&raw, &maintenance); err != nil {
			return err
		}
		var previous map[string]string
		if err := json.Unmarshal(raw, &previous); err != nil {
			return err
		}
		if update.Labels != nil && !maps.Equal(previous, expected) {
			return fmt.Errorf("%w: cluster labels changed since this editor was opened; reload the current labels and review your changes", ErrConflict)
		}
		labelsChanged := update.Labels != nil && !maps.Equal(previous, desired)
		maintenanceChanged := update.Maintenance != nil && maintenance != *update.Maintenance
		if !labelsChanged && !maintenanceChanged {
			return nil
		}
		if labelsChanged {
			labelsJSON, err := json.Marshal(desired)
			if err != nil {
				return err
			}
			if _, err = t.Exec(ctx, "UPDATE clusters SET labels=$2 WHERE id=$1", id, labelsJSON); err != nil {
				return err
			}
			detail, err := json.Marshal(struct {
				Reason   string            `json:"reason"`
				Previous map[string]string `json:"previous_labels"`
				Labels   map[string]string `json:"labels"`
			}{reason, cloneClusterLabels(previous), desired})
			if err != nil {
				return err
			}
			if err = t.audit(ctx, u.Key(), "cluster_labels_update", id, string(detail)); err != nil {
				return err
			}
		}
		if maintenanceChanged {
			if _, err := t.Exec(ctx, "UPDATE clusters SET maintenance=$2 WHERE id=$1", id, *update.Maintenance); err != nil {
				return err
			}
			return t.audit(ctx, u.Key(), "maintenance", id, reason)
		}
		return nil
	})
}
