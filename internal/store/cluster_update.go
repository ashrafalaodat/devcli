package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"

	"devctl.local/devctl/internal/model"
	"github.com/jackc/pgx/v5/pgconn"
)

// ClusterUpdate edits registry configuration, never Kubernetes resources. A nil
// field is omitted. Full edits use the version originally loaded by the editor;
// older label-only clients may instead send their original label snapshot.
// Ciphertext must already have been validated and encrypted by the API.
type ClusterUpdate struct {
	Name            *string
	Maintenance     *bool
	Labels          *map[string]string
	ExpectedLabels  *map[string]string
	MaxParticipants *int
	HealthProfile   *model.HealthProfile
	Ciphertext      []byte
	ExpectedVersion *int64
}

func ValidateClusterUpdate(update ClusterUpdate, reason string) error {
	if update.Name == nil && update.Maintenance == nil && update.Labels == nil && update.MaxParticipants == nil && update.HealthProfile == nil && update.Ciphertext == nil {
		return fmt.Errorf("provide cluster fields to update")
	}
	if update.ExpectedVersion != nil && *update.ExpectedVersion < 1 {
		return fmt.Errorf("expected_version must be a positive registry version")
	}
	if update.Name != nil || update.MaxParticipants != nil || update.HealthProfile != nil || update.Ciphertext != nil {
		if update.ExpectedVersion == nil {
			return fmt.Errorf("expected_version must contain the registry version originally loaded before editing")
		}
	}
	if update.Name != nil && (strings.TrimSpace(*update.Name) == "" || len(*update.Name) > 128) {
		return fmt.Errorf("display name must contain 1 through 128 bytes")
	}
	if update.MaxParticipants != nil && (*update.MaxParticipants < 2 || *update.MaxParticipants > 10) {
		return fmt.Errorf("max_participants must be 2 through 10")
	}
	if update.HealthProfile != nil && !model.ValidHealthProfile(*update.HealthProfile) {
		return fmt.Errorf("a supported health profile is required")
	}
	if update.Ciphertext != nil && len(update.Ciphertext) == 0 {
		return fmt.Errorf("encrypted kubeconfig must not be empty")
	}
	if update.Labels == nil && update.ExpectedLabels != nil {
		return fmt.Errorf("expected_labels is valid only with labels")
	}
	if update.Labels != nil && update.ExpectedLabels == nil && update.ExpectedVersion == nil {
		return fmt.Errorf("expected_labels or expected_version must contain the labels or registry version originally loaded before editing")
	}
	if reason = strings.TrimSpace(reason); reason == "" || len(reason) > 1000 {
		return fmt.Errorf("an audit reason of 1 through 1000 bytes is required")
	}
	if update.Labels != nil {
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
// The registry-version trigger fences stale editors. Credential/profile changes
// also invalidate health observations and in-flight probes through their own
// database trigger. Existing bookings and primary selections are preserved.
func (s *Store) UpdateCluster(ctx context.Context, u model.Identity, id string, update ClusterUpdate, reason string) error {
	if !u.Admin {
		return ErrForbidden
	}
	if err := ValidateClusterUpdate(update, reason); err != nil {
		return fmt.Errorf("%w: %s", ErrConflict, err)
	}
	reason = strings.TrimSpace(reason)
	return s.update(ctx, func(t *Tx) error {
		var raw, ciphertext []byte
		var name string
		var maintenance bool
		var maximum int
		var profile model.HealthProfile
		var version int64
		if err := t.QueryRow(ctx, `SELECT name,labels,maintenance,max_participants,health_profile,kubeconfig_ciphertext,registry_version
 FROM clusters WHERE id=$1 AND deregistered_at IS NULL FOR UPDATE`, id).Scan(&name, &raw, &maintenance, &maximum, &profile, &ciphertext, &version); err != nil {
			return err
		}
		if update.ExpectedVersion != nil && version != *update.ExpectedVersion {
			return fmt.Errorf("%w: cluster changed since this editor was opened; reload the current cluster and review your changes", ErrConflict)
		}
		var previous map[string]string
		if err := json.Unmarshal(raw, &previous); err != nil {
			return err
		}
		if update.ExpectedLabels != nil && !maps.Equal(previous, *update.ExpectedLabels) {
			return fmt.Errorf("%w: cluster labels changed since this editor was opened; reload the current labels and review your changes", ErrConflict)
		}
		fields := []string{}
		if update.Name != nil && name != strings.TrimSpace(*update.Name) {
			name = strings.TrimSpace(*update.Name)
			fields = append(fields, "name")
		}
		labelsChanged := update.Labels != nil && !maps.Equal(previous, *update.Labels)
		if labelsChanged {
			var err error
			raw, err = json.Marshal(cloneClusterLabels(*update.Labels))
			if err != nil {
				return err
			}
			fields = append(fields, "labels")
		}
		maintenanceChanged := update.Maintenance != nil && maintenance != *update.Maintenance
		if maintenanceChanged {
			maintenance = *update.Maintenance
			fields = append(fields, "maintenance")
		}
		if update.MaxParticipants != nil && maximum != *update.MaxParticipants {
			var held int
			if err := t.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE cluster_id=$1 AND state='ACTIVE'", id).Scan(&held); err != nil {
				return err
			}
			if *update.MaxParticipants < held {
				return fmt.Errorf("%w: sharing limit cannot be below the number of active bookings (%d)", ErrConflict, held)
			}
			maximum = *update.MaxParticipants
			fields = append(fields, "max_participants")
		}
		profileChanged := update.HealthProfile != nil && profile != *update.HealthProfile
		if profileChanged {
			profile = *update.HealthProfile
			fields = append(fields, "health_profile")
		}
		if update.Ciphertext != nil && !bytes.Equal(ciphertext, update.Ciphertext) {
			ciphertext = update.Ciphertext
			fields = append(fields, "kubeconfig")
		}
		if len(fields) == 0 {
			return nil
		}
		_, err := t.Exec(ctx, `UPDATE clusters SET name=$2,labels=$3,maintenance=$4,max_participants=$5,
 health_profile=$6,kubeconfig_ciphertext=$7 WHERE id=$1`, id, name, raw, maintenance, maximum, profile, ciphertext)
		if err != nil {
			var constraint *pgconn.PgError
			if errors.As(err, &constraint) && constraint.Code == "23505" {
				return fmt.Errorf("%w: cluster display name is already in use", ErrConflict)
			}
			return err
		}
		// Audit field names, never old/new credential content or ciphertext.
		detail, err := json.Marshal(struct {
			Reason string   `json:"reason"`
			Fields []string `json:"fields"`
		}{reason, fields})
		if err != nil {
			return err
		}
		if err = t.audit(ctx, u.Key(), "cluster_update", id, string(detail)); err != nil {
			return err
		}
		if labelsChanged {
			detail, err := json.Marshal(struct {
				Reason   string            `json:"reason"`
				Previous map[string]string `json:"previous_labels"`
				Labels   map[string]string `json:"labels"`
			}{reason, cloneClusterLabels(previous), cloneClusterLabels(*update.Labels)})
			if err != nil {
				return err
			}
			if err = t.audit(ctx, u.Key(), "cluster_labels_update", id, string(detail)); err != nil {
				return err
			}
		}
		if profileChanged {
			if err = t.audit(ctx, u.Key(), "cluster_health_profile", id, "profile updated through cluster editor; reason: "+reason); err != nil {
				return err
			}
		}
		if maintenanceChanged {
			return t.audit(ctx, u.Key(), "maintenance", id, reason)
		}
		return nil
	})
}

// AdminCluster reads live registry metadata without expiring or renewing bookings.
// The original kubeconfig is deliberately loaded through a separate audited call.
func (s *Store) AdminCluster(ctx context.Context, u model.Identity, id string) (model.Cluster, error) {
	var out model.Cluster
	if !u.Admin {
		return out, ErrForbidden
	}
	err := s.update(ctx, func(t *Tx) error {
		var err error
		out, err = t.cluster(ctx, id)
		if err == nil && out.DeregisteredAt != nil {
			return ErrNotFound
		}
		return err
	})
	return out, err
}

type AdminClusterConfig struct {
	Ciphertext      []byte `json:"-"`
	RegistryVersion int64  `json:"registry_version"`
}

// AdminKubeconfig is an explicit, audited administrative credential disclosure.
// Decryption stays in the API; normal metadata and developer APIs never call it.
func (s *Store) AdminKubeconfig(ctx context.Context, u model.Identity, id, reason string) (AdminClusterConfig, error) {
	var out AdminClusterConfig
	if !u.Admin {
		return out, ErrForbidden
	}
	if reason = strings.TrimSpace(reason); reason == "" || len(reason) > 1000 {
		return out, fmt.Errorf("%w: an audit reason of 1 through 1000 bytes is required", ErrConflict)
	}
	err := s.update(ctx, func(t *Tx) error {
		if err := t.QueryRow(ctx, `SELECT kubeconfig_ciphertext,registry_version FROM clusters
 WHERE id=$1 AND deregistered_at IS NULL FOR UPDATE`, id).Scan(&out.Ciphertext, &out.RegistryVersion); err != nil {
			return err
		}
		return t.audit(ctx, u.Key(), "cluster_kubeconfig_view", id, "administrator viewed stored kubeconfig; reason: "+reason)
	})
	return out, err
}
