package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ClusterConfigurationVersion captures the generation of the exact encrypted
// snapshot selected for forwarding. A concurrent edit must not pin an old
// transport to the new generation.
func (s *Store) ClusterConfigurationVersion(ctx context.Context, id string, ciphertext []byte) (int64, error) {
	var generation int64
	err := s.Pool.QueryRow(ctx, `SELECT configuration_generation FROM clusters
 WHERE id=$1 AND kubeconfig_ciphertext=$2 AND deregistered_at IS NULL`, id, ciphertext).Scan(&generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrConflict
	}
	return generation, err
}

// CheckClusterConfiguration ends streams using replaced credentials without
// changing a developer's booking, primary selection, or authentication lease.
func (s *Store) CheckClusterConfiguration(ctx context.Context, id string, generation int64) error {
	var current bool
	err := s.Pool.QueryRow(ctx, `SELECT configuration_generation=$2 FROM clusters
 WHERE id=$1 AND deregistered_at IS NULL`, id, generation).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !current {
		return ErrConflict
	}
	return err
}
