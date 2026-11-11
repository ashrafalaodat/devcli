package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"devctl.local/devctl/internal/model"
)

func populateCluster(c *model.Cluster, sessions []model.Session) {
	c.Participants = []model.Session{}
	for _, session := range sessions {
		if session.Cluster == c.ID && session.State == "ACTIVE" {
			c.Participants = append(c.Participants, session)
		}
	}
	c.Available = c.DeregisteredAt == nil && !c.Maintenance && (len(c.Participants) == 0 || c.Shareable && len(c.Participants) < c.MaxParticipants)
	switch {
	case c.DeregisteredAt != nil:
		c.Reason = "deregistered; stored Kubernetes credentials removed; booking history retained"
	case c.Maintenance:
		c.Reason = "maintenance: new bookings disabled"
	case len(c.Participants) == 0:
		c.Reason = "available for exclusive booking"
	case c.Shareable && c.Available:
		c.Reason = "holder enabled sharing; co-users and their contact details are visible"
	case c.Shareable:
		c.Reason = "sharing participant limit reached"
	default:
		c.Reason = "reserved exclusively; holder may enable sharing"
	}
}

// Cluster provides only public metadata, including archived identity for booking
// history. Registry/placement snapshots intentionally exclude archived clusters.
func (s *Store) Cluster(ctx context.Context, id string) (model.Cluster, error) {
	var c model.Cluster
	err := s.update(ctx, func(t *Tx) error {
		if err := t.expire(ctx); err != nil {
			return err
		}
		var raw []byte
		err := t.QueryRow(ctx, `SELECT id,name,labels,maintenance,COALESCE(controller_session,''),
 shareable,max_participants,deregistered_at FROM clusters WHERE id=$1`, id).Scan(
			&c.ID, &c.Name, &raw, &c.Maintenance, &c.ControllerSession, &c.Shareable, &c.MaxParticipants, &c.DeregisteredAt)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &c.Labels); err != nil {
			return err
		}
		sessions, err := t.sessions(ctx)
		if err != nil {
			return err
		}
		populateCluster(&c, sessions)
		return nil
	})
	return c, err
}

// Deregister erases the stored credential and removes a cluster from placement.
// It never contacts Kubernetes or ends active reservations. The metadata row is
// retained so historical sessions, idempotency records and audits keep their
// original cluster identity; an archived ID cannot later refer to a new cluster.
func (s *Store) Deregister(ctx context.Context, u model.Identity, id, reason string) error {
	if !u.Admin {
		return ErrForbidden
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 1000 {
		return fmt.Errorf("%w: an audit reason of 1 through 1000 bytes is required", ErrConflict)
	}
	return s.update(ctx, func(t *Tx) error {
		if err := t.expire(ctx); err != nil {
			return err
		}
		var archived *time.Time
		if err := t.QueryRow(ctx, "SELECT deregistered_at FROM clusters WHERE id=$1", id).Scan(&archived); err != nil {
			return err
		}
		if archived != nil {
			return nil
		}
		var held int
		if err := t.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE cluster_id=$1 AND state='ACTIVE'", id).Scan(&held); err != nil {
			return err
		}
		if held != 0 {
			return fmt.Errorf("%w: cluster has %d active booking(s); release all bookings before deregistering", ErrConflict, held)
		}
		_, err := t.Exec(ctx, `UPDATE clusters SET deregistered_at=clock_timestamp(),
 kubeconfig_ciphertext=NULL,maintenance=true,controller_session=NULL,shareable=false WHERE id=$1`, id)
		if err != nil {
			return err
		}
		return t.audit(ctx, u.Key(), "deregister", id, "removed stored Kubernetes credentials and placement entry; booking history retained; no Kubernetes API calls; reason: "+reason)
	})
}
