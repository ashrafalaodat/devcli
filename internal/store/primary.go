package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"devctl.local/devctl/internal/model"
	"github.com/jackc/pgx/v5"
)

var ErrBookingLimit = errors.New("developer booking limit reached")
var ErrNoPrimary = errors.New("no cluster is booked")

func (t *Tx) ensureDeveloper(ctx context.Context, u model.Identity) error {
	raw, err := json.Marshal(u)
	if err != nil {
		return err
	}
	_, err = t.Exec(ctx, "INSERT INTO developers(owner_id,identity) VALUES($1,$2) ON CONFLICT DO NOTHING", u.Key(), raw)
	return err
}

func (t *Tx) observeIdentity(ctx context.Context, u model.Identity) error {
	raw, err := json.Marshal(u)
	if err != nil {
		return err
	}
	_, err = t.Exec(ctx, "INSERT INTO developers(owner_id,identity) VALUES($1,$2) ON CONFLICT(owner_id) DO UPDATE SET identity=EXCLUDED.identity", u.Key(), raw)
	return err
}

func (s *Store) ObserveIdentity(ctx context.Context, u model.Identity) error {
	return s.update(ctx, func(t *Tx) error { return t.observeIdentity(ctx, u) })
}

// repairPrimary preserves a valid current selection and otherwise promotes the
// oldest remaining active booking. Every actual change revokes old streams by
// advancing the durable selection version and clearing its OAuth lease.
func (t *Tx) repairPrimary(ctx context.Context, owner string) error {
	var current string
	err := t.QueryRow(ctx, "SELECT COALESCE(primary_session_id,'') FROM developers WHERE owner_id=$1", owner).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var valid bool
	if err = t.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM sessions WHERE id=$1 AND owner_id=$2 AND state='ACTIVE' AND (expires_at IS NULL OR expires_at>clock_timestamp()))", current, owner).Scan(&valid); err != nil {
		return err
	}
	if valid {
		return nil
	}
	var next string
	err = t.QueryRow(ctx, "SELECT id FROM sessions WHERE owner_id=$1 AND state='ACTIVE' AND (expires_at IS NULL OR expires_at>clock_timestamp()) ORDER BY created_at,id LIMIT 1", owner).Scan(&next)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if current == next {
		return nil
	}
	_, err = t.Exec(ctx, "UPDATE developers SET primary_session_id=NULLIF($2,''),selection_version=selection_version+1,authorization_expires_at=NULL,authorization_version=NULL WHERE owner_id=$1", owner, next)
	return err
}

func (t *Tx) profile(ctx context.Context, u model.Identity) (model.DeveloperProfile, error) {
	var p model.DeveloperProfile
	if err := t.ensureDeveloper(ctx, u); err != nil {
		return p, err
	}
	if err := t.repairPrimary(ctx, u.Key()); err != nil {
		return p, err
	}
	var raw []byte
	var primary string
	err := t.QueryRow(ctx, `SELECT d.owner_id,d.identity,COALESCE(d.max_bookings_override,a.default_max_bookings),d.max_bookings_override,
 COALESCE(d.primary_session_id,''),d.selection_version
 FROM developers d CROSS JOIN application_settings a WHERE d.owner_id=$1`, u.Key()).Scan(&p.OwnerID, &raw, &p.MaxBookings, &p.MaxBookingsOverride, &primary, &p.SelectionVersion)
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal(raw, &p.User); err != nil {
		return p, err
	}
	ss, err := t.sessions(ctx)
	if err != nil {
		return p, err
	}
	for _, session := range ss {
		if session.Owner == u.Key() && session.State == "ACTIVE" {
			p.ActiveBookings++
			if session.ID == primary {
				v := session
				p.PrimarySession = &v
			}
		}
	}
	return p, nil
}

func (s *Store) Profile(ctx context.Context, u model.Identity) (model.DeveloperProfile, error) {
	var p model.DeveloperProfile
	err := s.update(ctx, func(t *Tx) error {
		if err := t.observeIdentity(ctx, u); err != nil {
			return err
		}
		if err := t.expire(ctx); err != nil {
			return err
		}
		var err error
		p, err = t.profile(ctx, u)
		return err
	})
	return p, err
}

func (s *Store) Developers(ctx context.Context, admin model.Identity) ([]model.DeveloperProfile, error) {
	if !admin.Admin {
		return nil, ErrForbidden
	}
	out := []model.DeveloperProfile{}
	err := s.update(ctx, func(t *Tx) error {
		if err := t.expire(ctx); err != nil {
			return err
		}
		rows, err := t.Query(ctx, "SELECT identity FROM developers ORDER BY owner_id")
		if err != nil {
			return err
		}
		users := []model.Identity{}
		for rows.Next() {
			var raw []byte
			var u model.Identity
			if err = rows.Scan(&raw); err != nil {
				rows.Close()
				return err
			}
			if err = json.Unmarshal(raw, &u); err != nil {
				rows.Close()
				return err
			}
			users = append(users, u)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, u := range users {
			p, err := t.profile(ctx, u)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

func (s *Store) Settings(ctx context.Context, u model.Identity) (model.Settings, error) {
	var v model.Settings
	if !u.Admin {
		return v, ErrForbidden
	}
	var seconds int
	err := s.Pool.QueryRow(ctx, "SELECT default_max_bookings,inactivity_grace_seconds FROM application_settings WHERE singleton").Scan(&v.DefaultMaxBookings, &seconds)
	v.InactivityGracePeriod = (time.Duration(seconds) * time.Second).String()
	return v, err
}

func validLimitReason(max int, reason string) error {
	if max < 1 || max > 100 {
		return fmt.Errorf("%w: booking limit must be 1 through 100", ErrConflict)
	}
	if strings.TrimSpace(reason) == "" || len(reason) > 1000 {
		return fmt.Errorf("%w: an audit reason of 1 through 1000 bytes is required", ErrConflict)
	}
	return nil
}

func (s *Store) UpdateSettings(ctx context.Context, admin model.Identity, max int, reason string) error {
	return s.UpdateReservationPolicy(ctx, admin, &max, nil, reason)
}

// UpdateReservationPolicy applies partial patches under the same durable lock as
// booking, activity and expiry. Omitted settings cannot overwrite concurrent edits.
func (s *Store) UpdateReservationPolicy(ctx context.Context, admin model.Identity, max *int, grace *time.Duration, reason string) error {
	if !admin.Admin {
		return ErrForbidden
	}
	value := 1
	if max != nil {
		value = *max
	}
	if err := validLimitReason(value, reason); err != nil {
		return err
	}
	if max == nil && grace == nil {
		return fmt.Errorf("%w: supply a booking limit or inactivity grace period", ErrConflict)
	}
	if grace != nil && (*grace < time.Minute || *grace > 168*time.Hour || *grace%time.Second != 0) {
		return fmt.Errorf("%w: inactivity grace period must be whole seconds between 1m and 168h", ErrConflict)
	}
	return s.update(ctx, func(t *Tx) error {
		// Expire against the current policy first. A larger grace period must
		// never resurrect a booking whose inactivity deadline already passed.
		if err := t.expire(ctx); err != nil {
			return err
		}
		if max != nil {
			if _, err := t.Exec(ctx, "UPDATE application_settings SET default_max_bookings=$1 WHERE singleton", *max); err != nil {
				return err
			}
			if err := t.audit(ctx, admin.Key(), "booking_default_limit", "settings", fmt.Sprintf("default maximum bookings set to %d; existing bookings retained; reason: %s", *max, reason)); err != nil {
				return err
			}
		}
		if grace != nil {
			seconds := int64(*grace / time.Second)
			if _, err := t.Exec(ctx, "UPDATE application_settings SET inactivity_grace_seconds=$1 WHERE singleton", seconds); err != nil {
				return err
			}
			if _, err := t.Exec(ctx, `UPDATE sessions SET expires_at=GREATEST(created_at,idle_anchor_at,last_activity_at)+make_interval(secs=>$1) WHERE state='ACTIVE'`, seconds); err != nil {
				return err
			}
			if err := t.audit(ctx, admin.Key(), "inactivity_grace_period", "settings", fmt.Sprintf("inactivity grace period set to %s for current and future bookings; reason: %s", grace.String(), reason)); err != nil {
				return err
			}
			return t.expire(ctx)
		}
		return nil
	})
}

func (s *Store) UpdateDeveloperLimit(ctx context.Context, admin model.Identity, owner string, max *int, reason string) error {
	if !admin.Admin {
		return ErrForbidden
	}
	value := 1
	if max != nil {
		value = *max
	}
	if err := validLimitReason(value, reason); err != nil {
		return err
	}
	return s.update(ctx, func(t *Tx) error {
		r, err := t.Exec(ctx, "UPDATE developers SET max_bookings_override=$2 WHERE owner_id=$1", owner, max)
		if err != nil {
			return err
		}
		if r.RowsAffected() != 1 {
			return ErrNotFound
		}
		detail := "reset maximum bookings to organisation default"
		if max != nil {
			detail = fmt.Sprintf("maximum bookings set to %d", *max)
		}
		return t.audit(ctx, admin.Key(), "developer_booking_limit", owner, detail+"; existing bookings retained; reason: "+reason)
	})
}

func (s *Store) SelectPrimary(ctx context.Context, u model.Identity, target string) (model.DeveloperProfile, error) {
	var out model.DeveloperProfile
	err := s.update(ctx, func(t *Tx) error {
		if err := t.observeIdentity(ctx, u); err != nil {
			return err
		}
		if err := t.expire(ctx); err != nil {
			return err
		}
		var id string
		err := t.QueryRow(ctx, `SELECT s.id FROM sessions s JOIN clusters c ON c.id=s.cluster_id
 WHERE s.owner_id=$1 AND s.state='ACTIVE' AND c.deregistered_at IS NULL AND (s.expires_at IS NULL OR s.expires_at>clock_timestamp())
		 AND (s.id=$2 OR c.id=$2 OR c.name=$2)
 ORDER BY CASE WHEN s.id=$2 THEN 0 WHEN c.id=$2 THEN 1 ELSE 2 END,s.created_at,s.id LIMIT 1`, u.Key(), target).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: select an active cluster that you have booked", ErrForbidden)
		}
		if err != nil {
			return err
		}
		r, err := t.Exec(ctx, "UPDATE developers SET primary_session_id=$2,selection_version=selection_version+1,authorization_expires_at=NULL,authorization_version=NULL WHERE owner_id=$1 AND primary_session_id IS DISTINCT FROM $2", u.Key(), id)
		if err != nil {
			return err
		}
		if r.RowsAffected() > 0 {
			if err = t.audit(ctx, u.Key(), "primary_select", id, "developer changed primary cluster; existing gateway streams revoked"); err != nil {
				return err
			}
		}
		out, err = t.profile(ctx, u)
		if err == nil {
			_, err = t.recordPrimaryActivity(ctx, u, id, out.SelectionVersion)
		}
		if err == nil {
			out, err = t.profile(ctx, u)
		}
		return err
	})
	return out, err
}

func (t *Tx) primary(ctx context.Context, u model.Identity) (model.Session, int64, error) {
	p, err := t.profile(ctx, u)
	if err != nil {
		return model.Session{}, 0, err
	}
	if p.PrimarySession == nil {
		return model.Session{}, p.SelectionVersion, ErrNoPrimary
	}
	return *p.PrimarySession, p.SelectionVersion, nil
}

func (s *Store) Primary(ctx context.Context, u model.Identity) (model.Session, int64, error) {
	var session model.Session
	var version int64
	var resultErr error
	err := s.update(ctx, func(t *Tx) error {
		if err := t.expire(ctx); err != nil {
			return err
		}
		session, version, resultErr = t.primary(ctx, u)
		// Expiry and clearing the last primary remain durable even when the
		// caller receives the expected no-booking response.
		if errors.Is(resultErr, ErrNoPrimary) {
			return nil
		}
		return resultErr
	})
	if err == nil {
		err = resultErr
	}
	return session, version, err
}

func (s *Store) PrimaryConfig(ctx context.Context, u model.Identity) (model.Session, int64, string, []byte, error) {
	var session model.Session
	var version int64
	var encrypted []byte
	var resultErr error
	err := s.update(ctx, func(t *Tx) error {
		if err := t.expire(ctx); err != nil {
			return err
		}
		session, version, resultErr = t.primary(ctx, u)
		if errors.Is(resultErr, ErrNoPrimary) {
			return nil
		}
		if resultErr != nil {
			return resultErr
		}
		session, resultErr = t.recordPrimaryActivity(ctx, u, session.ID, version)
		if resultErr != nil {
			return resultErr
		}
		if err := t.QueryRow(ctx, "SELECT kubeconfig_ciphertext FROM clusters WHERE id=$1 AND deregistered_at IS NULL", session.Cluster).Scan(&encrypted); err != nil {
			return err
		}
		return t.audit(ctx, u.Key(), "gateway", session.ID, "loaded current primary upstream credentials for server-side forwarding")
	})
	if err == nil {
		err = resultErr
	}
	return session, version, session.Cluster, encrypted, err
}

func (s *Store) CheckPrimaryAccess(ctx context.Context, u model.Identity, sessionID string, version int64) error {
	var allowed bool
	err := s.Pool.QueryRow(ctx, `SELECT d.selection_version=$3 AND s.owner_id=$1 AND s.state='ACTIVE'
 AND (s.expires_at IS NULL OR s.expires_at>clock_timestamp()) FROM developers d
 JOIN sessions s ON s.id=d.primary_session_id WHERE d.owner_id=$1 AND s.id=$2`, u.Key(), sessionID, version).Scan(&allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if !allowed {
		return ErrConflict
	}
	return nil
}
