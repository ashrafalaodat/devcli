package store

import (
	"context"
	"crypto/sha256"
	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/scheduler"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

//go:embed schema.sql
var schema string
var ErrConflict = errors.New("reservation conflict")
var ErrForbidden = errors.New("session belongs to another user")
var ErrNotFound = pgx.ErrNoRows
var ErrKey = errors.New("idempotency key was already used with different parameters")

type Store struct{ Pool *pgxpool.Pool }
type Tx struct{ pgx.Tx }

func Open(ctx context.Context, url string) (*Store, error) {
	p, e := pgxpool.New(ctx, url)
	if e != nil {
		return nil, e
	}
	s := &Store{p}
	if e = s.update(ctx, func(t *Tx) error { _, e := t.Exec(ctx, schema); return e }); e != nil {
		p.Close()
		return nil, e
	}
	return s, nil
}

// All reservation mutations use a database-backed lock, including across servers.
func (s *Store) update(ctx context.Context, fn func(*Tx) error) error {
	t, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer t.Rollback(ctx)
	if _, e = t.Exec(ctx, "SELECT pg_advisory_xact_lock(44738101)"); e != nil {
		return e
	}
	if e = fn(&Tx{t}); e != nil {
		return e
	}
	return t.Commit(ctx)
}
func (t *Tx) now(ctx context.Context) (time.Time, error) {
	var now time.Time
	e := t.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now)
	return now.UTC(), e
}
func (t *Tx) audit(ctx context.Context, actor, action, id, detail string) error {
	_, e := t.Exec(ctx, "INSERT INTO audit(actor,action,object_id,detail) VALUES($1,$2,$3,$4)", actor, action, id, detail)
	return e
}
func (s *Store) Audit(ctx context.Context, actor, action, id, detail string) error {
	return s.update(ctx, func(t *Tx) error { return t.audit(ctx, actor, action, id, detail) })
}
func (t *Tx) sessions(ctx context.Context) ([]model.Session, error) {
	rows, e := t.Query(ctx, "SELECT s.id,s.owner_id,s.identity,s.cluster_id,s.state,s.created_at,s.ended_at,s.expires_at,s.last_activity_at,s.reason,COALESCE(d.primary_session_id=s.id,false) FROM sessions s LEFT JOIN developers d ON d.owner_id=s.owner_id ORDER BY s.created_at,s.id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.Session{}
	for rows.Next() {
		var v model.Session
		var raw []byte
		if e = rows.Scan(&v.ID, &v.Owner, &raw, &v.Cluster, &v.State, &v.CreatedAt, &v.EndedAt, &v.ExpiresAt, &v.LastActivityAt, &v.Reason, &v.Primary); e != nil {
			return nil, e
		}
		var u model.Identity
		if e = json.Unmarshal(raw, &u); e != nil {
			return nil, e
		}
		v.Name = u.Name
		v.DisplayName = u.DisplayName
		v.Email = u.Email
		out = append(out, v)
	}
	return out, rows.Err()
}
func (t *Tx) clusters(ctx context.Context, ss []model.Session) ([]model.Cluster, error) {
	rows, e := t.Query(ctx, "SELECT id,name,labels,maintenance,COALESCE(controller_session,''),shareable,max_participants FROM clusters ORDER BY id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.Cluster{}
	for rows.Next() {
		var c model.Cluster
		var raw []byte
		if e = rows.Scan(&c.ID, &c.Name, &raw, &c.Maintenance, &c.ControllerSession, &c.Shareable, &c.MaxParticipants); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(raw, &c.Labels); e != nil {
			return nil, e
		}
		c.Participants = []model.Session{}
		for _, s := range ss {
			if s.Cluster == c.ID && s.State == "ACTIVE" {
				c.Participants = append(c.Participants, s)
			}
		}
		c.Available = !c.Maintenance && (len(c.Participants) == 0 || c.Shareable && len(c.Participants) < c.MaxParticipants)
		switch {
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
		out = append(out, c)
	}
	return out, rows.Err()
}

// When the controller leaves, the oldest participant becomes controller. Sharing
// resets to private; remaining bookings are never evicted.
func (t *Tx) repair(ctx context.Context, cluster string) error {
	var controller string
	e := t.QueryRow(ctx, "SELECT COALESCE(controller_session,'') FROM clusters WHERE id=$1", cluster).Scan(&controller)
	if e != nil {
		return e
	}
	var valid bool
	e = t.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM sessions WHERE id=$1 AND cluster_id=$2 AND state='ACTIVE')", controller, cluster).Scan(&valid)
	if e != nil || valid {
		return e
	}
	var next string
	e = t.QueryRow(ctx, "SELECT id FROM sessions WHERE cluster_id=$1 AND state='ACTIVE' ORDER BY created_at,id LIMIT 1", cluster).Scan(&next)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	_, e = t.Exec(ctx, "UPDATE clusters SET controller_session=NULLIF($2,''),shareable=false WHERE id=$1", cluster, next)
	return e
}
func (t *Tx) expire(ctx context.Context) error {
	rows, e := t.Query(ctx, "UPDATE sessions SET state='EXPIRED',ended_at=clock_timestamp(),reason='optional lease expired; gateway requests denied; legacy credentials are not revoked' WHERE state='ACTIVE' AND expires_at<=clock_timestamp() RETURNING id,cluster_id,owner_id")
	if e != nil {
		return e
	}
	type item struct{ id, cluster, owner string }
	items := []item{}
	for rows.Next() {
		var v item
		if e = rows.Scan(&v.id, &v.cluster, &v.owner); e != nil {
			rows.Close()
			return e
		}
		items = append(items, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, v := range items {
		if e = t.repairPrimary(ctx, v.owner); e != nil {
			return e
		}
		if e = t.repair(ctx, v.cluster); e != nil {
			return e
		}
		if e = t.audit(ctx, "system", "expire", v.id, "booking released; no Kubernetes mutation or credential revocation"); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) Expire(ctx context.Context) error {
	return s.update(ctx, func(t *Tx) error { return t.expire(ctx) })
}
func (s *Store) Snapshot(ctx context.Context) ([]model.Cluster, []model.Session, error) {
	var cs []model.Cluster
	var ss []model.Session
	e := s.update(ctx, func(t *Tx) error {
		if e := t.expire(ctx); e != nil {
			return e
		}
		var e error
		ss, e = t.sessions(ctx)
		if e != nil {
			return e
		}
		cs, e = t.clusters(ctx, ss)
		return e
	})
	return cs, ss, e
}
func (s *Store) Book(ctx context.Context, u model.Identity, b model.Booking, key string) (model.Session, bool, error) {
	var out model.Session
	var created bool
	err := s.update(ctx, func(t *Tx) error {
		var err error
		out, created, err = t.book(ctx, u, b, key)
		return err
	})
	return out, created, err
}

func bookingHash(b model.Booking) string {
	raw, _ := json.Marshal(b)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func (t *Tx) book(ctx context.Context, u model.Identity, b model.Booking, key string) (model.Session, bool, error) {
	var out model.Session
	created := false
	hash := bookingHash(b)
	err := func() error {
		if e := t.expire(ctx); e != nil {
			return e
		}
		var previous, oldhash string
		e := t.QueryRow(ctx, "SELECT session_id,request_hash FROM booking_keys WHERE owner_id=$1 AND key=$2", u.Key(), key).Scan(&previous, &oldhash)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		ss, e2 := t.sessions(ctx)
		if e2 != nil {
			return e2
		}
		if e == nil {
			if hash != oldhash {
				return ErrKey
			}
			for _, v := range ss {
				if v.ID == previous {
					out = v
					return nil
				}
			}
			return ErrNotFound
		}
		if e := t.observeIdentity(ctx, u); e != nil {
			return e
		}
		var limit, held int
		if e := t.QueryRow(ctx, "SELECT COALESCE(d.max_bookings_override,a.default_max_bookings),(SELECT count(*) FROM sessions WHERE owner_id=$1 AND state='ACTIVE') FROM developers d CROSS JOIN application_settings a WHERE d.owner_id=$1", u.Key()).Scan(&limit, &held); e != nil {
			return e
		}
		if held >= limit {
			return fmt.Errorf("%w: you hold %d of %d allowed clusters", ErrBookingLimit, held, limit)
		}
		cs, e := t.clusters(ctx, ss)
		if e != nil {
			return e
		}
		c, e := scheduler.Pick(cs, b)
		if e != nil {
			return e
		}
		for _, v := range c.Participants {
			if v.Owner == u.Key() {
				return errors.New("you already have an active booking on this cluster")
			}
		}
		now, e := t.now(ctx)
		if e != nil {
			return e
		}
		out = model.Session{ID: "s-" + uuid.NewString(), Owner: u.Key(), Name: u.Name, DisplayName: u.DisplayName, Email: u.Email, Cluster: c.ID, State: "ACTIVE", CreatedAt: now, Reason: "exclusive cluster booking; no Kubernetes resources are changed"}
		if len(c.Participants) > 0 {
			out.Reason = "joined holder-approved shared booking; coordinate manually with listed participants"
		}
		if b.TTL != "" {
			ttl, e := time.ParseDuration(b.TTL)
			if e != nil || ttl < time.Minute || ttl > 7*24*time.Hour {
				return errors.New("TTL must be between 1m and 168h")
			}
			end := now.Add(ttl)
			out.ExpiresAt = &end
		}
		identity, _ := json.Marshal(u)
		_, e = t.Exec(ctx, "INSERT INTO sessions(id,owner_id,identity,cluster_id,state,created_at,expires_at,reason) VALUES($1,$2,$3,$4,'ACTIVE',$5,$6,$7)", out.ID, out.Owner, identity, out.Cluster, out.CreatedAt, out.ExpiresAt, out.Reason)
		if e != nil {
			return e
		}
		if len(c.Participants) == 0 {
			if _, e = t.Exec(ctx, "UPDATE clusters SET controller_session=$2,shareable=false WHERE id=$1", c.ID, out.ID); e != nil {
				return e
			}
		}
		if _, e = t.Exec(ctx, "INSERT INTO booking_keys VALUES($1,$2,$3,$4)", u.Key(), key, hash, out.ID); e != nil {
			return e
		}
		if e = t.repairPrimary(ctx, u.Key()); e != nil {
			return e
		}
		if e = t.QueryRow(ctx, "SELECT primary_session_id=$2 FROM developers WHERE owner_id=$1", u.Key(), out.ID).Scan(&out.Primary); e != nil {
			return e
		}
		created = true
		return t.audit(ctx, u.Key(), "book", out.ID, out.Reason)
	}()
	return out, created, err
}
func (s *Store) Share(ctx context.Context, u model.Identity, id string, on bool) error {
	return s.update(ctx, func(t *Tx) error {
		if e := t.expire(ctx); e != nil {
			return e
		}
		var owner, cluster, state string
		e := t.QueryRow(ctx, "SELECT owner_id,cluster_id,state FROM sessions WHERE id=$1", id).Scan(&owner, &cluster, &state)
		if e != nil {
			return e
		}
		if owner != u.Key() {
			return ErrForbidden
		}
		if state != "ACTIVE" {
			return ErrConflict
		}
		var controller string
		if e = t.QueryRow(ctx, "SELECT COALESCE(controller_session,'') FROM clusters WHERE id=$1", cluster).Scan(&controller); e != nil {
			return e
		}
		if controller != id {
			return errors.New("only the controlling holder can change sharing")
		}
		if _, e = t.Exec(ctx, "UPDATE clusters SET shareable=$2 WHERE id=$1", cluster, on); e != nil {
			return e
		}
		detail := "disabled new shared bookings; existing bookings retained"
		if on {
			detail = "enabled shared bookings and participant contact visibility"
		}
		return t.audit(ctx, u.Key(), "share", id, detail)
	})
}
func (t *Tx) stop(ctx context.Context, u model.Identity, id, reason string, force bool) error {
	var owner, cluster, state string
	e := t.QueryRow(ctx, "SELECT owner_id,cluster_id,state FROM sessions WHERE id=$1", id).Scan(&owner, &cluster, &state)
	if e != nil {
		return e
	}
	if owner != u.Key() && !(force && u.Admin) {
		return ErrForbidden
	}
	if state != "ACTIVE" {
		return nil
	}
	if _, e = t.Exec(ctx, "UPDATE sessions SET state='RELEASED',ended_at=clock_timestamp(),reason=$2 WHERE id=$1", id, reason); e != nil {
		return e
	}
	if e = t.repairPrimary(ctx, owner); e != nil {
		return e
	}
	if e = t.repair(ctx, cluster); e != nil {
		return e
	}
	return t.audit(ctx, u.Key(), "release", id, reason)
}
func (s *Store) Stop(ctx context.Context, u model.Identity, id, reason string, force bool) error {
	return s.update(ctx, func(t *Tx) error { return t.stop(ctx, u, id, reason, force) })
}
func (s *Store) Logout(ctx context.Context, u model.Identity) error {
	return s.update(ctx, func(t *Tx) error {
		ss, e := t.sessions(ctx)
		if e != nil {
			return e
		}
		for _, v := range ss {
			if v.Owner == u.Key() && v.State == "ACTIVE" {
				if e = t.stop(ctx, u, v.ID, "logout released booking; gateway requests denied; legacy credential copies are not revoked", false); e != nil {
					return e
				}
			}
		}
		return t.audit(ctx, u.Key(), "logout", u.Key(), "released all bookings; personal gateway credentials preserved")
	})
}
func (s *Store) Renew(ctx context.Context, u model.Identity, id string, ttl time.Duration) error {
	return s.update(ctx, func(t *Tx) error {
		if e := t.expire(ctx); e != nil {
			return e
		}
		var owner, state string
		var old *time.Time
		e := t.QueryRow(ctx, "SELECT owner_id,state,expires_at FROM sessions WHERE id=$1", id).Scan(&owner, &state, &old)
		if e != nil {
			return e
		}
		if owner != u.Key() {
			return ErrForbidden
		}
		if state != "ACTIVE" {
			return ErrConflict
		}
		if old == nil {
			return errors.New("session already has no expiry")
		}
		if ttl < time.Minute || ttl > 7*24*time.Hour {
			return errors.New("TTL must be between 1m and 168h")
		}
		now, e := t.now(ctx)
		if e != nil {
			return e
		}
		end := now.Add(ttl)
		if !end.After(*old) {
			return errors.New("renewal must extend expiry")
		}
		if _, e = t.Exec(ctx, "UPDATE sessions SET expires_at=$2 WHERE id=$1", id, end); e != nil {
			return e
		}
		return t.audit(ctx, u.Key(), "renew", id, ttl.String())
	})
}
func (s *Store) Register(ctx context.Context, u model.Identity, c model.Cluster, ciphertext []byte) error {
	if !u.Admin {
		return ErrForbidden
	}
	return s.update(ctx, func(t *Tx) error {
		labels, e := json.Marshal(c.Labels)
		if e != nil {
			return e
		}
		if _, e = t.Exec(ctx, "INSERT INTO clusters(id,name,labels,kubeconfig_ciphertext,max_participants) VALUES($1,$2,$3,$4,$5)", c.ID, c.Name, labels, ciphertext, c.MaxParticipants); e != nil {
			return errors.New("cluster ID or name already registered")
		}
		return t.audit(ctx, u.Key(), "register", c.ID, "encrypted static kubeconfig imported; no Kubernetes API calls")
	})
}
func (s *Store) Maintain(ctx context.Context, u model.Identity, id string, on bool, reason string) error {
	if !u.Admin {
		return ErrForbidden
	}
	return s.update(ctx, func(t *Tx) error {
		tag, e := t.Exec(ctx, "UPDATE clusters SET maintenance=$2 WHERE id=$1", id, on)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return t.audit(ctx, u.Key(), "maintenance", id, reason)
	})
}

// Config is server-internal: the encrypted upstream credentials must never be
// returned by an API response or written to a developer machine.
func (s *Store) Config(ctx context.Context, u model.Identity, id string) (string, []byte, error) {
	var cluster string
	var encrypted []byte
	e := s.update(ctx, func(t *Tx) error {
		if e := t.expire(ctx); e != nil {
			return e
		}
		var owner, state string
		e := t.QueryRow(ctx, "SELECT owner_id,cluster_id,state FROM sessions WHERE id=$1", id).Scan(&owner, &cluster, &state)
		if e != nil {
			return e
		}
		if owner != u.Key() {
			return ErrForbidden
		}
		if state != "ACTIVE" {
			return ErrConflict
		}
		if e = t.QueryRow(ctx, "SELECT kubeconfig_ciphertext FROM clusters WHERE id=$1", cluster).Scan(&encrypted); e != nil {
			return e
		}
		return t.audit(ctx, u.Key(), "gateway", id, "loaded upstream credentials for server-side forwarding; no credentials delivered")
	})
	return cluster, encrypted, e
}

// Access checks the committed lease without returning cluster credentials. It is
// also used by long-lived gateway streams; no transaction is held while proxying.
func (s *Store) Access(ctx context.Context, u model.Identity, id string) error {
	var owner, state string
	var unexpired bool
	e := s.Pool.QueryRow(ctx, "SELECT owner_id,state,(expires_at IS NULL OR expires_at>clock_timestamp()) FROM sessions WHERE id=$1", id).Scan(&owner, &state, &unexpired)
	if e != nil {
		return e
	}
	if owner != u.Key() {
		return ErrForbidden
	}
	if state != "ACTIVE" || !unexpired {
		return ErrConflict
	}
	return nil
}
