// Package scheduler implements reservation-only, stable first-fit selection.
// It must be called while holding the database reservation lock.
package scheduler

import (
	"devctl.local/devctl/internal/model"
	"errors"
	"sort"
	"time"
)

var ErrUnavailable = errors.New("no matching available cluster; check reservation capacity, sharing consent and fresh cluster health")

func Pick(cs []model.Cluster, b model.Booking) (model.Cluster, error) {
	return PickAt(cs, b, time.Now().UTC())
}

func PickAt(cs []model.Cluster, b model.Booking, now time.Time) (model.Cluster, error) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
	// Prefer an empty cluster over joining a shared reservation.
	for _, shared := range []bool{false, true} {
		for _, c := range cs {
			if !model.Match(c, b) || c.Maintenance || !c.HealthEligible(now) {
				continue
			}
			n := len(c.Participants)
			if !shared && n == 0 {
				return c, nil
			}
			if shared && n > 0 && c.Shareable && n < c.MaxParticipants {
				return c, nil
			}
		}
	}
	return model.Cluster{}, ErrUnavailable
}
