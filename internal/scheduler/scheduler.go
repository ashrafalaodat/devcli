// Package scheduler implements reservation-only, stable first-fit selection.
// It must be called while holding the database reservation lock.
package scheduler

import (
	"devctl.local/devctl/internal/model"
	"errors"
	"sort"
)

var ErrUnavailable = errors.New("no matching available cluster; a current holder must enable sharing before another developer can book it")

func Pick(cs []model.Cluster, b model.Booking) (model.Cluster, error) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
	// Prefer an empty cluster over joining a shared reservation.
	for _, shared := range []bool{false, true} {
		for _, c := range cs {
			if !model.Match(c, b) || c.Maintenance {
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
