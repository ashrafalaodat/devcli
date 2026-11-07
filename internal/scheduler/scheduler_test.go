package scheduler

import (
	"devctl.local/devctl/internal/model"
	"testing"
)

func TestPlacement(t *testing.T) {
	private := model.Cluster{ID: "a", Name: "Alpha", Labels: map[string]string{"region": "eu"}, MaxParticipants: 2, Participants: []model.Session{{ID: "s1"}}}
	empty := model.Cluster{ID: "b", Name: "Beta", MaxParticipants: 2}
	for _, tt := range []struct {
		name string
		cs   []model.Cluster
		b    model.Booking
		want string
	}{
		{"private rejected", []model.Cluster{private}, model.Booking{}, ""},
		{"automatic fallback", []model.Cluster{private, empty}, model.Booking{}, "b"},
		{"named busy rejected", []model.Cluster{private, empty}, model.Booking{Cluster: "a"}, ""},
		{"selector busy rejected", []model.Cluster{private, empty}, model.Booking{Selector: map[string]string{"region": "eu"}}, ""},
		{"stable ordering", []model.Cluster{empty, {ID: "c", MaxParticipants: 2}}, model.Booking{}, "b"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, e := Pick(tt.cs, tt.b)
			if tt.want == "" {
				if e == nil {
					t.Fatal("expected unavailable")
				}
			} else if e != nil || c.ID != tt.want {
				t.Fatalf("got %s %v", c.ID, e)
			}
		})
	}
	private.Shareable = true
	if c, e := Pick([]model.Cluster{private}, model.Booking{}); e != nil || c.ID != "a" {
		t.Fatal(c, e)
	}
	if c, e := Pick([]model.Cluster{private, empty}, model.Booking{}); e != nil || c.ID != "b" {
		t.Fatal("prefer unused cluster", c, e)
	}
	private.Participants = append(private.Participants, model.Session{ID: "s2"})
	if _, e := Pick([]model.Cluster{private}, model.Booking{}); e == nil {
		t.Fatal("shared capacity exceeded")
	}
	empty.Maintenance = true
	if _, e := Pick([]model.Cluster{empty}, model.Booking{}); e == nil {
		t.Fatal("maintenance allocated")
	}
}
