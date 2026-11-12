package model

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type Identity struct {
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email,omitempty"`
	Admin       bool   `json:"admin"`
	// TokenExpiresAt comes only from a verified access token, never API JSON.
	TokenExpiresAt time.Time `json:"-"`
}

func (i Identity) Key() string {
	h := sha256.Sum256([]byte(i.Issuer + "\x00" + i.Subject))
	return hex.EncodeToString(h[:])
}

type Cluster struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Labels            map[string]string `json:"labels"`
	Maintenance       bool              `json:"maintenance"`
	ControllerSession string            `json:"controller_session,omitempty"`
	Shareable         bool              `json:"shareable"`
	MaxParticipants   int               `json:"max_participants"`
	Participants      []Session         `json:"participants"`
	Available         bool              `json:"available"`
	Reason            string            `json:"reason"`
	DeregisteredAt    *time.Time        `json:"deregistered_at,omitempty"`
}
type Session struct {
	ID             string     `json:"id"`
	Owner          string     `json:"owner"`
	Name           string     `json:"name"`
	DisplayName    string     `json:"display_name"`
	Email          string     `json:"email,omitempty"`
	Cluster        string     `json:"cluster"`
	State          string     `json:"state"`
	CreatedAt      time.Time  `json:"created_at"`
	EndedAt        *time.Time `json:"ended_at,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	LastActivityAt *time.Time `json:"last_activity_at,omitempty"`
	Reason         string     `json:"reason"`
	Primary        bool       `json:"primary"`
}

// DeveloperProfile is the server-wide reservation and primary selection for one
// issuer/subject. Clients never choose their booking limit themselves.
type DeveloperProfile struct {
	OwnerID             string   `json:"owner_id"`
	User                Identity `json:"user"`
	MaxBookings         int      `json:"max_bookings"`
	MaxBookingsOverride *int     `json:"max_bookings_override,omitempty"`
	ActiveBookings      int      `json:"active_bookings"`
	PrimarySession      *Session `json:"primary_session,omitempty"`
	SelectionVersion    int64    `json:"selection_version"`
}

type Settings struct {
	DefaultMaxBookings    int    `json:"default_max_bookings"`
	InactivityGracePeriod string `json:"inactivity_grace_period"`
}
type Booking struct {
	Cluster  string            `json:"cluster,omitempty"`
	Selector map[string]string `json:"selector,omitempty"`
}

func Match(c Cluster, b Booking) bool {
	if b.Cluster != "" && b.Cluster != c.ID && b.Cluster != c.Name {
		return false
	}
	for k, v := range b.Selector {
		if actual, present := c.Labels[k]; !present || actual != v {
			return false
		}
	}
	return true
}
