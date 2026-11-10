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
}
type Booking struct {
	Cluster  string            `json:"cluster,omitempty"`
	Selector map[string]string `json:"selector,omitempty"`
	TTL      string            `json:"ttl,omitempty"`
}

func Match(c Cluster, b Booking) bool {
	if b.Cluster != "" && b.Cluster != c.ID && b.Cluster != c.Name {
		return false
	}
	for k, v := range b.Selector {
		if c.Labels[k] != v {
			return false
		}
	}
	return true
}
