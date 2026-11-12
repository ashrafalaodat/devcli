package model

import "fmt"

// AutoBookingPolicy is mutable server-side PAT metadata. It applies only when
// its owner has no active primary; changing it never switches an existing hold.
type AutoBookingPolicy struct {
	Enabled  bool              `json:"enabled"`
	Selector map[string]string `json:"selector"`
}

func ValidateAutoBookingPolicy(policy AutoBookingPolicy) error {
	if err := ValidateLabels(policy.Selector); err != nil {
		return fmt.Errorf("automatic booking selector: %w", err)
	}
	return nil
}
