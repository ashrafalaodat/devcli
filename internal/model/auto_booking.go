package model

import (
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// AutoBookingPolicy is mutable server-side PAT metadata. It applies only when
// its owner has no active primary; changing it never switches an existing hold.
type AutoBookingPolicy struct {
	Enabled  bool              `json:"enabled"`
	Selector map[string]string `json:"selector"`
}

func ValidateAutoBookingPolicy(policy AutoBookingPolicy) error {
	if len(policy.Selector) > 32 {
		return fmt.Errorf("automatic booking selector must contain at most 32 labels")
	}
	keys := make([]string, 0, len(policy.Selector))
	for key := range policy.Selector {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(key) > 317 {
			return fmt.Errorf("selector label key exceeds the Kubernetes length limit")
		}
		if len(policy.Selector[key]) > 63 {
			return fmt.Errorf("selector label value exceeds 63 bytes")
		}
		if problems := validation.IsQualifiedName(key); len(problems) != 0 {
			return fmt.Errorf("invalid selector label key %q: %s", key, strings.Join(problems, "; "))
		}
		if problems := validation.IsValidLabelValue(policy.Selector[key]); len(problems) != 0 {
			return fmt.Errorf("invalid selector value for %q: %s", key, strings.Join(problems, "; "))
		}
	}
	return nil
}
