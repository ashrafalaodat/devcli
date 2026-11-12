package model

import (
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

// ValidateLabels is shared by registry labels and equality-label PAT selectors.
// Empty values are valid; placement matching separately requires key presence.
func ValidateLabels(labels map[string]string) error {
	if len(labels) > 32 {
		return fmt.Errorf("labels must contain at most 32 entries")
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(key) > 317 {
			return fmt.Errorf("label key exceeds the Kubernetes length limit")
		}
		if len(labels[key]) > 63 {
			return fmt.Errorf("label value exceeds 63 bytes")
		}
		if problems := validation.IsQualifiedName(key); len(problems) != 0 {
			return fmt.Errorf("invalid label key %q: %s", key, strings.Join(problems, "; "))
		}
		if problems := validation.IsValidLabelValue(labels[key]); len(problems) != 0 {
			return fmt.Errorf("invalid label value for %q: %s", key, strings.Join(problems, "; "))
		}
	}
	return nil
}
