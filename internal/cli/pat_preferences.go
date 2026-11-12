package cli

import (
	"errors"
	"net/url"
	"strings"

	"devctl.local/devctl/internal/model"
	"devctl.local/devctl/internal/store"
	"github.com/spf13/cobra"
)

func personalSelector(fields []string) (map[string]string, error) {
	selector := map[string]string{}
	for _, field := range fields {
		key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok || key == "" {
			return nil, errors.New("automatic booking labels must be key=value pairs")
		}
		if _, exists := selector[key]; exists {
			return nil, errors.New("automatic booking selector contains a duplicate label key")
		}
		selector[key] = value
	}
	return selector, nil
}

func (c *Client) addPATUpdateCommand(token *cobra.Command) {
	var autoBook, clearSelector bool
	var selectors []string
	var reason string
	update := &cobra.Command{
		Use:   "update PAT_ID",
		Short: "Edit automatic-booking preferences without replacing your PAT or kubeconfig",
		Long:  "Edit the server-side automatic-booking preferences for a PAT. Existing primary bookings are unchanged. New preferences apply when a later Kubernetes request needs to reserve a cluster. The token, its expiry, and your downloaded kubeconfig remain unchanged.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			changeEnabled := cmd.Flags().Changed("auto-book")
			changeSelector := cmd.Flags().Changed("selector")
			if !personalTokenID.MatchString(args[0]) {
				return errors.New("a valid PAT ID is required")
			}
			if !changeEnabled && !changeSelector && !clearSelector {
				return errors.New("provide --auto-book, --selector, or --clear-selector")
			}
			if changeSelector && clearSelector {
				return errors.New("choose --selector or --clear-selector")
			}
			auditReason := strings.TrimSpace(reason)
			if len(auditReason) > 1000 {
				return errors.New("--reason must be at most 1000 bytes")
			}
			var replacement map[string]string
			if changeSelector || clearSelector {
				var err error
				replacement, err = personalSelector(selectors)
				if err != nil {
					return err
				}
				if err = model.ValidateAutoBookingPolicy(model.AutoBookingPolicy{Selector: replacement}); err != nil {
					return err
				}
			}
			var existing store.PAT
			path := "/v1/pats/" + url.PathEscape(args[0])
			if err := c.request(cmd.Context(), "GET", path, nil, "", &existing); err != nil {
				return err
			}
			if existing.ID != args[0] {
				return errors.New("backend returned an unexpected personal credential")
			}
			policy := existing.AutoBooking
			if policy.Selector == nil {
				policy.Selector = map[string]string{}
			}
			if changeEnabled {
				policy.Enabled = autoBook
			}
			if changeSelector || clearSelector {
				policy.Selector = replacement
			}
			if err := model.ValidateAutoBookingPolicy(policy); err != nil {
				return err
			}
			var updated store.PAT
			body := map[string]any{"auto_booking": policy, "reason": auditReason}
			if err := c.request(cmd.Context(), "PATCH", path, body, "", &updated); err != nil {
				return err
			}
			return c.print(updated)
		},
	}
	update.Flags().BoolVar(&autoBook, "auto-book", false, "Enable or disable automatic booking for this PAT")
	update.Flags().StringSliceVarP(&selectors, "selector", "l", nil, "Replace automatic booking equality labels, e.g. region=eu,type=test")
	update.Flags().BoolVar(&clearSelector, "clear-selector", false, "Remove label constraints; automatic booking can choose any free cluster")
	update.Flags().StringVar(&reason, "reason", "", "Audit reason (required for an administrator changing another user's PAT)")
	token.AddCommand(update)
}
