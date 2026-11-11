package cli

import (
	"errors"
	"github.com/spf13/cobra"
	"net/url"
)

func (c *Client) addPolicyCommands(admin *cobra.Command) {
	var maximum int
	var reason string
	settings := &cobra.Command{Use: "settings", Short: "View or change the default developer booking limit", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		var out any
		if !cmd.Flags().Changed("max-bookings") {
			if err := c.request(cmd.Context(), "GET", "/v1/admin/settings", nil, "", &out); err != nil {
				return err
			}
			return c.print(out)
		}
		if maximum < 1 || maximum > 100 || reason == "" {
			return errors.New("--max-bookings must be 1 through 100 and --reason is required")
		}
		if err := c.request(cmd.Context(), "PATCH", "/v1/admin/settings", map[string]any{"default_max_bookings": maximum, "reason": reason}, "", &out); err != nil {
			return err
		}
		return c.print(out)
	}}
	settings.Flags().IntVar(&maximum, "max-bookings", 1, "Default maximum active cluster bookings per developer")
	settings.Flags().StringVar(&reason, "reason", "", "Audit reason for a change")
	admin.AddCommand(settings)
	admin.AddCommand(&cobra.Command{Use: "developers", Short: "List developer booking limits and primary selections", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		var out any
		if err := c.request(cmd.Context(), "GET", "/v1/admin/developers", nil, "", &out); err != nil {
			return err
		}
		return c.print(out)
	}})
	var override int
	var reset bool
	var overrideReason string
	limit := &cobra.Command{Use: "limit OWNER_ID", Short: "Set a developer's booking limit or reset it to the default", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if overrideReason == "" {
			return errors.New("--reason is required")
		}
		if reset == cmd.Flags().Changed("max-bookings") {
			return errors.New("choose exactly one of --max-bookings or --reset")
		}
		var value any
		if !reset {
			if override < 1 || override > 100 {
				return errors.New("--max-bookings must be 1 through 100")
			}
			value = override
		}
		var out any
		if err := c.request(cmd.Context(), "PATCH", "/v1/admin/developers/"+url.PathEscape(args[0]), map[string]any{"max_bookings": value, "reason": overrideReason}, "", &out); err != nil {
			return err
		}
		return c.print(out)
	}}
	limit.Flags().IntVar(&override, "max-bookings", 1, "Maximum active bookings for this developer")
	limit.Flags().BoolVar(&reset, "reset", false, "Remove override and use the administrator default")
	limit.Flags().StringVar(&overrideReason, "reason", "", "Audit reason")
	admin.AddCommand(limit)
}
