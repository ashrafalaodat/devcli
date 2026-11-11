package cli

import (
	"errors"
	"github.com/spf13/cobra"
	"net/url"
	"strings"
	"time"
)

func (c *Client) addPolicyCommands(admin *cobra.Command) {
	var maximum int
	var reason, inactiveGrace string
	settings := &cobra.Command{Use: "settings", Short: "View or change booking limits and the inactivity grace period", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		var out any
		changeMaximum := cmd.Flags().Changed("max-bookings")
		changeGrace := cmd.Flags().Changed("inactive-grace")
		if !changeMaximum && !changeGrace {
			if err := c.request(cmd.Context(), "GET", "/v1/admin/settings", nil, "", &out); err != nil {
				return err
			}
			return c.print(out)
		}
		if strings.TrimSpace(reason) == "" {
			return errors.New("--reason is required")
		}
		body := map[string]any{"reason": reason}
		if changeMaximum {
			if maximum < 1 || maximum > 100 {
				return errors.New("--max-bookings must be 1 through 100")
			}
			body["default_max_bookings"] = maximum
		}
		if changeGrace {
			grace, err := time.ParseDuration(inactiveGrace)
			if err != nil || grace < time.Minute || grace > 168*time.Hour || grace%time.Second != 0 {
				return errors.New("--inactive-grace must be whole seconds from 1m through 168h")
			}
			body["inactivity_grace_period"] = grace.String()
		}
		if err := c.request(cmd.Context(), "PATCH", "/v1/admin/settings", body, "", &out); err != nil {
			return err
		}
		return c.print(out)
	}}
	settings.Flags().IntVar(&maximum, "max-bookings", 1, "Default maximum active cluster bookings per developer")
	settings.Flags().StringVar(&inactiveGrace, "inactive-grace", "4h", "Auto-release a booking after this period without activity (1m through 168h)")
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
