package cli

import (
	"errors"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

func (c *Client) addDeregisterCommand(admin *cobra.Command) {
	var reason string
	command := &cobra.Command{
		Use:   "deregister CLUSTER_ID",
		Short: "Remove a cluster and its stored credentials from devctl",
		Long:  "Remove a cluster and its stored Kubernetes credentials from devctl. Active bookings must be released first. Booking history and Kubernetes workloads are retained.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			auditReason := strings.TrimSpace(reason)
			if auditReason == "" || len(auditReason) > 1000 {
				return errors.New("--reason must contain 1 through 1000 bytes")
			}
			if strings.TrimSpace(args[0]) == "" {
				return errors.New("cluster ID is required")
			}
			var result any
			if err := c.request(cmd.Context(), "DELETE", "/v1/admin/clusters/"+url.PathEscape(args[0]), map[string]string{"reason": auditReason}, "", &result); err != nil {
				return err
			}
			return c.print(result)
		},
	}
	command.Flags().StringVar(&reason, "reason", "", "Required audit reason for deregistration")
	admin.AddCommand(command)
}
