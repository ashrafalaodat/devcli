package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"devctl.local/devctl/internal/model"
	"github.com/spf13/cobra"
)

var healthClusterID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

type healthCheckRequest struct {
	ID      string              `json:"id"`
	Pending bool                `json:"pending"`
	Health  model.ClusterHealth `json:"health"`
}

func healthAuditReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 1000 {
		return "", errors.New("--reason must contain 1 through 1000 bytes")
	}
	return reason, nil
}
func validateHealthCluster(id string) error {
	if !healthClusterID.MatchString(id) {
		return errors.New("cluster ID must contain 1 through 63 letters, numbers, dots, underscores or hyphens")
	}
	return nil
}
func clusterHealthPath(id string) string { return "/v1/clusters/" + url.PathEscape(id) + "/health" }

func (c *Client) addHealthCommands(admin *cobra.Command) {
	cluster := &cobra.Command{Use: "cluster", Short: "Inspect and configure cluster health checks"}
	status := &cobra.Command{Use: "status CLUSTER_ID", Short: "Show the latest persisted health observation without probing", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateHealthCluster(args[0]); err != nil {
			return err
		}
		var out model.ClusterHealth
		if err := c.request(cmd.Context(), "GET", clusterHealthPath(args[0]), nil, "", &out); err != nil {
			return err
		}
		return c.print(out)
	}}
	cluster.AddCommand(status)
	var checkReason string
	var wait bool
	var timeout time.Duration
	check := &cobra.Command{Use: "check CLUSTER_ID", Short: "Queue a read-only API health check; optionally wait for that cycle", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateHealthCluster(args[0]); err != nil {
			return err
		}
		why, err := healthAuditReason(checkReason)
		if err != nil {
			return err
		}
		if timeout < time.Second || timeout > 15*time.Minute {
			return errors.New("--timeout must be between 1s and 15m")
		}
		if cmd.Flags().Changed("timeout") && !wait {
			return errors.New("--timeout requires --wait")
		}
		var result healthCheckRequest
		if err = c.request(cmd.Context(), "POST", "/v1/admin/clusters/"+url.PathEscape(args[0])+"/health-check", map[string]string{"reason": why}, "", &result); err != nil {
			return err
		}
		if !wait {
			fmt.Fprintln(c.Err, "Health check accepted. Acceptance is not a passing result; inspect it with devctl admin cluster status.")
			return c.print(result)
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
		defer cancel()
		health, err := c.waitForHealthCheck(ctx, args[0], result)
		if err != nil {
			return err
		}
		if err = c.print(health); err != nil {
			return err
		}
		fmt.Fprintln(c.Err, "Health check completed:", health.State, ". Recovery may require another successful cycle.")
		if health.State == "FAILING" || health.State == "STALE" || health.State == "UNKNOWN" {
			return &ExitError{4, errors.New("cluster health check did not pass; inspect the reported reason")}
		}
		return nil
	}}
	check.Flags().StringVar(&checkReason, "reason", "", "Required audit reason for the check")
	check.Flags().BoolVar(&wait, "wait", false, "Wait for the requested cycle to complete, not indefinitely for recovery")
	check.Flags().DurationVar(&timeout, "timeout", 2*time.Minute, "Maximum wait, from 1s through 15m")
	cluster.AddCommand(check)
	var profile, profileReason string
	var expected int64
	update := &cobra.Command{Use: "profile CLUSTER_ID", Short: "Change required API checks with stale-write protection", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateHealthCluster(args[0]); err != nil {
			return err
		}
		if profile != "api-ready.v1" && profile != "discovery-only.v1" {
			return errors.New("--profile must be api-ready.v1 or discovery-only.v1")
		}
		why, err := healthAuditReason(profileReason)
		if err != nil {
			return err
		}
		if cmd.Flags().Changed("expected-revision") && expected < 1 {
			return errors.New("--expected-revision must be positive")
		}
		if !cmd.Flags().Changed("expected-revision") {
			var current model.ClusterHealth
			if err = c.request(cmd.Context(), "GET", clusterHealthPath(args[0]), nil, "", &current); err != nil {
				return err
			}
			expected = current.PolicyRevision
		}
		var out model.ClusterHealth
		if err = c.request(cmd.Context(), "PATCH", "/v1/admin/clusters/"+url.PathEscape(args[0])+"/health-profile", map[string]any{"profile": profile, "expected_revision": expected, "reason": why}, "", &out); err != nil {
			return err
		}
		fmt.Fprintln(c.Err, "Health profile saved; previous observations are invalidated. Existing bookings and access are preserved.")
		return c.print(out)
	}}
	update.Flags().StringVar(&profile, "profile", "", "api-ready.v1 or lower-assurance discovery-only.v1")
	update.Flags().StringVar(&profileReason, "reason", "", "Required audit reason for changing the profile")
	update.Flags().Int64Var(&expected, "expected-revision", 0, "Expected policy revision (defaults to a fresh server snapshot)")
	cluster.AddCommand(update)
	admin.AddCommand(cluster)
}

func (c *Client) waitForHealthCheck(ctx context.Context, id string, request healthCheckRequest) (model.ClusterHealth, error) {
	if !request.Pending {
		return request.Health, nil
	}
	var baseline time.Time
	if request.Health.CheckedAt != nil {
		baseline = *request.Health.CheckedAt
	}
	for {
		var current model.ClusterHealth
		if err := c.request(ctx, "GET", clusterHealthPath(id), nil, "", &current); err != nil {
			return model.ClusterHealth{}, err
		}
		if request.Health.ConfigurationGeneration > 0 && current.ConfigurationGeneration != request.Health.ConfigurationGeneration || request.Health.PolicyRevision > 0 && current.PolicyRevision != request.Health.PolicyRevision {
			return model.ClusterHealth{}, &ExitError{4, errors.New("cluster configuration or health profile changed while waiting; request another check")}
		}
		if !current.CheckPending && current.CheckedAt != nil && current.CheckedAt.After(baseline) {
			return current, nil
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return model.ClusterHealth{}, errors.New("waiting for the health check timed out or was cancelled; the queued check remains visible in cluster status")
		case <-timer.C:
		}
	}
}
