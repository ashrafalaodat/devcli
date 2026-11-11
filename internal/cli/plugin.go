package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// The plugin shares login/refresh implementation with the full CLI, exposing
// only connection controls. Booking and administrator actions stay in CLI/UI.
func NewPluginCommand() *cobra.Command {
	c := &Client{HTTP: &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, Out: os.Stdout, Err: os.Stderr}
	return newPluginCommand(c)
}

func newPluginCommand(c *Client) *cobra.Command {
	root := newCommand(c)
	root.Use = "kubectl devctl"
	root.Short = "Connect kubectl to your primary booked cluster through the gateway"
	root.Long = "SSO login and automatic token refresh for your stable developer kubeconfig. Book clusters with the full devctl CLI or web UI, then switch your primary here."
	root.CompletionOptions.DisableDefaultCmd = true
	for _, cmd := range root.Commands() {
		switch cmd.Name() {
		case "setup", "logout", "credential", "heartbeat", "shell":
			cmd.Hidden = cmd.Name() == "credential" || cmd.Name() == "heartbeat" || cmd.Name() == "shell"
		default:
			root.RemoveCommand(cmd)
		}
	}
	root.AddCommand(&cobra.Command{Use: "login", Short: "Log in and print your stable gateway kubeconfig path without booking", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error { return c.pluginLogin(cmd.Context()) }})
	root.AddCommand(&cobra.Command{Use: "status", Short: "Show your current primary booking and booking limit", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		var profile developerProfile
		if err := c.request(cmd.Context(), "GET", "/v1/profile", nil, "", &profile); err != nil {
			return err
		}
		return c.print(profile)
	}})
	root.AddCommand(&cobra.Command{Use: "switch CLUSTER", Short: "Switch to another cluster you already booked", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var profile developerProfile
		if err := c.request(cmd.Context(), "POST", "/v1/primary", map[string]string{"cluster": args[0]}, "", &profile); err != nil {
			return err
		}
		return c.print(profile)
	}})
	return root
}
func (c *Client) pluginLogin(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if _, _, err := c.authenticatedProfile(ctx, true); err != nil {
		return err
	}
	path, err := c.setupGateway(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Err, "Logged in. This kubeconfig follows your primary booking. Book a cluster in the web UI or full devctl CLI if none is booked.")
	_, err = fmt.Fprintln(c.Out, path)
	return err
}
